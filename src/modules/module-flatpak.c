/***
  This file is part of PulseAudio.

  Copyright 2016 Red Hat, Inc.

  PulseAudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published
  by the Free Software Foundation; either version 2.1 of the License,
  or (at your option) any later version.

  PulseAudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with PulseAudio; if not, see <http://www.gnu.org/licenses/>.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <pulse/xmalloc.h>
#include <pulse/rtclock.h>
#include <pulse/timeval.h>

#include <pulsecore/core-error.h>
#include <pulsecore/module.h>
#include <pulsecore/core-util.h>
#include <pulsecore/modargs.h>
#include <pulsecore/log.h>
#include <pulsecore/sink-input.h>
#include <pulsecore/core-util.h>
#include <pulsecore/dbus-shared.h>

#include "module-flatpak-symdef.h"

PA_MODULE_AUTHOR("Matthias Clasen");
PA_MODULE_DESCRIPTION("Controls access to server resources for flatpak apps");
PA_MODULE_VERSION(PACKAGE_VERSION);
PA_MODULE_LOAD_ONCE(true);
PA_MODULE_USAGE("");

static const char* const valid_modargs[] = {
    NULL,
};

typedef struct access_policy access_policy;
typedef struct event_item event_item;
typedef struct client_data client_data;
typedef struct userdata userdata;

typedef pa_hook_result_t (*access_rule_t)(pa_core *c, pa_access_data *d, struct userdata *u);

struct access_policy {
    uint32_t index;
    struct userdata *userdata;

    access_rule_t rule[PA_ACCESS_HOOK_MAX];
};

struct event_item {
    PA_LLIST_FIELDS(event_item);

    int facility;
    uint32_t object_index;
};

struct async_cache {
  bool checked;
  bool granted;
};

struct userdata {
    pa_core *core;

    pa_hook_slot *hook[PA_ACCESS_HOOK_MAX];

    pa_idxset *policies;
    uint32_t default_policy;
    uint32_t portal_policy;

    pa_dbus_connection *connection;
    pa_hashmap *clients;
    pa_hook_slot *client_put_slot;
    pa_hook_slot *client_auth_slot;
    pa_hook_slot *client_proplist_changed_slot;
    pa_hook_slot *client_unlink_slot;
};

struct client_data {
    struct userdata *u;

    uint32_t index;
    uint32_t policy;
    pid_t pid;

    struct async_cache cached[PA_ACCESS_HOOK_MAX];
    pa_time_event *time_event;
    pa_access_data *access_data;

    PA_LLIST_HEAD(event_item, events);
};


static void add_event(struct client_data *cd, int facility, uint32_t oidx) {
    event_item *i;

    i = pa_xnew0(event_item, 1);
    PA_LLIST_INIT(event_item, i);
    i->facility = facility;
    i->object_index = oidx;

    PA_LLIST_PREPEND(event_item, cd->events, i);
}

static event_item *find_event(struct client_data *cd, int facility, uint32_t oidx) {
    event_item *i;

    PA_LLIST_FOREACH(i, cd->events) {
        if (i->facility == facility && i->object_index == oidx)
            return i;
    }
    return NULL;
}

static bool remove_event(struct client_data *cd, int facility, uint32_t oidx) {
    event_item *i = find_event(cd, facility, oidx);
    if (i) {
      PA_LLIST_REMOVE(event_item, cd->events, i);
      pa_xfree(i);
      return true;
    }
    return false;
}

static void timeout_cb(pa_mainloop_api*a, pa_time_event* e, const struct timeval *t, void *data) {
    client_data *cd = data;
    struct userdata *u = cd->u;
    pa_access_data *d = cd->access_data;

    pa_log("async check finished of operation %d/%d for client %d", d->hook, d->object_index, d->client_index);
    u->core->mainloop->time_restart(cd->time_event, NULL);

    cd->cached[d->hook].checked = true;
    /* this should be granted or denied */
    cd->cached[d->hook].granted = true;

    d->async_finish_cb (d, cd->cached[d->hook].granted);
}

static client_data * client_data_new(struct userdata *u, uint32_t index, uint32_t policy, pid_t pid) {
    client_data *cd;

    cd = pa_xnew0(client_data, 1);
    cd->u = u;
    cd->index = index;
    cd->policy = policy;
    cd->pid = pid;
    cd->time_event = pa_core_rttime_new(u->core, PA_USEC_INVALID, timeout_cb, cd);
    pa_hashmap_put(u->clients, PA_UINT32_TO_PTR(index), cd);
    pa_log("new client %d with pid %d, policy %d", index, pid, policy);

    return cd;
}

static void client_data_free(client_data *cd) {
    event_item *e;

    while ((e = cd->events)) {
        PA_LLIST_REMOVE(event_item, cd->events, e);
        pa_xfree(e);
    }
    pa_log("removed client %d", cd->index);
    cd->u->core->mainloop->time_free(cd->time_event);
    pa_xfree(cd);
}

static client_data * client_data_get(struct userdata *u, uint32_t index) {
    return pa_hashmap_get(u->clients, PA_UINT32_TO_PTR(index));
}

static void client_data_remove(struct userdata *u, uint32_t index) {
    pa_hashmap_remove_and_free(u->clients, PA_UINT32_TO_PTR(index));
}

/* rule checks if the operation on the object is performed by the owner of the object */
static pa_hook_result_t rule_check_owner (pa_core *c, pa_access_data *d, struct userdata *u) {
    pa_hook_result_t result = PA_HOOK_STOP;
    uint32_t idx = PA_INVALID_INDEX;

    switch (d->hook) {
        case PA_ACCESS_HOOK_GET_CLIENT_INFO:
        case PA_ACCESS_HOOK_KILL_CLIENT: {
            idx = d->object_index;
            break;
        }

        case PA_ACCESS_HOOK_GET_SINK_INPUT_INFO:
        case PA_ACCESS_HOOK_MOVE_SINK_INPUT:
        case PA_ACCESS_HOOK_SET_SINK_INPUT_VOLUME:
        case PA_ACCESS_HOOK_SET_SINK_INPUT_MUTE:
        case PA_ACCESS_HOOK_KILL_SINK_INPUT: {
            const pa_sink_input *si = pa_idxset_get_by_index(c->sink_inputs, d->object_index);
            idx = (si && si->client) ? si->client->index : PA_INVALID_INDEX;
            break;
        }

        case PA_ACCESS_HOOK_GET_SOURCE_OUTPUT_INFO:
        case PA_ACCESS_HOOK_MOVE_SOURCE_OUTPUT:
        case PA_ACCESS_HOOK_SET_SOURCE_OUTPUT_VOLUME:
        case PA_ACCESS_HOOK_SET_SOURCE_OUTPUT_MUTE:
        case PA_ACCESS_HOOK_KILL_SOURCE_OUTPUT: {
            const pa_source_output *so = pa_idxset_get_by_index(c->source_outputs, d->object_index);
            idx = (so && so->client) ? so->client->index : PA_INVALID_INDEX;
            break;
        }
        default:
            break;
    }
    if (idx == d->client_index)
        result = PA_HOOK_OK;
    else
        pa_log("blocked operation %d/%d of client %d to client %d", d->hook, d->object_index, idx, d->client_index);

    return result;
}

/* rule allows the operation */
static pa_hook_result_t rule_allow (pa_core *c, pa_access_data *d, struct userdata *u) {
    pa_log("allow operation %d/%d for client %d", d->hook, d->object_index, d->client_index);
    return PA_HOOK_OK;
}

/* rule blocks the operation */
static pa_hook_result_t rule_block (pa_core *c, pa_access_data *d, struct userdata *u) {
    pa_log("blocked operation %d/%d for client %d", d->hook, d->object_index, d->client_index);
    return PA_HOOK_STOP;
}

static DBusHandlerResult portal_response(DBusConnection *connection, DBusMessage *msg, void *user_data)
{
    client_data *cd = user_data;
    pa_access_data *d = cd->access_data;

    if (dbus_message_is_signal(msg, "org.freedesktop.portal.Request", "Response")) {
        uint32_t response = 2;
        DBusError error;

        dbus_error_init(&error);

        dbus_connection_remove_filter (connection, portal_response, cd);

        if (!dbus_message_get_args(msg, &error, DBUS_TYPE_UINT32, &response, DBUS_TYPE_INVALID)) {
            pa_log("failed to parse Response: %s\n", error.message);
            dbus_error_free(&error);
          }

        cd->cached[d->hook].checked = true;
        cd->cached[d->hook].granted = response == 0 ? true : false;

        pa_log("portal check result: %d\n", cd->cached[d->hook].granted);

        d->async_finish_cb (d, cd->cached[d->hook].granted);

        return DBUS_HANDLER_RESULT_HANDLED;
    }

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static pa_hook_result_t rule_check_portal (pa_core *c, pa_access_data *d, struct userdata *u) {
    client_data *cd = client_data_get(u, d->client_index);
    DBusMessage *m = NULL, *r = NULL;
    DBusError error;
    pid_t pid;
    DBusMessageIter msg_iter;
    DBusMessageIter dict_iter;
    const char *handle;
    const char *device;

    if (cd->cached[d->hook].checked) {
        pa_log("returned cached answer for portal check: %d\n", cd->cached[d->hook].granted);
        return cd->cached[d->hook].granted ? PA_HOOK_OK : PA_HOOK_STOP;
    }

    pa_log("ask portal for operation %d/%d for client %d", d->hook, d->object_index, d->client_index);

    cd->access_data = d;

    dbus_error_init(&error);

    if (!(m = dbus_message_new_method_call("org.freedesktop.portal.Desktop",
                                           "/org/freedesktop/portal/desktop",
                                           "org.freedesktop.portal.Device",
                                           "AccessDevice"))) {
        return PA_HOOK_STOP;
    }

    if (d->hook == PA_ACCESS_HOOK_CONNECT_RECORD)
      device = "microphone";
    else if (d->hook == PA_ACCESS_HOOK_CONNECT_PLAYBACK ||
             d->hook == PA_ACCESS_HOOK_PLAY_SAMPLE)
      device = "speakers";
    else
      pa_assert_not_reached ();

    pid = cd->pid;
    if (!dbus_message_append_args(m,
                                  DBUS_TYPE_UINT32, &pid,
                                  DBUS_TYPE_INVALID)) {
        dbus_message_unref(m);
        return PA_HOOK_STOP;
    }

    dbus_message_iter_init_append(m, &msg_iter);
    dbus_message_iter_open_container (&msg_iter, DBUS_TYPE_ARRAY, "s", &dict_iter);
    dbus_message_iter_append_basic (&dict_iter, DBUS_TYPE_STRING, &device);
    dbus_message_iter_close_container (&msg_iter, &dict_iter);

    dbus_message_iter_open_container (&msg_iter, DBUS_TYPE_ARRAY, "{sv}", &dict_iter);
    dbus_message_iter_close_container (&msg_iter, &dict_iter);

    if (!(r = dbus_connection_send_with_reply_and_block(pa_dbus_connection_get(u->connection), m, -1, &error))) {
        pa_log("Failed to call portal: %s\n", error.message);
        dbus_error_free(&error);
        dbus_message_unref(m);
        return PA_HOOK_STOP;
    }

    dbus_message_unref(m);

    if (!dbus_message_get_args(r, &error, DBUS_TYPE_OBJECT_PATH, &handle, DBUS_TYPE_INVALID)) {
        pa_log("Failed to parse AccessDevice result: %s\n", error.message);
        dbus_error_free(&error);
        dbus_message_unref(r);
        return PA_HOOK_STOP;
    }

    dbus_message_unref(r);

    dbus_bus_add_match(pa_dbus_connection_get(u->connection),
                       "type='signal',interface='org.freedesktop.portal.Request'",
                       &error);
    dbus_connection_flush(pa_dbus_connection_get(u->connection));
    if (dbus_error_is_set(&error)) {
        pa_log("Failed to subscribe to Request signal: %s\n", error.message);
        dbus_error_free(&error);
        return PA_HOOK_STOP;
    }

    dbus_connection_add_filter(pa_dbus_connection_get(u->connection), portal_response, cd, NULL);

    return PA_HOOK_CANCEL;
}

static access_policy *access_policy_new(struct userdata *u, bool allow_all) {
    access_policy *ap;
    int i;

    ap = pa_xnew0(access_policy, 1);
    ap->userdata = u;
    for (i = 0; i < PA_ACCESS_HOOK_MAX; i++)
      ap->rule[i] = allow_all ? rule_allow : rule_block;

    pa_idxset_put(u->policies, ap, &ap->index);

    return ap;
}

static void access_policy_free(access_policy *ap) {
    pa_idxset_remove_by_index(ap->userdata->policies, ap->index);
    pa_xfree(ap);
}

static pa_hook_result_t check_access (pa_core *c, pa_access_data *d, struct userdata *u) {
    access_policy *ap;
    access_rule_t rule;
    client_data *cd = client_data_get(u, d->client_index);

    /* unknown client */
    if (cd == NULL)
        return PA_HOOK_STOP;

    ap = pa_idxset_get_by_index(u->policies, cd->policy);

    rule = ap->rule[d->hook];
    if (rule)
      return rule(c, d, u);

    return PA_HOOK_STOP;
}

static const pa_access_hook_t event_hook[PA_SUBSCRIPTION_EVENT_FACILITY_MASK+1] = {
    [PA_SUBSCRIPTION_EVENT_SINK] = PA_ACCESS_HOOK_GET_SINK_INFO,
    [PA_SUBSCRIPTION_EVENT_SOURCE] = PA_ACCESS_HOOK_GET_SOURCE_INFO,
    [PA_SUBSCRIPTION_EVENT_SINK_INPUT] = PA_ACCESS_HOOK_GET_SINK_INPUT_INFO,
    [PA_SUBSCRIPTION_EVENT_SOURCE_OUTPUT] = PA_ACCESS_HOOK_GET_SOURCE_OUTPUT_INFO,
    [PA_SUBSCRIPTION_EVENT_MODULE] = PA_ACCESS_HOOK_GET_MODULE_INFO,
    [PA_SUBSCRIPTION_EVENT_CLIENT] = PA_ACCESS_HOOK_GET_CLIENT_INFO,
    [PA_SUBSCRIPTION_EVENT_SAMPLE_CACHE] = PA_ACCESS_HOOK_GET_SAMPLE_INFO,
    [PA_SUBSCRIPTION_EVENT_SERVER] = PA_ACCESS_HOOK_GET_SERVER_INFO,
    [PA_SUBSCRIPTION_EVENT_CARD] = PA_ACCESS_HOOK_GET_CARD_INFO
};



static pa_hook_result_t filter_event (pa_core *c, pa_access_data *d, struct userdata *u) {
    int facility;
    client_data *cd;

    facility = d->event & PA_SUBSCRIPTION_EVENT_FACILITY_MASK;

    cd = client_data_get (u, d->client_index);
    /* unknown client destination, block event */
    if (cd == NULL)
        goto block;

    switch (d->event & PA_SUBSCRIPTION_EVENT_TYPE_MASK) {
        case PA_SUBSCRIPTION_EVENT_REMOVE:
            /* if the client saw this object before, let the event go through */
            if (remove_event(cd, facility, d->object_index)) {
                pa_log("pass event %02x/%d to client %d", d->event, d->object_index, d->client_index);
                return PA_HOOK_OK;
            }
            break;

        case PA_SUBSCRIPTION_EVENT_CHANGE:
            /* if the client saw this object before, let it go through */
            if (find_event(cd, facility, d->object_index)) {
                pa_log("pass event %02x/%d to client %d", d->event, d->object_index, d->client_index);
                return PA_HOOK_OK;
            }

            /* fallthrough to do hook check and register event */
        case PA_SUBSCRIPTION_EVENT_NEW: {
            pa_access_data data = *d;

            /* new object, check if the client is allowed to inspect it */
            data.hook = event_hook[facility];
            if (data.hook && pa_hook_fire(&c->access[data.hook], &data) == PA_HOOK_OK) {
                /* client can inspect the object, remember for later */
                add_event(cd, facility, d->object_index);
                pa_log("pass event %02x/%d to client %d", d->event, d->object_index, d->client_index);
                return PA_HOOK_OK;
            }
            break;
        }
        default:
            break;
    }

block:
    pa_log("blocked event %02x/%d for client %d", d->event, d->object_index, d->client_index);
    return PA_HOOK_STOP;
}

static bool
client_is_sandboxed (pa_client *cl)
{
    char *path;
    char data[2048];
    int n;
    const char *state = NULL;
    const char *current;
    bool result;
    int fd;
    pid_t pid;

    if (cl->creds_valid) {
        pa_log ("client has trusted pid %d", cl->creds.pid);
    }
    else {
        pa_log ("no trusted pid found, assuming not sandboxed\n");
        return false;
    }

    pid = cl->creds.pid;

    path = pa_sprintf_malloc("/proc/%u/cgroup", pid);
    fd = pa_open_cloexec(path, O_RDONLY, 0);
    free (path);

    if (fd == -1)
      return false;

    pa_loop_read(fd, &data, sizeof(data), NULL);
    close(fd);

    result = false;
    while ((current = pa_split_in_place(data, "\n", &n, &state)) != NULL) {
        if (strncmp(current, "1:name=systemd:", strlen("1:name=systemd:")) == 0) {
            const char *p = strstr(current, "flatpak-");
            if (p && p - current < n) {
                pa_log("found a flatpak cgroup, assuming sandboxed\n");
                result = true;
                break;
            }
        }
    }

   return result;
}

static uint32_t find_policy_for_client (struct userdata *u, pa_client *cl) {
    char *s;

    s = pa_proplist_to_string(cl->proplist);
    pa_log ("client proplist %s", s);
    pa_xfree(s);

    return u->default_policy;
    if (client_is_sandboxed (cl)) {
        pa_log("client is sandboxed, choosing portal policy\n");
        return u->portal_policy;
    }
    else {
        pa_log("client not sandboxed, choosing default policy\n");
        return u->default_policy;
    }
}

static pa_hook_result_t client_put_cb(pa_core *c, pa_object *o, struct userdata *u) {
    pa_client *cl;
    uint32_t policy;

    pa_assert(c);
    pa_object_assert_ref(o);

    cl = (pa_client *) o;
    pa_assert(cl);

    /* when we get here, the client just connected and is not yet authenticated
     * we should probably install a policy that denies all access */
    policy = find_policy_for_client(u, cl);

    client_data_new(u, cl->index, policy, cl->creds.pid);

    pa_log("client put: policy %d, pid %u\n", policy, cl->creds.pid);

    return PA_HOOK_OK;
}

static pa_hook_result_t client_auth_cb(pa_core *c, pa_object *o, struct userdata *u) {
    pa_client *cl;
    client_data *cd;
    uint32_t policy;

    pa_assert(c);
    pa_object_assert_ref(o);

    cl = (pa_client *) o;
    pa_assert(cl);

    cd = client_data_get (u, cl->index);
    if (cd == NULL)
        return PA_HOOK_OK;

    policy = find_policy_for_client(u, cl);
    cd->policy = policy;
    cd->pid = cl->creds.pid;

    pa_log("auth cb: policy %d, pid %u\n", cd->policy, cd->pid);

    return PA_HOOK_OK;
}

static pa_hook_result_t client_proplist_changed_cb(pa_core *c, pa_object *o, struct userdata *u) {
    pa_client *cl;
    client_data *cd;
    uint32_t policy;

    pa_assert(c);
    pa_object_assert_ref(o);

    cl = (pa_client *) o;
    pa_assert(cl);

    cd = client_data_get (u, cl->index);
    if (cd == NULL)
        return PA_HOOK_OK;

    policy = find_policy_for_client(u, cl);
    cd->policy = policy;
    cd->pid = cl->creds.pid;

    return PA_HOOK_OK;
}

static pa_hook_result_t client_unlink_cb(pa_core *c, pa_object *o, struct userdata *u) {
    pa_client *cl;

    pa_assert(c);
    pa_object_assert_ref(o);

    cl = (pa_client *) o;
    pa_assert(cl);

    client_data_remove(u, cl->index);

    return PA_HOOK_OK;
}


int pa__init(pa_module*m) {
    pa_modargs *ma = NULL;
    struct userdata *u;
    int i;
    access_policy *ap;
    DBusError error;

    pa_assert(m);

    if (!(ma = pa_modargs_new(m->argument, valid_modargs))) {
        pa_log("Failed to parse module arguments");
        goto fail;
    }

    u = pa_xnew0(struct userdata, 1);
    u->core = m->core;
    m->userdata = u;

    dbus_error_init(&error);

    if (!(u->connection = pa_dbus_bus_get (u->core, DBUS_BUS_SESSION, &error))) {
        pa_log("Failed to connect to session bus: %s\n", error.message);
        dbus_error_free(&error);
    }

    u->policies = pa_idxset_new (NULL, NULL);
    u->clients = pa_hashmap_new_full(pa_idxset_trivial_hash_func, pa_idxset_trivial_compare_func, NULL,
                                                    (pa_free_cb_t) client_data_free);

    u->client_put_slot = pa_hook_connect(&u->core->hooks[PA_CORE_HOOK_CLIENT_PUT], PA_HOOK_EARLY, (pa_hook_cb_t) client_put_cb, u);
    u->client_auth_slot = pa_hook_connect(&u->core->hooks[PA_CORE_HOOK_CLIENT_AUTH], PA_HOOK_EARLY, (pa_hook_cb_t) client_auth_cb, u);
    u->client_proplist_changed_slot = pa_hook_connect(&u->core->hooks[PA_CORE_HOOK_CLIENT_PROPLIST_CHANGED], PA_HOOK_EARLY, (pa_hook_cb_t) client_proplist_changed_cb, u);
    u->client_unlink_slot = pa_hook_connect(&u->core->hooks[PA_CORE_HOOK_CLIENT_UNLINK], PA_HOOK_EARLY, (pa_hook_cb_t) client_unlink_cb, u);

    for (i = 0; i < PA_ACCESS_HOOK_MAX; i++) {
        pa_hook_cb_t cb;

        if (i == PA_ACCESS_HOOK_FILTER_SUBSCRIBE_EVENT)
            cb = (pa_hook_cb_t) filter_event;
        else
            cb = (pa_hook_cb_t) check_access;

        u->hook[i] = pa_hook_connect(&u->core->access[i], PA_HOOK_EARLY - 1, cb, u);
    }

    ap = access_policy_new(u, false);

    ap->rule[PA_ACCESS_HOOK_GET_SINK_INFO] = rule_allow;
    ap->rule[PA_ACCESS_HOOK_GET_SOURCE_INFO] = rule_allow;
    ap->rule[PA_ACCESS_HOOK_GET_SERVER_INFO] = rule_allow;
    ap->rule[PA_ACCESS_HOOK_GET_MODULE_INFO] = rule_allow;
    ap->rule[PA_ACCESS_HOOK_GET_CARD_INFO] = rule_allow;
    ap->rule[PA_ACCESS_HOOK_STAT] = rule_allow;
    ap->rule[PA_ACCESS_HOOK_GET_SAMPLE_INFO] = rule_allow;

    ap->rule[PA_ACCESS_HOOK_PLAY_SAMPLE] = rule_allow;
    ap->rule[PA_ACCESS_HOOK_CONNECT_PLAYBACK] = rule_allow;
    ap->rule[PA_ACCESS_HOOK_CONNECT_RECORD] = rule_allow;

    ap->rule[PA_ACCESS_HOOK_GET_CLIENT_INFO] = rule_check_owner;
    ap->rule[PA_ACCESS_HOOK_KILL_CLIENT] = rule_check_owner;

    ap->rule[PA_ACCESS_HOOK_GET_SINK_INPUT_INFO] = rule_check_owner;
    ap->rule[PA_ACCESS_HOOK_MOVE_SINK_INPUT] = rule_check_owner;
    ap->rule[PA_ACCESS_HOOK_SET_SINK_INPUT_VOLUME] = rule_check_owner;
    ap->rule[PA_ACCESS_HOOK_SET_SINK_INPUT_MUTE] = rule_check_owner;
    ap->rule[PA_ACCESS_HOOK_KILL_SINK_INPUT] = rule_check_owner;

    ap->rule[PA_ACCESS_HOOK_GET_SOURCE_OUTPUT_INFO] = rule_check_owner;
    ap->rule[PA_ACCESS_HOOK_MOVE_SOURCE_OUTPUT] = rule_check_owner;
    ap->rule[PA_ACCESS_HOOK_SET_SOURCE_OUTPUT_VOLUME] = rule_check_owner;
    ap->rule[PA_ACCESS_HOOK_SET_SOURCE_OUTPUT_MUTE] = rule_check_owner;
    ap->rule[PA_ACCESS_HOOK_KILL_SOURCE_OUTPUT] = rule_check_owner;

    u->default_policy = ap->index;

    ap = access_policy_new(u, false);

    ap->rule[PA_ACCESS_HOOK_GET_SINK_INFO] = rule_allow;
    ap->rule[PA_ACCESS_HOOK_GET_SOURCE_INFO] = rule_allow;
    ap->rule[PA_ACCESS_HOOK_GET_SERVER_INFO] = rule_allow;
    ap->rule[PA_ACCESS_HOOK_GET_MODULE_INFO] = rule_allow;
    ap->rule[PA_ACCESS_HOOK_GET_CARD_INFO] = rule_allow;
    ap->rule[PA_ACCESS_HOOK_STAT] = rule_allow;
    ap->rule[PA_ACCESS_HOOK_GET_SAMPLE_INFO] = rule_allow;

    ap->rule[PA_ACCESS_HOOK_PLAY_SAMPLE] = rule_check_portal;
    ap->rule[PA_ACCESS_HOOK_CONNECT_PLAYBACK] = rule_check_portal;
    ap->rule[PA_ACCESS_HOOK_CONNECT_RECORD] = rule_check_portal;

    ap->rule[PA_ACCESS_HOOK_GET_CLIENT_INFO] = rule_check_owner;
    ap->rule[PA_ACCESS_HOOK_KILL_CLIENT] = rule_check_owner;

    ap->rule[PA_ACCESS_HOOK_GET_SINK_INPUT_INFO] = rule_check_owner;
    ap->rule[PA_ACCESS_HOOK_MOVE_SINK_INPUT] = rule_check_owner;
    ap->rule[PA_ACCESS_HOOK_SET_SINK_INPUT_VOLUME] = rule_check_owner;
    ap->rule[PA_ACCESS_HOOK_SET_SINK_INPUT_MUTE] = rule_check_owner;
    ap->rule[PA_ACCESS_HOOK_KILL_SINK_INPUT] = rule_check_owner;

    ap->rule[PA_ACCESS_HOOK_GET_SOURCE_OUTPUT_INFO] = rule_check_owner;
    ap->rule[PA_ACCESS_HOOK_MOVE_SOURCE_OUTPUT] = rule_check_owner;
    ap->rule[PA_ACCESS_HOOK_SET_SOURCE_OUTPUT_VOLUME] = rule_check_owner;
    ap->rule[PA_ACCESS_HOOK_SET_SOURCE_OUTPUT_MUTE] = rule_check_owner;
    ap->rule[PA_ACCESS_HOOK_KILL_SOURCE_OUTPUT] = rule_check_owner;

    u->portal_policy = ap->index;

    pa_modargs_free(ma);
    return 0;

fail:
    pa__done(m);

    if (ma)
        pa_modargs_free(ma);
    return -1;
}

void pa__done(pa_module*m) {
    struct userdata* u;
    int i;

    pa_assert(m);

    if (!(u = m->userdata))
        return;

    for (i = 0; i < PA_ACCESS_HOOK_MAX; i++) {
        if (u->hook[i])
            pa_hook_slot_free(u->hook[i]);
    }

    if (u->policies)
        pa_idxset_free(u->policies, (pa_free_cb_t) access_policy_free);

    if (u->client_put_slot)
        pa_hook_slot_free(u->client_put_slot);
    if (u->client_auth_slot)
        pa_hook_slot_free(u->client_auth_slot);
    if (u->client_proplist_changed_slot)
        pa_hook_slot_free(u->client_proplist_changed_slot);
    if (u->client_unlink_slot)
        pa_hook_slot_free(u->client_unlink_slot);

    if (u->clients)
        pa_hashmap_free(u->clients);

    if (u->connection)
        pa_dbus_connection_unref (u->connection);

    pa_xfree(u);
}
