/* $Id$ */

/***
  This file is part of polypaudio.
 
  polypaudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published
  by the Free Software Foundation; either version 2 of the License,
  or (at your option) any later version.
 
  polypaudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.
 
  You should have received a copy of the GNU Lesser General Public License
  along with polypaudio; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>

#include "glib-mainloop.h"
#include "idxset.h"
#include "xmalloc.h"

/* A mainloop implementation based on GLIB 1.2 */

struct pa_io_event {
    struct pa_glib_mainloop *mainloop;
    int dead;
    GIOChannel *io_channel;
    guint source;
    GIOCondition io_condition;
    int fd;
    void (*callback) (struct pa_mainloop_api*m, struct pa_io_event *e, int fd, enum pa_io_event_flags f, void *userdata);
    void *userdata;
    void (*destroy_callback) (struct pa_mainloop_api *m, struct pa_io_event*e, void *userdata);
    struct pa_io_event *next, *prev;
};

struct pa_time_event {
    struct pa_glib_mainloop *mainloop;
    int dead;
    guint source;
    struct timeval timeval;
    void (*callback) (struct pa_mainloop_api*m, struct pa_time_event *e, const struct timeval *tv, void *userdata);
    void *userdata;
    void (*destroy_callback) (struct pa_mainloop_api *m, struct pa_time_event*e, void *userdata);
    struct pa_time_event *next, *prev;
};

struct pa_defer_event {
    struct pa_glib_mainloop *mainloop;
    int dead;
    guint source;
    void (*callback) (struct pa_mainloop_api*m, struct pa_defer_event *e, void *userdata);
    void *userdata;
    void (*destroy_callback) (struct pa_mainloop_api *m, struct pa_defer_event*e, void *userdata);
    struct pa_defer_event *next, *prev;
};

struct pa_glib_mainloop {
    struct pa_mainloop_api api;
    guint cleanup_source;
    struct pa_io_event *io_events, *dead_io_events;
    struct pa_time_event *time_events, *dead_time_events;
    struct pa_defer_event *defer_events, *dead_defer_events;
};

static void schedule_free_dead_events(struct pa_glib_mainloop *g);

static void glib_io_enable(struct pa_io_event*e, enum pa_io_event_flags f);

static struct pa_io_event* glib_io_new(struct pa_mainloop_api*m, int fd, enum pa_io_event_flags f, void (*callback) (struct pa_mainloop_api*m, struct pa_io_event*e, int fd, enum pa_io_event_flags f, void *userdata), void *userdata) {
    struct pa_io_event *e;
    struct pa_glib_mainloop *g;

    assert(m && m->userdata && fd >= 0 && callback);
    g = m->userdata;

    e = pa_xmalloc(sizeof(struct pa_io_event));
    e->mainloop = m->userdata;
    e->dead = 0;
    e->fd = fd;
    e->callback = callback;
    e->userdata = userdata;
    e->destroy_callback = NULL;

    e->io_channel = g_io_channel_unix_new(e->fd);
    assert(e->io_channel);
    e->source = (guint) -1;
    e->io_condition = 0;

    glib_io_enable(e, f);

    e->next = g->io_events;
    if (e->next) e->next->prev = e;
    g->io_events = e;
    e->prev = NULL;
    
    return e;
}

static gboolean io_cb(GIOChannel *source, GIOCondition condition, gpointer data) {
    struct pa_io_event *e = data;
    enum pa_io_event_flags f;
    assert(source && e && e->io_channel == source);

    f = (condition & G_IO_IN ? PA_IO_EVENT_INPUT : 0) |
        (condition & G_IO_OUT ? PA_IO_EVENT_OUTPUT : 0) |
        (condition & G_IO_ERR ? PA_IO_EVENT_ERROR : 0) |
        (condition & G_IO_HUP ? PA_IO_EVENT_HANGUP : 0);
    
    e->callback(&e->mainloop->api, e, e->fd, f, e->userdata);
    return TRUE;
}

static void glib_io_enable(struct pa_io_event*e, enum pa_io_event_flags f) {
    GIOCondition c;
    assert(e && !e->dead);

    c = (f & PA_IO_EVENT_INPUT ? G_IO_IN : 0) | (f & PA_IO_EVENT_OUTPUT ? G_IO_OUT : 0);
    
    if (c == e->io_condition)
        return;
    
    if (e->source != (guint) -1)
        g_source_remove(e->source);

    e->source = g_io_add_watch_full(e->io_channel, G_PRIORITY_DEFAULT, c | G_IO_ERR | G_IO_HUP, io_cb, e, NULL);
    assert(e->source != (guint) -1);
    e->io_condition = c;
}

static void glib_io_free(struct pa_io_event*e) {
    assert(e && !e->dead);

    if (e->source != (guint) -1) {
        g_source_remove(e->source);
        e->source = (guint) -1;
    }
    
    if (e->prev)
        e->prev->next = e->next;
    else
        e->mainloop->io_events = e->next;

    if (e->next)
        e->next->prev = e->prev;

    if ((e->next = e->mainloop->dead_io_events))
        e->next->prev = e;

    e->mainloop->dead_io_events = e;
    e->prev = NULL;

    e->dead = 1;
    schedule_free_dead_events(e->mainloop);
}

static void glib_io_set_destroy(struct pa_io_event*e, void (*callback)(struct pa_mainloop_api*m, struct pa_io_event *e, void *userdata)) {
    assert(e);
    e->destroy_callback = callback;
}

/* Time sources */

static void glib_time_restart(struct pa_time_event*e, const struct timeval *tv);

static struct pa_time_event* glib_time_new(struct pa_mainloop_api*m, const struct timeval *tv, void (*callback) (struct pa_mainloop_api*m, struct pa_time_event*e, const struct timeval *tv, void *userdata), void *userdata) {
    struct pa_glib_mainloop *g;
    struct pa_time_event *e;
    
    assert(m && m->userdata && tv && callback);
    g = m->userdata;

    e = pa_xmalloc(sizeof(struct pa_time_event));
    e->mainloop = g;
    e->dead = 0;
    e->callback = callback;
    e->userdata = userdata;
    e->destroy_callback = NULL;
    e->source = (guint) -1;

    glib_time_restart(e, tv);

    e->next = g->time_events;
    if (e->next) e->next->prev = e;
    g->time_events = e;
    e->prev = NULL;
    
    return e;
}

static guint msec_diff(const struct timeval *a, const struct timeval *b) {
    guint r;
    assert(a && b);
    
    if (a->tv_sec < b->tv_sec)
        return 0;

    if (a->tv_sec == b->tv_sec && a->tv_sec <= b->tv_sec)
        return 0;

    r = (a->tv_sec-b->tv_sec)*1000;

    if (a->tv_usec >= b->tv_usec)
        r += (a->tv_usec - b->tv_usec) / 1000;
    else
        r -= (b->tv_usec - a->tv_usec) / 1000;
    
    return r;
}

static gboolean time_cb(gpointer data) {
    struct pa_time_event* e = data;
    assert(e && e->mainloop && e->source != (guint) -1);

    g_source_remove(e->source);
    e->source = (guint) -1;

    e->callback(&e->mainloop->api, e, &e->timeval, e->userdata);
    return FALSE;
}

static void glib_time_restart(struct pa_time_event*e, const struct timeval *tv) {
    struct timeval now;
    assert(e && e->mainloop && !e->dead);

    gettimeofday(&now, NULL);
    if (e->source != (guint) -1)
        g_source_remove(e->source);

    if (tv) {
        e->timeval = *tv;
        e->source = g_timeout_add_full(G_PRIORITY_DEFAULT, msec_diff(tv, &now), time_cb, e, NULL);
        assert(e->source != (guint) -1);
    } else
        e->source = (guint) -1;
 }

static void glib_time_free(struct pa_time_event *e) {
    assert(e && e->mainloop && !e->dead);

    if (e->source != (guint) -1) {
        g_source_remove(e->source);
        e->source = (guint) -1;
    }

    if (e->prev)
        e->prev->next = e->next;
    else
        e->mainloop->time_events = e->next;

    if (e->next)
        e->next->prev = e->prev;

    if ((e->next = e->mainloop->dead_time_events))
        e->next->prev = e;

    e->mainloop->dead_time_events = e;
    e->prev = NULL;

    e->dead = 1;
    schedule_free_dead_events(e->mainloop);
}

static void glib_time_set_destroy(struct pa_time_event *e, void (*callback)(struct pa_mainloop_api*m, struct pa_time_event*e, void *userdata)) {
    assert(e);
    e->destroy_callback = callback;
}

/* Deferred sources */

static void glib_defer_enable(struct pa_defer_event *e, int b);

static struct pa_defer_event* glib_defer_new(struct pa_mainloop_api*m, void (*callback) (struct pa_mainloop_api*m, struct pa_defer_event *e, void *userdata), void *userdata) {
    struct pa_defer_event *e;
    struct pa_glib_mainloop *g;

    assert(m && m->userdata && callback);
    g = m->userdata;
    
    e = pa_xmalloc(sizeof(struct pa_defer_event));
    e->mainloop = g;
    e->dead = 0;
    e->callback = callback;
    e->userdata = userdata;
    e->destroy_callback = NULL;
    e->source = (guint) -1;

    glib_defer_enable(e, 1);

    e->next = g->defer_events;
    if (e->next) e->next->prev = e;
    g->defer_events = e;
    e->prev = NULL;
    return e;
}

static gboolean idle_cb(gpointer data) {
    struct pa_defer_event* e = data;
    assert(e && e->mainloop && e->source != (guint) -1);

    e->callback(&e->mainloop->api, e, e->userdata);
    return TRUE;
}

static void glib_defer_enable(struct pa_defer_event *e, int b) {
    assert(e && e->mainloop);

    if (e->source != (guint) -1 && !b) {
        g_source_remove(e->source);
        e->source = (guint) -1;
    } else if (e->source == (guint) -1 && b) {
        e->source = g_idle_add_full(G_PRIORITY_HIGH, idle_cb, e, NULL);
        assert(e->source != (guint) -1);
    }
}

static void glib_defer_free(struct pa_defer_event *e) {
    assert(e && e->mainloop && !e->dead);

    if (e->source != (guint) -1) {
        g_source_remove(e->source);
        e->source = (guint) -1;
    }

    if (e->prev)
        e->prev->next = e->next;
    else
        e->mainloop->defer_events = e->next;

    if (e->next)
        e->next->prev = e->prev;

    if ((e->next = e->mainloop->dead_defer_events))
        e->next->prev = e;

    e->mainloop->dead_defer_events = e;
    e->prev = NULL;

    e->dead = 1;
    schedule_free_dead_events(e->mainloop);
}

static void glib_defer_set_destroy(struct pa_defer_event *e, void (*callback)(struct pa_mainloop_api *m, struct pa_defer_event *e, void *userdata)) {
    assert(e);
    e->destroy_callback = callback;
}

/* quit() */

static void glib_quit(struct pa_mainloop_api*a, int retval) {
    struct pa_glib_mainloop *g;
    assert(a && a->userdata);
    g = a->userdata;

    /* NOOP */
}

static const struct pa_mainloop_api vtable = {
    .userdata = NULL,

    .io_new = glib_io_new,
    .io_enable = glib_io_enable,
    .io_free = glib_io_free,
    .io_set_destroy= glib_io_set_destroy,

    .time_new = glib_time_new,
    .time_restart = glib_time_restart,
    .time_free = glib_time_free,
    .time_set_destroy = glib_time_set_destroy,
    
    .defer_new = glib_defer_new,
    .defer_enable = glib_defer_enable,
    .defer_free = glib_defer_free,
    .defer_set_destroy = glib_defer_set_destroy,
    
    .quit = glib_quit,
};

struct pa_glib_mainloop *pa_glib_mainloop_new(void) {
    struct pa_glib_mainloop *g;
    
    g = pa_xmalloc(sizeof(struct pa_glib_mainloop));
    
    g->api = vtable;
    g->api.userdata = g;

    g->io_events = g->dead_io_events = NULL;
    g->time_events = g->dead_time_events = NULL;
    g->defer_events = g->dead_defer_events = NULL;

    g->cleanup_source = (guint) -1;
    return g;
}

static void free_io_events(struct pa_io_event *e) {
    while (e) {
        struct pa_io_event *r = e;
        e = r->next;

        if (r->source != (guint) -1)
            g_source_remove(r->source);

        if (r->io_channel)
            g_io_channel_unref(r->io_channel);
        
        if (r->destroy_callback)
            r->destroy_callback(&r->mainloop->api, r, r->userdata);

        pa_xfree(r);
    }
}

static void free_time_events(struct pa_time_event *e) {
    while (e) {
        struct pa_time_event *r = e;
        e = r->next;

        if (r->source != (guint) -1)
            g_source_remove(r->source);
        
        if (r->destroy_callback)
            r->destroy_callback(&r->mainloop->api, r, r->userdata);

        pa_xfree(r);
    }
}

static void free_defer_events(struct pa_defer_event *e) {
    while (e) {
        struct pa_defer_event *r = e;
        e = r->next;

        if (r->source != (guint) -1)
            g_source_remove(r->source);
        
        if (r->destroy_callback)
            r->destroy_callback(&r->mainloop->api, r, r->userdata);

        pa_xfree(r);
    }
}

void pa_glib_mainloop_free(struct pa_glib_mainloop* g) {
    assert(g);

    free_io_events(g->io_events);
    free_io_events(g->dead_io_events);
    free_defer_events(g->defer_events);
    free_defer_events(g->dead_defer_events);
    free_time_events(g->time_events);
    free_time_events(g->dead_time_events);

    if (g->cleanup_source != (guint) -1)
        g_source_remove(g->cleanup_source);

    pa_xfree(g);
}

struct pa_mainloop_api* pa_glib_mainloop_get_api(struct pa_glib_mainloop *g) {
    assert(g);
    return &g->api;
}

static gboolean free_dead_events(gpointer p) {
    struct pa_glib_mainloop *g = p;
    assert(g);

    free_io_events(g->dead_io_events);
    free_defer_events(g->dead_defer_events);
    free_time_events(g->dead_time_events);

    g->dead_io_events = NULL;
    g->dead_defer_events = NULL;
    g->dead_time_events = NULL;

    g_source_remove(g->cleanup_source);
    g->cleanup_source = (guint) -1;

    return FALSE;
}

static void schedule_free_dead_events(struct pa_glib_mainloop *g) {
    assert(g);

    if (g->cleanup_source != (guint) -1)
        return;
    
    g->cleanup_source = g_idle_add_full(G_PRIORITY_HIGH, free_dead_events, g, NULL);
}
