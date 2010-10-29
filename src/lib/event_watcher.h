/*
 * Copyright (c) 2006 Christian Biere <christianbiere@gmx.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef EVENT_WATCHER_HEADER_FILE
#define EVENT_WATCHER_HEADER_FILE

#include "common.h"

#include "event_source.h"

typedef struct ev_watcher ev_watcher_t;

typedef void (*ev_watcher_periodic_cb_t)(ev_watcher_t *,const struct timeval *);
typedef void (*ev_watcher_process_cb_t)(ev_watcher_t *, pid_t); 

/**
 * Constructor
 */
ev_watcher_t *ev_watcher_new(void);

/**
 * Setters
 */
void  ev_watcher_set_periodic_cb(ev_watcher_t *, ev_watcher_periodic_cb_t);
void  ev_watcher_set_timeout(ev_watcher_t *, unsigned long);

/**
 * Miscellaneous methods
 */
void  ev_watcher_check(ev_watcher_t *);
void  ev_watcher_mainloop(ev_watcher_t *);
int   ev_watcher_watch_source(ev_watcher_t *, ev_source_t *, ev_type_t);
void  ev_watcher_source_closed(ev_watcher_t *, ev_source_t *);
int   ev_watcher_watch_process(ev_watcher_t *, pid_t, ev_watcher_process_cb_t);

/**
 * Destructor
 */
void  ev_watcher_destruct(ev_watcher_t *);

/* vi: set ai et sts=2 sw=2 cindent: */
#endif /* EVENT_WATCHER_HEADER_FILE */
