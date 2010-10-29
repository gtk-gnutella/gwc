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

#ifndef EVENT_SOURCE_HEADER_FILE
#define EVENT_SOURCE_HEADER_FILE

#include "common.h"

typedef enum {
  EVT_NONE    = 0,
  EVT_READ    = (1 << 0),
  EVT_WRITE   = (1 << 1),
  EVT_RDWR    = EVT_READ | EVT_WRITE,
  EVT_HANGUP  = (1 << 2),
  EVT_ERROR   = (1 << 3),
  EVT_TIMEOUT = (1 << 4),

  EVT_ANY     = 0x1f 
} ev_type_t;

typedef struct ev_source ev_source_t;
typedef void (*ev_source_cb)(ev_source_t *, ev_type_t);

struct ev_watcher;

/**
 * Constructor
 */
ev_source_t *ev_source_new(int fd);

/**
 * Getters
 */
ev_type_t       ev_source_get_eventmask(ev_source_t *);
unsigned int    ev_source_get_timeout(ev_source_t *);
unsigned long   ev_source_get_age(ev_source_t *);
void *          ev_source_get_context(ev_source_t *);
int             ev_source_get_fd(ev_source_t *);
struct timeval  ev_source_get_stamp(ev_source_t *);
struct ev_watcher *  ev_source_get_watcher(ev_source_t *);

/**
 * Setters
 */
void          ev_source_set_context(ev_source_t *, void *);
void          ev_source_set_event_cb(ev_source_t *, ev_source_cb);
void          ev_source_set_eventmask(ev_source_t *, ev_type_t);
void          ev_source_set_timeout(ev_source_t *, unsigned int);
void          ev_source_set_watcher(ev_source_t *, struct ev_watcher *);

/**
 * Miscellaneous methods
 */
void          ev_source_check(ev_source_t *);
void          ev_source_event(ev_source_t *, ev_type_t, const struct timeval *);
void          ev_source_close(ev_source_t *);
bool          ev_source_is_closed(ev_source_t *);

/**
 * Reference counting
 */
void          ev_source_ref(ev_source_t *);
void          ev_source_unref(ev_source_t *);

/* vi: set ai et sts=2 sw=2 cindent: */
#endif /* EVENT_SOURCE_HEADER_FILE */
