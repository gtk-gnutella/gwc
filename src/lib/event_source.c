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

#include "event_source.h"
#include "event_watcher.h"

#include "mem.h"
#include "oop.h"

typedef enum ev_source_magic {
  EV_SOURCE_MAGIC = 0x928a3707
} ev_source_magic_t;

struct ev_source {
  ev_source_magic_t   magic;
  int                 ref_count;

  struct ev_watcher   *watcher;
  void                *context;
  void                (*event_cb)(ev_source_t *, ev_type_t);
  struct timeval      stamp;
  struct timeval      established;
  ev_type_t           eventmask;
  unsigned int        timeout;
  int                 fd;
};

#define GETTER(type, attr) \
type \
ev_source_get_ ## attr (ev_source_t *evs) \
{ \
  ev_source_check(evs); \
  return (evs->attr); \
}

#define SETTER(type, attr) \
void \
ev_source_set_ ## attr (ev_source_t *evs, type val) \
{ \
  ev_source_check(evs); \
  evs->attr = (val); \
}

GETTER(struct timeval, stamp)
GETTER(int, fd)
GETTER(ev_type_t, eventmask)
GETTER(unsigned, timeout)
GETTER(void *, context)
GETTER(struct ev_watcher *, watcher)
  
SETTER(ev_type_t, eventmask)
SETTER(unsigned, timeout)
SETTER(void *, context)
SETTER(ev_source_cb, event_cb)
SETTER(struct ev_watcher *, watcher)

void
ev_source_check(ev_source_t *evs)
{
  RUNTIME_ASSERT(evs);
  RUNTIME_ASSERT(EV_SOURCE_MAGIC == evs->magic);
  RUNTIME_ASSERT(evs->ref_count > 0);
  RUNTIME_ASSERT(evs->fd >= -1);
}

void
ev_source_event(ev_source_t *evs, ev_type_t evt, const struct timeval *now)
{
  ev_source_check(evs);

  if (
      EVT_NONE == evt &&
      evs->timeout &&
      DIFFTIMEVAL(now, &evs->stamp) / 1000 >= evs->timeout
  ) {
    evt = EVT_TIMEOUT;
  }

  if (EVT_NONE != evt && evs->event_cb) {
      evs->stamp = *now;
      evs->event_cb(evs, evt);
  }
}

static ev_source_t *
ev_source_alloc(void)
{
  ev_source_t *evs;

  evs = mem_chunk_alloc(sizeof *evs);
  return evs;
}

static void
ev_source_free(ev_source_t *evs)
{
  if (evs) {
    evs->magic = 0;
    evs->watcher = NULL;
    evs->event_cb = NULL;
    evs->context = NULL;
    evs->fd = -2;
    mem_chunk_free(evs, sizeof *evs);
  }
}

void
ev_source_ref(ev_source_t *evs)
{
  ev_source_check(evs);
  RUNTIME_ASSERT(evs->ref_count > 0);
  RUNTIME_ASSERT(evs->ref_count < INT_MAX);
  evs->ref_count++;
}

void
ev_source_unref(ev_source_t *evs)
{
  ev_source_check(evs);
  RUNTIME_ASSERT(evs->ref_count > 0);
  evs->ref_count--;
  if (0 == evs->ref_count) {
    ev_source_free(evs);
  }
}

unsigned long 
ev_source_get_age(ev_source_t *evs)
{
  ev_source_check(evs);
  return DIFFTIMEVAL(&evs->stamp, &evs->established) / 1000000;
}

bool
ev_source_is_closed(ev_source_t *evs)
{
  ev_source_check(evs);
  return evs->fd < 0;
}

void
ev_source_close(ev_source_t *evs)
{
  ev_source_check(evs);
  RUNTIME_ASSERT(evs->fd >= 0);
  if (evs->watcher) {
    ev_watcher_check(evs->watcher);
    ev_watcher_source_closed(evs->watcher, evs);
  }
  evs->fd = -1;
}

ev_source_t *
ev_source_new(int fd)
{
  ev_source_t *evs;

  RUNTIME_ASSERT(fd >= 0);

  evs = ev_source_alloc();
  if (evs) {
    evs->magic = EV_SOURCE_MAGIC;
    evs->ref_count = 1;

    compat_mono_time(&evs->stamp);
    evs->fd = fd;
    evs->established = evs->stamp;
    evs->context = NULL;
    evs->event_cb = NULL;
    evs->watcher = NULL;
    evs->timeout = 0;
    evs->eventmask = EVT_NONE;
  }
  return evs;
}

/* vi: set ai et sts=2 sw=2 cindent: */
