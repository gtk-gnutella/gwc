/*
 * Copyright (c) 2005
 *    Christian Biere <christianbiere@gmx.de> All rights reserved.
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

#ifndef SNODE_HEADER_FILE
#define SNODE_HEADER_FILE

#include "common.h"

typedef struct snode {
  void *ptr;
  struct snode *next;
} snode_t;

snode_t *snode_new(void *ptr);
void snode_free(snode_t *sn);

static inline snode_t *
snode_append(snode_t *first, snode_t *sn)
{
  snode_t *n;
  
  if (!first)
    return sn;
  
  n = first;
  while (n->next)
    n = n->next;

  n->next = sn;
  return first;
}

static inline snode_t *
snode_prepend(snode_t *first, snode_t *sn)
{
  snode_t *n;
  
  if (!first)
    return sn;
  if (!sn)
    return first;
  
  n = sn;
  while (n->next)
    n = n->next;

  n->next = first;
  return sn;
}

static inline snode_t *
snode_reverse(snode_t *sn)
{
  snode_t *last, *next;
  
  if (!sn || !sn->next)
    return sn;

  last = NULL;
  while (NULL != (next = sn->next)) {
    sn->next = last;
    last = sn;
    sn = next;
  }
  sn->next = last;
  
  return sn;
}

static inline snode_t *
snode_remove(snode_t *sn, void *ptr)
{
  snode_t *last, *first;
  
  if (!sn)
    return NULL;

  if (sn->ptr == ptr)
    return sn->next;

  first = sn;
  for (last = sn, sn = sn->next; sn != NULL; last = sn, sn = sn->next) {
    if (sn->ptr == ptr) {
      last->next = sn->next;
      break;
    }
  }

  return first;
}

static inline snode_t *
snode_find(snode_t *sn, void *ptr)
{
  while (sn != NULL) {
    if (sn->ptr == ptr)
      break;
    sn = sn->next;
  }

  return sn;
}

static inline snode_t *
snode_copy_all(const snode_t *first)
{
  const snode_t *sn;
  snode_t *sn_copy = NULL, *last = NULL;

  for (sn = first; NULL != sn; sn = sn->next) {
    snode_t *sn_new;

    sn_new = snode_new(sn->ptr);
    sn_copy = snode_append(last, sn_new);
    last = sn_new;
  }
  return sn_copy;
}

static inline void
snode_foreach(snode_t *sn, bool (*func)(snode_t *))
{
  if (func) {
    while (sn) {
      snode_t *next;

      next = sn->next;
      if (func(sn))
        break;
      sn = next;
    }
  }
}

static inline void
snode_foreach_with_data(snode_t *sn,
    bool (*func)(snode_t *, void *data), void *data)
{
  if (func) {
    while (sn) {
      snode_t *next;

      next = sn->next;
      if (func(sn, data))
        break;
      sn = next;
    }
  }
}

static inline bool
snode_free_(snode_t *sn)
{
  snode_free(sn);
  return false;
}

static inline void
snode_free_all(snode_t *sn)
{
  snode_foreach(sn, snode_free_);
}

static inline snode_t * 
snode_copy(snode_t *sn)
{
  return sn ? snode_new(sn->ptr) : NULL;
}

static inline snode_t * 
snode_append_copy(snode_t *anchor, snode_t *sn)
{
  return snode_append(anchor, snode_copy(sn));
}

static inline snode_t * 
snode_append_data(snode_t *anchor, void *data)
{
  return snode_append(anchor, snode_new(data));
}

static inline snode_t * 
snode_prepend_data(snode_t *anchor, void *data)
{
  return snode_prepend(anchor, snode_new(data));
}

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
#endif /* SNODE_HEADER_FILE */
