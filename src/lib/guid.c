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

#include "guid.h"
#include "hashtable.h"
#include "mem.h"
#include "nettools.h"

typedef struct guid_rec {
  guid_t guid;
  void *udata;
} guid_rec_t;

typedef struct {
  size_t num_slots;
  hashtable_t *ht;
} guid_tab_t;

static guid_tab_t *guid_tab;

static bool
guid_cmp(const void *p, const void *q)
{
  const guid_t *a = p, *b = q;

  return a->u64[0] == b->u64[0] && a->u64[1] == b->u64[1];
}

static uint32_t 
guid_hash(const void *p)
{
  const guid_t *a = p;
  
  return (uint32_t) (a->u64[0] ^ a->u64[1] ^ ((a->u64[0] ^ a->u64[1]) >> 32));
}

int
guid_init(size_t slots)
{
  if (NULL == (guid_tab = calloc(1, sizeof *guid_tab)))
    goto failure;

  guid_tab->num_slots = slots;
  if (NULL == (guid_tab->ht = hashtable_new(slots, guid_hash, guid_cmp)))
    goto failure;

  return 0;

failure:

  if (guid_tab->ht) {
    hashtable_destruct(guid_tab->ht);
    guid_tab->ht = NULL;
  }
  if (guid_tab) {
    DO_FREE(guid_tab);
  }
  
  return -1;
}

bool
guid_is_bogus(const guid_t *guid)
{
  const uint8_t b = guid->u8[0];
  unsigned i = 1;
  
  for (i = 0; i < ARRAY_LEN(guid->u8); i++) {
    if (b != guid->u8[i++])
      return false;
  }
  
  return true;
}

bool
guid_is_magic(const guid_t *guid, void **udata)
{
  guid_rec_t *rec;
  void *p;
  
  RUNTIME_ASSERT(guid != NULL);
  
  if (hashtable_get(guid_tab->ht, guid, &p)) {
    RUNTIME_ASSERT(p != NULL);
    rec = p;
    if (udata) {
      *udata = rec->udata;
    }
    return true;
  }
  
  return false;
}

int
guid_add(guid_t *guid, void *udata)
{
  guid_rec_t *rec;

  RUNTIME_ASSERT(guid != NULL);
  
  if (NULL == (rec = mem_chunk_alloc(sizeof *rec))) {
    return -1;
  }
  rec->guid = *guid;
  rec->udata = udata;

  if (!hashtable_add(guid_tab->ht, &rec->guid, rec)) {
    mem_chunk_free(rec, sizeof *rec);
    return -1;
  }
  
  return 0;
}

void
guid_remove(guid_t *guid)
{
  void *p;
  
  RUNTIME_ASSERT(guid != NULL);

  if (hashtable_get(guid_tab->ht, guid, &p)) {
    guid_rec_t *rec = p;

    RUNTIME_ASSERT(rec != NULL);
    hashtable_remove(guid_tab->ht, guid);
    mem_chunk_free(rec, sizeof *rec);
  }
}

static inline uint32_t
guid_get_iter(void)
{
  static bool initialized;
  static uint32_t i;
  int j;

  if (!initialized) {
    struct timeval tv;

    compat_mono_time(&tv);
    i = random() ^ (tv.tv_sec << 17) ^ tv.tv_usec;
    initialized = true;
  }

  j = random() & 7;
  do {
    i += 0x3F54133F;
  } while (j-- > 0);
  return i;
}


void
guid_create(guid_t *guid)
{
  uint32_t x, i;
  RUNTIME_ASSERT(guid != NULL);
  
  x = guid_get_iter();
  for (i = 0; i < 4; i++, x >>= 8) {
    guid->u32[i] = ((uint32_t) random() << 8) | (x & 0xff);
  }
}

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
