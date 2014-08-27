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

#include "mem.h"

union align_chunk {
  void      *ptr;
  uint8_t   u8;
  uint16_t  u16;
  uint32_t  u32;
  uint64_t  u64;
  float     f;
  double    d;
};

struct mem_chunk {
  void *next;
};

struct mem_cache {
	struct mem_chunk **pools;
	struct mem_chunk *avail;
  size_t num_pools;
  size_t size;  /* size of chunk in this cache */
  size_t hold;  /* amount of chunks per pool */
  size_t inuse; /* number of chunks in use in this cache */
};

static struct mem_chunk * 
mem_pool_new(size_t size, size_t hold)
{
  struct mem_chunk *mp;
  size_t len;
  
  RUNTIME_ASSERT(size >= sizeof *mp);
  RUNTIME_ASSERT(0 == size % sizeof *mp);
  RUNTIME_ASSERT(hold > 0);
  
  len = hold * size;

  mp = compat_page_align(len);
  if (mp) {
    size_t i, step = size / sizeof *mp;

    for (i = 0; hold-- > 1; i += step) {
      mp[i].next = &mp[i + step];
    }

    mp[i].next = NULL;
  }

  return mp;
}

mem_cache_t *
mem_new(size_t size)
{
  mem_cache_t *mc;

  RUNTIME_ASSERT(size > 0);
  
  mc = calloc(1, sizeof *mc);
  if (mc) {

    if (size > sizeof(struct mem_chunk)) {
      mc->size = round_size(sizeof(union align_chunk), size);
    } else {
      mc->size = sizeof(struct mem_chunk);
    }
    
    mc->hold = MAX(16, compat_getpagesize() / mc->size);
    mc->num_pools = 0;
    mc->avail = NULL;
    mc->pools = NULL;
  }
  return mc;
}
 
void *
mem_alloc(mem_cache_t *mc)
{
  void *p;

  RUNTIME_ASSERT(mc);
  
  if (NULL != (p = mc->avail)) {
    mc->avail = mc->avail->next;
  } else {
    struct mem_chunk *mp;
    
    mp = mem_pool_new(mc->size, mc->hold);
    if (mp) {
      size_t n;

      for (n = mc->num_pools / 2; n < mc->num_pools; n++) {
        if (NULL == mc->pools[mc->num_pools])
          break;
      }

      if (n == mc->num_pools) {
        void *q;

        n = mc->num_pools ? 2 * mc->num_pools : 1;
        RUNTIME_ASSERT(n > mc->num_pools);
        q = realloc(mc->pools, n * sizeof mc->pools[0]);
        if (!q) {
          free(mp);
          return NULL;
        }
        
        mc->pools = q;
        mc->pools[mc->num_pools] = mp;
        while (++mc->num_pools < n) {
          mc->pools[mc->num_pools] = NULL;
        }
      }

      mc->avail = &mp[0];
      p = mc->avail;
      mc->avail = mc->avail->next;
    } else {
      return NULL;
    }
  }

  RUNTIME_ASSERT(p);
  mc->inuse++;
  return p;
}

void
mem_free(mem_cache_t *mc, void *p)
{
  RUNTIME_ASSERT(mc);

  if (p) {
    struct mem_chunk *c = p;
   
    c->next = mc->avail;
    mc->avail = c;
    mc->inuse--;
  }
}

/**
 * Frees the mem_cache_t structure and all cached freed chunks. It DOES NOT
 * free chunks still in use.
 */
void
mem_destruct(mem_cache_t *mc)
{
  if (mc) {
    size_t i;

    for (i = 0; i < mc->num_pools; i++) {
      free(mc->pools[i]);
    }
    free(mc->pools);
    free(mc);
  }
}

#ifdef USE_MALLOC
void *
mem_chunk_alloc(size_t size)
{
  void *p;

  p = malloc(size);
#ifdef LOG_MALLOC 
  DBUG("alloc(%lu)=%p", (unsigned long) size, p);  
#endif
  return p;
}

void
mem_chunk_free(void *p, size_t size)
{
#ifdef LOG_MALLOC 
  DBUG("free(%p, %lu)", p, (unsigned long) size);  
#endif  /* LOG_MALLOC */
  free(p);
}

#else /* !USE_MALLOC */

static struct mem_cache *global_mc[11];

/**
 * Find the appropriate mem cache for the given size.
 */
static struct mem_cache *
find_mc(size_t size)
{
  static bool initialized;
  unsigned i;

  if (!initialized) {
      initialized = true;

      for (i = 0; i < ARRAY_LEN(global_mc); i++)
        global_mc[i] = mem_new(sizeof(void *) << i);
  }

  for (i = 0; i < ARRAY_LEN(global_mc); i++) {
    if (size <= global_mc[i]->size)
      return global_mc[i];
  }

  return NULL;
}

void *
mem_chunk_alloc(size_t size)
{
  struct mem_cache *mc;
  void *p;

  mc = find_mc(size);
  if (mc) {
    p = mem_alloc(mc);
  } else {
    p = compat_page_align(size);
  }

  return p;
}

void
mem_chunk_free(void *p, size_t size)
{
  struct mem_cache *mc;

  mc = find_mc(size);
  if (mc) {
    mem_free(mc, p);
  } else {
    compat_page_free(p, size);
  }
}
#endif

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
