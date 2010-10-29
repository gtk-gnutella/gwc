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

#ifndef MEM_HEADER_FILE
#define MEM_HEADER_FILE

#include "common.h"

typedef struct mem_cache mem_cache_t;

mem_cache_t *mem_new(size_t chunk_size);
void *mem_alloc(mem_cache_t *mc);
void mem_free(mem_cache_t *mc, void *p);
void mem_destruct(mem_cache_t *mc);

void *mem_chunk_alloc(size_t size);
void mem_chunk_free(void *p, size_t size);

static inline void *
mem_chunk_copy(const void *data, size_t size)
{
  void *p;
  
  p = mem_chunk_alloc(size);
  if (p) {
    memcpy(p, data, size);
  }
  return p;
}

static inline void *
mem_chunk_strdup(const char *s)
{
  void *p;

  if (s) {
    size_t size;
    
    size = 1 + strlen(s);
    p = mem_chunk_alloc(size);
    if (p) {
      memcpy(p, s, size);
    }
  } else {
    p = NULL;
  }
  return p;
}

static inline void
mem_chunk_strfree(char *s)
{
  if (s) {
    mem_chunk_free(s, 1 + strlen(s));
  }
}


/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
#endif /* MEM_HEADER_FILE */
