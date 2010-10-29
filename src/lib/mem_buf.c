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

#include "mem_buf.h"
#include "mem.h"

struct mem_buf *
mem_buf_new_shallow(void *base, size_t size, void (*destruct)(struct mem_buf *))
{
  struct mem_buf *mb;

  mb = mem_chunk_alloc(sizeof *mb);
  if (mb) {
    mb->base = base;
    mb->size = size;
    mb->fill = size;
    mb->destruct = destruct;
    mb->refs = 1;
  }
  return mb;
}

struct mem_buf *
mem_buf_new_chunk(size_t size)
{
  struct mem_buf *mb;

  mb = mem_chunk_alloc(sizeof *mb);
  if (mb) {
    mb->base = mem_chunk_alloc(size);
    mb->size = size;
    mb->fill = 0;
    mb->destruct = mem_buf_destruct_mem_chunk;
    mb->refs = 1;
  }
  return mb;
}

struct mem_buf *
mem_buf_new_copy(const void *data, size_t size)
{
  struct mem_buf *mb;

  mb = mem_buf_new_chunk(size);
  if (mb) {
    memcpy(mb->base, data, size);
    mb->fill = size;
  }
  return mb;
}

void
mem_buf_ref(struct mem_buf *mb)
{
  RUNTIME_ASSERT(mb);
  RUNTIME_ASSERT(mb->refs > 0);
  RUNTIME_ASSERT(mb->refs < INT_MAX);
  
  mb->refs++;
}

static void
mem_buf_destruct(struct mem_buf *mb)
{
  RUNTIME_ASSERT(0 == mb->refs);
  if (mb->destruct) {
    mb->destruct(mb);
  }
}

void
mem_buf_destruct_mem_chunk(struct mem_buf *mb)
{
  RUNTIME_ASSERT(mb);
  RUNTIME_ASSERT(mb->base);
  RUNTIME_ASSERT(mb->size > 0);
  RUNTIME_ASSERT(mb->fill <= mb->size);
  RUNTIME_ASSERT(0 == mb->refs);

  mem_chunk_free(mb->base, mb->size);
}

void
mem_buf_unref(struct mem_buf *mb)
{
  RUNTIME_ASSERT(mb);
  RUNTIME_ASSERT(mb->refs > 0);
  if (0 == --(mb->refs)) {
    mem_buf_destruct(mb);
    mem_chunk_free(mb, sizeof *mb);
  }
}

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
