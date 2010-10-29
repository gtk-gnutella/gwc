/*
 * Copyright (c) 2004
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

#ifndef SLIST_HEADER_FILE
#define SLIST_HEADER_FILE

#include "lib/common.h"
#include "lib/snode.h"

typedef struct slist slist_t;

typedef struct slist_iter {
  snode_t  *node;
  snode_t  *prev;
  snode_t  removed;
  slist_t  *l;
  int     stamp;
} slist_iter_t;

slist_t *slist_new(void);
void slist_free(slist_t *l);
void *slist_get_last(const slist_t *l);
size_t slist_get_length(const slist_t *l);
bool slist_prepend(slist_t *l, void *ptr);

void *slist_iter_get_ptr(slist_iter_t *i);
void slist_iter_delete(slist_iter_t *i);
bool slist_iter_append(slist_iter_t *i, void *ptr);
bool slist_iter_prepend(slist_iter_t *i, void *ptr);
bool slist_iter_next(slist_iter_t *i);
bool slist_iter_prev(slist_iter_t *i);
bool slist_iter_first(slist_iter_t *i, slist_t *l);
bool slist_iter_last(slist_iter_t *i, slist_t *l);
slist_t *slist_copy(slist_t *to_copy);


/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
#endif /* SLIST_HEADER_FILE */
