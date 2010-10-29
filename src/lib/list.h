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

#ifndef LIST_HEADER_FILE
#define LIST_HEADER_FILE

#include "common.h"
#include "node.h"

typedef struct list list_t;

typedef struct list_iter {
  node_t  *node;
  node_t  removed;
  list_t  *l;
  int     stamp;
} list_iter_t;

list_t *list_new(void);
void list_free(list_t *l);
void *list_get_last(const list_t *l);
size_t list_get_length(const list_t *l);
bool list_append(list_t *l, void *ptr);
bool list_prepend(list_t *l, void *ptr);
bool list_empty(const list_t *l);

void *list_iter_get_ptr(list_iter_t *i);
void list_iter_delete(list_iter_t *i);
bool list_iter_append(list_iter_t *i, void *ptr);
bool list_iter_prepend(list_iter_t *i, void *ptr);
bool list_iter_next(list_iter_t *i);
bool list_iter_prev(list_iter_t *i);
bool list_iter_first(list_iter_t *i, list_t *l);
bool list_iter_last(list_iter_t *i, list_t *l);


/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
#endif /* LIST_HEADER_FILE */
