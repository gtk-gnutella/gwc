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

#ifndef HASHLIST_HEADER_FILE
#define HASHLIST_HEADER_FILE

#include "common.h"
#include "node.h"

typedef struct hashlist hashlist_t;

typedef struct hashlist_iter {
  node_t	*item;
  node_t	removed;
  hashlist_t	*hl;
  int		stamp;
} hashlist_iter_t;

typedef bool (* hashlist_cmp_cb)(const void *, const void *);
typedef uint32_t (* hashlist_hash_cb)(const void *);
typedef bool (* hashlist_foreach_cb)(const void *key, const void *value,
	void *udata);

hashlist_t *hashlist_new(size_t num_bins,
	hashlist_hash_cb, hashlist_cmp_cb);
void hashlist_remove(hashlist_t *hl, const void *key);
bool hashlist_get(hashlist_t *hl, const void *key, void **value);
void hashlist_destruct(hashlist_t *hl);
bool hashlist_append(hashlist_t *hl, const void *key, void *value);
bool hashlist_prepend(hashlist_t *hl, const void *key, void *value);
bool hashlist_empty(hashlist_t *hl);
size_t hashlist_fill(hashlist_t *hl);
size_t hashlist_bin_fill(hashlist_t *hl);
void hashlist_foreach(const hashlist_t *hl,
	hashlist_foreach_cb func, void *udata);

bool hashlist_iter_first(hashlist_iter_t *iter, hashlist_t *hl);
bool hashlist_iter_last(hashlist_iter_t *iter, hashlist_t *hl);
bool hashlist_iter_prev(hashlist_iter_t *iter);
bool hashlist_iter_next(hashlist_iter_t *iter);
const void *hashlist_iter_get_key(hashlist_iter_t *iter);
void *hashlist_iter_get_value(hashlist_iter_t *iter);
void hashlist_iter_delete(hashlist_iter_t *iter);

#endif /* HASHLIST_HEADER_FILE */
