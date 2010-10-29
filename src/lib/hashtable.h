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

#ifndef HASHTABLE_HEADER_FILE
#define HASHTABLE_HEADER_FILE

#include "common.h"

typedef struct hashtable hashtable_t;
typedef bool (* hashtable_cmp_cb)(const void *, const void *);
typedef uint32_t (* hashtable_hash_cb)(const void *);
typedef bool (* hashtable_foreach_cb)(const void *key, const void *value,
	void *udata);

hashtable_t *hashtable_new(size_t size, hashtable_hash_cb, hashtable_cmp_cb);
void hashtable_remove(hashtable_t *ht, const void *key);
bool hashtable_get(hashtable_t *ht, const void *key, void **value);
void hashtable_destruct(hashtable_t *ht);
bool hashtable_add(hashtable_t *ht, const void *key, void *value);
bool hashtable_full(hashtable_t *ht);
bool hashtable_empty(hashtable_t *ht);
size_t hashtable_fill(hashtable_t *ht);
size_t hashtable_size(hashtable_t *ht);
void hashtable_foreach(const hashtable_t *ht,
	hashtable_foreach_cb func, void *udata);

#endif /* HASHTABLE_HEADER_FILE */
