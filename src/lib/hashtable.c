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

#include "hashtable.h"
#include "mem.h"

typedef struct hash_item {
  const void *key;
  void *value;
  struct hash_item *next;
} hash_item_t;

struct hashtable {
  uint32_t          num_bins; /* Number of bins */
  size_t            fill; /* Number of items actually in the table */
  size_t            bin_fill; /* Number of bins in use */
  uint32_t          rnd;
  hash_item_t       **bins;    /* Array of bins of size ``num_bins'' */
  hashtable_hash_cb hash;
  hashtable_cmp_cb  cmp;
};

#define hashtable_check(ht)                 \
do {                                        \
  const hashtable_t *ht_ = (ht);            \
                                            \
  RUNTIME_ASSERT(ht_ != NULL);                      \
  RUNTIME_ASSERT(ht_->num_bins > 0);                \
} while (0)


static hash_item_t * 
hash_item_get(hashtable_t *ht, const void *key, void *value)
{
  hash_item_t *item;

  RUNTIME_ASSERT(ht != NULL);

  item = mem_chunk_alloc(sizeof *item);
  if (item) {
    item->key = key;
    item->value = value;
    item->next = NULL;
  }
  return item;
}

static void 
hash_item_free(hashtable_t *ht, hash_item_t *item)
{
  RUNTIME_ASSERT(ht != NULL);
  RUNTIME_ASSERT(item != NULL);

  mem_chunk_free(item, sizeof *item);
}

hashtable_t *
hashtable_new(size_t num_bins, hashtable_hash_cb hash, hashtable_cmp_cb cmp)
{
  hashtable_t *ht;
  
  RUNTIME_ASSERT(num_bins > 0);

  ht = mem_chunk_alloc(sizeof *ht);
  if (ht) {
    ht->rnd = random();
    ht->num_bins = num_bins;
    ht->fill = 0;
    ht->bin_fill = 0;
    ht->bins = mem_chunk_alloc(ht->num_bins * sizeof ht->bins[0]);
    if (ht->bins) {
      size_t i;

      for (i = 0; i < ht->num_bins; i++) {
        ht->bins[i] = NULL;
      }
    }
    ht->hash = hash;
    ht->cmp = cmp;
    hashtable_check(ht);
  }
  return ht;
}

/**
 * Checks whether the hashtable contains any items.
 *
 * @param ht the hashtable to check.
 * @return TRUE if there are no items in the hashtable, FALSE otherwise.
 */
bool
hashtable_empty(hashtable_t *ht)
{
  hashtable_check(ht);
  return 0 == ht->fill;
}

/**
 * Checks how many items are currently in stored in the hashtable.
 *
 * @param ht the hashtable to check.
 * @return the number of items in the hashtable.
 */
size_t
hashtable_fill(hashtable_t *ht)
{
  hashtable_check(ht);
  return ht->fill;
}

/**
 * Checks how many bins are currently in used by the hashtable.
 *
 * @param ht the hashtable to check.
 * @return the number of bins used by the hashtable.
 */
size_t
hashtable_bin_fill(hashtable_t *ht)
{
  hashtable_check(ht);
  return ht->bin_fill;
}

/**
 * @param ht a hashtable.
 * @param key the key to look for.
 * @param bin if not NULL, it will be set to the bin number that is or would
 *        be used for the key. It is set regardless whether the key is in
 *        the hashtable.
 * @return NULL if the key is not in the hashtable. Otherwise, the item
 *         associated with the key is returned.
 */
static hash_item_t *
hashtable_find(hashtable_t *ht, const void *key, uint32_t *bin)
{
  hash_item_t *item;
  uint32_t hash, b;

  hashtable_check(ht);

  hash = ht->hash ? ht->hash(key) : (uint32_t) (uintptr_t) key;
  b = (hash ^ ht->rnd) % ht->num_bins;
  item = ht->bins[b];
  if (bin) {
    *bin = b;
  }

  if (ht->cmp) {
    for (/* NOTHING */; item != NULL; item = item->next) {
      if (ht->cmp(key, item->key))
        return item;
    }
  } else {
    for (/* NOTHING */; item != NULL; item = item->next) {
      if (key == item->key)
        return item;
    }
  }

  return NULL;
}

void
hashtable_foreach(const hashtable_t *ht, hashtable_foreach_cb func, void *udata)
{
  size_t i;

  hashtable_check(ht);
  RUNTIME_ASSERT(func != NULL);

  for (i = 0; i < ht->num_bins; i++) {
    hash_item_t *item;

    for (item = ht->bins[i]; NULL != item; item = item->next) {
      if (func(item->key, item->value, udata))
        return;
    }
  }
}

/**
 * Adds a new item to the hashtable. If the hashtable already contains an
 * item with the same key, the value of this item is simply replaced by
 * the new value.
 *
 * @return false if the item could not be added, true on success.
 */
bool
hashtable_add(hashtable_t *ht, const void *key, void *value)
{
  hash_item_t *item;
  uint32_t bin;
  
  hashtable_check(ht);

  item = hashtable_find(ht, key, &bin);

  /* Just replace the value, the key matched an item in the hashtable */
  if (item) {
    item->value = value;
    return true;
  }

  if (NULL == (item = hash_item_get(ht, key, value)))
    return false;

  RUNTIME_ASSERT(item != NULL);
  if (NULL == ht->bins[bin]) {
    RUNTIME_ASSERT(ht->bin_fill < ht->num_bins);
    ht->bin_fill++;
  }
  item->next = ht->bins[bin];
  ht->bins[bin] = item;
  ht->fill++;

  return true;
}

void
hashtable_remove(hashtable_t *ht, const void *key)
{
  hash_item_t *item;
  uint32_t bin;

  item = hashtable_find(ht, key, &bin);
  if (item) {
    hash_item_t *i;

    i = ht->bins[bin];
    RUNTIME_ASSERT(i != NULL);
    if (i == item) {
      if (!i->next) {
        RUNTIME_ASSERT(ht->bin_fill > 0);
        ht->bin_fill--;
      }
      ht->bins[bin] = i->next;
    } else {
      
      RUNTIME_ASSERT(i->next != NULL);
      while (item != i->next) { 
        RUNTIME_ASSERT(i->next != NULL);
        i = i->next;
      }
      RUNTIME_ASSERT(i->next == item);

      i->next = item->next;
    }

    hash_item_free(ht, item);
    ht->fill--;
  }
}

bool
hashtable_get(hashtable_t *ht, const void *key, void **value)
{
  hash_item_t *item;

  hashtable_check(ht);
  item = hashtable_find(ht, key, NULL);
  if (!item)
    return false;
  if (value)
    *value = item->value;
  return true;
}

void
hashtable_destruct(hashtable_t *ht)
{
  size_t i;

  hashtable_check(ht);
  for (i = 0; i < ht->num_bins; i++) {
    hash_item_t *item = ht->bins[i];

    while (item) {
      hash_item_t *next;

      next = item->next;
      hash_item_free(ht, item);
      item = next;
    }
  }

  mem_chunk_free(ht->bins, ht->num_bins * sizeof ht->bins[0]);
  mem_chunk_free(ht, sizeof *ht);
}

/* vi: set ai et sts=2 sw=2 cindent: */
