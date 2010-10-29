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

#include "hashlist.h"
#include "mem.h"

typedef struct hash_item {
  node_t node;
  void *value;
  struct hash_item *bnext;   /* Next item in the same bin */
} hash_item_t;

struct hashlist {
  hash_item_t       **bins;    /* Array of bins of size ``num_bins'' */
  node_t            *first;
  node_t            *last;
  hashlist_hash_cb  hash;
  hashlist_cmp_cb   cmp;
  int               stamp;
  uint32_t          num_bins; /* Number of bins */
  size_t            fill;     /* Number of items actually in the list */
  size_t            bin_fill; /* Number of bins in use */
  uint32_t          rnd;
};

#define HASHLIST_CHECK(hl)                 \
do {                                        \
  const hashlist_t *hl_ = (hl);            \
                                            \
  RUNTIME_ASSERT(hl_ != NULL);                      \
  RUNTIME_ASSERT(hl_->num_bins > 0);                \
  RUNTIME_ASSERT((hl_->fill == 0) ^ (NULL != hl_->first)); \
  RUNTIME_ASSERT((hl_->fill == 0) ^ (NULL != hl_->last)); \
  RUNTIME_ASSERT((hl_->fill > 1) ^ (hl_->first == hl_->last)); \
} while (0)

/* Checks whether the iter and the list are in sync */
#define HASHLIST_ITER_CHECK(i)      \
do {                                    \
  const hashlist_iter_t *iter_ = (i);   \
                                        \
  RUNTIME_ASSERT(iter_ != NULL);                \
  RUNTIME_ASSERT(iter_->hl != NULL);            \
  RUNTIME_ASSERT(iter_->stamp == iter_->hl->stamp);            \
} while (0)


static hash_item_t * 
hash_item_get(hashlist_t *hl, const void *key, void *value)
{
  hash_item_t *item;

  RUNTIME_ASSERT(hl != NULL);

  item = mem_chunk_alloc(sizeof *item);
  if (item) {
    item->bnext = NULL;
    item->value = value;
    item->node.ptr = deconstify_void_ptr(key);
    item->node.prev = NULL;
    item->node.next = NULL;
  }
  return item;
}

static void 
hash_item_free(hashlist_t *hl, hash_item_t *item)
{
  RUNTIME_ASSERT(hl != NULL);
  RUNTIME_ASSERT(item != NULL);

  mem_chunk_free(item, sizeof *item);
}

hashlist_t *
hashlist_new(size_t num_bins, hashlist_hash_cb hash, hashlist_cmp_cb cmp)
{
  hashlist_t *hl;
  
  RUNTIME_ASSERT(num_bins > 0);

  hl = calloc(1, sizeof *hl);
  if (hl) {
    hl->rnd = random();
    hl->num_bins = num_bins;
    hl->fill = 0;
    hl->bin_fill = 0;
    hl->bins = calloc(hl->num_bins, sizeof(hl->bins[0]));
    hl->hash = hash;
    hl->cmp = cmp;
    hl->first = NULL;
    hl->last = NULL;
    hl->stamp = 0;
    HASHLIST_CHECK(hl);
  }
  return hl;
}

/**
 * Checks whether the hashlist contains any items.
 *
 * @param hl the hashlist to check.
 * @return TRUE if there are no items in the hashlist, FALSE otherwise.
 */
bool
hashlist_empty(hashlist_t *hl)
{
  HASHLIST_CHECK(hl);
  return hl->fill == 0;
}

/**
 * Checks how many items are currently in stored in the hashlist.
 *
 * @param hl the hashlist to check.
 * @return the number of items in the hashlist.
 */
size_t
hashlist_fill(hashlist_t *hl)
{
  HASHLIST_CHECK(hl);
  return hl->fill;
}

/**
 * Checks how many bins are currently in used by the hashlist.
 *
 * @param hl the hashlist to check.
 * @return the number of bins used by the hashlist.
 */
size_t
hashlist_bin_fill(hashlist_t *hl)
{
  HASHLIST_CHECK(hl);
  return hl->bin_fill;
}

/**
 * @param hl a hashlist.
 * @param key the key to look for.
 * @param bin if not NULL, it will be set to the bin number that is or would
 *        be used for the key. It is set regardless whether the key is in
 *        the hashlist.
 * @return NULL if the key is not in the hashlist. Otherwise, the item
 *         associated with the key is returned.
 */
static hash_item_t *
hashlist_find(hashlist_t *hl, const void *key, uint32_t *bin)
{
  hash_item_t *item;
  uint32_t hash, b;

  HASHLIST_CHECK(hl);

  hash = hl->hash ? hl->hash(key) : (uint32_t) PTR2UINT(key);
  b = (hash ^ hl->rnd) % hl->num_bins;
  item = hl->bins[b];
  if (bin) {
    *bin = b;
  }

  if (hl->cmp) {
    for (/* NOTHING */; item != NULL; item = item->bnext) {
      if (hl->cmp(key, item->node.ptr))
        return item;
    }
  } else {
    for (/* NOTHING */; item != NULL; item = item->bnext) {
      if (key == item->node.ptr)
        return item;
    }
  }

  return NULL;
}

void
hashlist_foreach(const hashlist_t *hl, hashlist_foreach_cb func, void *udata)
{
  node_t *node;
  
  HASHLIST_CHECK(hl);
  RUNTIME_ASSERT(func != NULL);

  for (node = hl->first; node != NULL; node = node->next) {
    hash_item_t *item;

    item = (hash_item_t *) node;
    if (func(node->ptr, item->value, udata))
      return;
  }
}

static inline hash_item_t *
hashlist_insert(hashlist_t *hl, const void *key, void *value)
{
  hash_item_t *item;
  uint32_t bin;
  
  item = hashlist_find(hl, key, &bin);
  RUNTIME_ASSERT(NULL == item);

  if (NULL != (item = hash_item_get(hl, key, value))) {
    RUNTIME_ASSERT(item != NULL);
    if (NULL == hl->bins[bin]) {
      RUNTIME_ASSERT(hl->bin_fill < hl->num_bins);
      hl->bin_fill++;
    }
    item->bnext = hl->bins[bin];
    hl->bins[bin] = item;
    hl->fill++;
    hl->stamp++;
  }
  
  return item;
}

/**
 * Appends a new item to the hashlist. The item must not already be in the
 * hashlist.
 *
 * @return false if the item could not be added, true on success.
 */
bool
hashlist_append(hashlist_t *hl, const void *key, void *value)
{
  hash_item_t *item;
  
  HASHLIST_CHECK(hl);

  if (NULL == (item = hashlist_insert(hl, key, value)))
    return false;
  
  RUNTIME_ASSERT(item != NULL);
  item->node.prev = hl->last;
  if (!hl->first) {
    RUNTIME_ASSERT(!hl->last);
    hl->first = &item->node;
  } else {
    RUNTIME_ASSERT(NULL != hl->last);
    hl->last->next = &item->node;
  }
  hl->last = &item->node;

  return true;
}

/**
 * Prepends a new item to the hashlist. The item must not already be in the
 * hashlist.
 *
 * @return false if the item could not be added, true on success.
 */
bool
hashlist_prepend(hashlist_t *hl, const void *key, void *value)
{
  hash_item_t *item;
  
  HASHLIST_CHECK(hl);

  if (NULL == (item = hashlist_insert(hl, key, value)))
    return false;
  
  RUNTIME_ASSERT(item != NULL);
  item->node.next = hl->first;
  if (!hl->first) {
    RUNTIME_ASSERT(!hl->last);
    hl->last = &item->node;
  } else {
    RUNTIME_ASSERT(NULL != hl->last);
    hl->first->prev = &item->node;
  }
  hl->first = &item->node;

  return true;
}

void
hashlist_remove(hashlist_t *hl, const void *key)
{
  hash_item_t *item, *i;
  uint32_t bin;

  if (NULL == (item = hashlist_find(hl, key, &bin)))
    return;

  RUNTIME_ASSERT(bin < hl->num_bins);
  i = hl->bins[bin];
  RUNTIME_ASSERT(i != NULL);
  if (i == item) {
    if (!i->bnext) {
      RUNTIME_ASSERT(hl->bin_fill > 0);
      hl->bin_fill--;
    }
    hl->bins[bin] = i->bnext;
  } else {
    RUNTIME_ASSERT(i->bnext != NULL);
    while (item != i->bnext) { 
      RUNTIME_ASSERT(i->bnext != NULL);
      i = i->bnext;
    }
    RUNTIME_ASSERT(i->bnext == item);
    i->bnext = item->bnext;
  }

  if (item->node.prev)
    item->node.prev->next = item->node.next;
  if (item->node.next)
    item->node.next->prev = item->node.prev;
  if (hl->first == &item->node)
    hl->first = item->node.next;
  if (hl->last == &item->node)
    hl->last = item->node.prev;

  hash_item_free(hl, item);
  hl->fill--;
  hl->stamp++;
}

bool
hashlist_get(hashlist_t *hl, const void *key, void **value)
{
  hash_item_t *item;

  HASHLIST_CHECK(hl);
  item = hashlist_find(hl, key, NULL);
  if (!item)
    return false;
  if (value)
    *value = item->value;
  return true;
}

void
hashlist_destruct(hashlist_t *hl)
{
  size_t i;

  HASHLIST_CHECK(hl);
  for (i = 0; i < hl->num_bins; i++) {
    hash_item_t *item = hl->bins[i];

    while (item) {
      hash_item_t *bnext;

      bnext = item->bnext;
      hash_item_free(hl, item);
      item = bnext;
    }
  }

  DO_FREE(hl->bins);
  DO_FREE(hl);
}

static inline bool
hashlist_iter_init(hashlist_iter_t *iter, hashlist_t *hl, bool first)
{
  RUNTIME_ASSERT(hl != NULL);
  RUNTIME_ASSERT(iter != NULL);
  
  HASHLIST_CHECK(hl);

  iter->hl = hl;
  iter->stamp = hl->stamp;
  iter->item = first ? hl->first : hl->last;
  iter->removed.ptr = NULL;
  iter->removed.prev = NULL;
  iter->removed.next = NULL;
  HASHLIST_ITER_CHECK(iter);
  return NULL != iter->item;
}

/**
 * Sets the hashlist_iter to the first item of the hashlist. If the hashlist is
 * empty, the function returns false and the hashlist_iter must not be
 * used for operations like get_ptr or delete.
 *
 * @param iter a hashlist_iter struct.
 * @param hl a valid hashlist
 */
bool
hashlist_iter_first(hashlist_iter_t *iter, hashlist_t *hl)
{
  RUNTIME_ASSERT(iter != NULL);
  HASHLIST_CHECK(hl);

  return hashlist_iter_init(iter, hl, true);
}

/**
 * Sets the hashlist_iter to the last item of the hashlist. If the hashlist is
 * empty, the function returns false and the hashlist_iter must not be
 * used for operations like get_ptr or delete.
 */
bool
hashlist_iter_last(hashlist_iter_t *iter, hashlist_t *hl)
{
  RUNTIME_ASSERT(iter != NULL);
  HASHLIST_CHECK(hl);

  return hashlist_iter_init(iter, hl, false);
}

/**
 * Moves the hashlist_iter to the next node unless the hashlist is empty or
 * hashlist_iter already points to the last node.
 *
 * @param iter an initialized hashlist_iter.
 * @return true if the hashlist_iter moved to the next node. false on failure.
 */
bool
hashlist_iter_next(hashlist_iter_t *iter)
{
  HASHLIST_ITER_CHECK(iter);
  
  if (iter->item && iter->item->next) {
    iter->item = iter->item->next;
    return true;
  }
  
  return false;
}

/**
 * Moves the hashlist_iter to the previous node unless the list is empty or
 * hashlist_iter already points to the first node.
 *
 * @param iter an initialized hashlist_iter.
 * @return true if the hashlist_iter moved to the previous node, false on
 *         failure.
 */
bool
hashlist_iter_prev(hashlist_iter_t *iter)
{
  HASHLIST_ITER_CHECK(iter);

  if (iter->item && iter->item->prev) {
    iter->item = iter->item->prev;
    return true;
  }

  return false;
}

/**
 * Retrieves the payload pointer of the current item. This must not be
 * used for empty lists unless hashlist_iter points to the previously deleted
 * only node.
 *
 * @param iter a valid hashlist_iter.
 * @return the key of the item at the current position.
 */
const void *
hashlist_iter_get_key(hashlist_iter_t *iter)
{
  HASHLIST_ITER_CHECK(iter);
  RUNTIME_ASSERT(iter->item != NULL);

  return iter->item->ptr;
}

/**
 * Retrieves the payload pointer of the current item. This must not be
 * used for empty lists.
 *
 * @param iter a valid hashlist_iter.
 * @return the value of the item at the current position.
 */
void *
hashlist_iter_get_value(hashlist_iter_t *iter)
{
  HASHLIST_ITER_CHECK(iter);
  RUNTIME_ASSERT(iter->item != NULL);
  RUNTIME_ASSERT(&iter->removed != iter->item);

  return ((hash_item_t *) iter->item)->value;
}

/**
 * Deletes the item at the current position from the hashlist. The iterator
 * copies the values of the node, so that it's still valid for read-only
 * operations. This must not be used for empty lists.
 *
 * @param iter a valid list_iter.
 */
void
hashlist_iter_delete(hashlist_iter_t *iter)
{
  HASHLIST_ITER_CHECK(iter);
  HASHLIST_CHECK(iter->hl);
  RUNTIME_ASSERT(iter->item != NULL);
 
  /* Items must not be deleted more than once! */
  RUNTIME_ASSERT(&iter->removed != iter->item);

  /* Copy the old values, so that we can still iterate to the next
   * or previous item */
  iter->removed = *iter->item;
  
  iter->item = &iter->removed;
  hashlist_remove(iter->hl, iter->item->ptr);
  iter->stamp++;

  HASHLIST_CHECK(iter->hl);
  HASHLIST_ITER_CHECK(iter);
}

/* vi: set ai et sts=2 sw=2 cindent: */
