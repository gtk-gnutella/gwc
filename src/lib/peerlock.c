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

#include "peerlock.h"
#include "hashlist.h"
#include "mem.h"
#include "nettools.h"

struct peer_lock {
  union {
    in_addr_t   ipv4;
    net_addr_t *ipv6_ptr;
  } addr;
  time_t        stamp;
  uint8_t       count;
  bool          is_ipv4;
};

struct peer_lock_set {
  size_t            size;
  int               delay;
  uint8_t           limit;
  time_t            last_gc;
  time_t            last_add;
  hashlist_t        *hl;    /* fast lookup of locks by IP address */
};

static inline net_addr_t
peer_lock_get_addr(const struct peer_lock *pl)
{
  if (pl->is_ipv4) {
    return net_addr_set_ipv4(pl->addr.ipv4);
  } else {
    return *pl->addr.ipv6_ptr;
  }
}

static inline struct peer_lock *
peer_lock_alloc(const net_addr_t addr)
{
  struct peer_lock *pl;

  pl = mem_chunk_alloc(sizeof *pl);
  if (pl) {
    if (AF_INET == net_addr_family(addr)) {
      pl->is_ipv4 = true;
      pl->addr.ipv4 = net_addr_ipv4(addr);
    } else {
      pl->is_ipv4 = false;
      pl->addr.ipv6_ptr = mem_chunk_copy(&addr, sizeof addr);
      RUNTIME_ASSERT(pl->addr.ipv6_ptr);
    }
  }

  return pl;
}

static inline void
peer_lock_free(struct peer_lock *pl)
{
  if (!pl->is_ipv4) {
    mem_chunk_free(pl->addr.ipv6_ptr, sizeof *pl->addr.ipv6_ptr);
  }
  mem_chunk_free(pl, sizeof *pl);
}

static uint32_t
peer_lock_hash_func(const void *key)
{
  return net_addr_hash(peer_lock_get_addr(key));
}

static bool 
peer_lock_cmp_func(const void *p, const void *q)
{
  return net_addr_equal(peer_lock_get_addr(p), peer_lock_get_addr(q));
}

#define peer_lock_set_check(pls)        \
do {                                    \
  const peer_lock_set_t *pls_ = (pls);  \
  RUNTIME_ASSERT(pls_ != NULL);                 \
  RUNTIME_ASSERT(pls_->hl != NULL);             \
} while (0)

peer_lock_set_t *
peer_lock_set_new(size_t size, int delay, uint8_t limit)
{
  peer_lock_set_t *ls;

  RUNTIME_ASSERT(size > 0);
  RUNTIME_ASSERT(delay >= 0);
  RUNTIME_ASSERT(limit > 0);

  ls = calloc(1, sizeof *ls);
  if (ls) {
    ls->size = size;
    ls->delay = delay;
    ls->limit = limit;
    ls->hl = hashlist_new(size, peer_lock_hash_func, peer_lock_cmp_func);
    ls->last_gc = 0;
    ls->last_add = 0;

    peer_lock_set_check(ls);
  }
  return ls;
}

/**
 * Removes all locks that have exceeded. 
 */
static void
peer_lock_set_garbage_collect(peer_lock_set_t *ls, time_t now)
{
  hashlist_iter_t i;
  bool v;

  peer_lock_set_check(ls);

  /* Don't run more than once a second, time_t isn't more precise anyway */
  if (ls->last_gc != 0 && now == ls->last_gc)
    return;
  ls->last_gc = now;

#if 0
  DBUG("%s: items=%d, bins=%d", __func__,
    (int) hashlist_fill(ls->hl),
    (int) hashlist_bin_fill(ls->hl));
#endif
 
  for (v = hashlist_iter_first(&i, ls->hl); v; v = hashlist_iter_next(&i)) {
    struct peer_lock *pl;
    void *value;

    pl = hashlist_iter_get_value(&i);
    RUNTIME_ASSERT(pl != NULL);
    if (difftime(now, pl->stamp) <= ls->delay) {
      break;
    }

    if (!hashlist_get(ls->hl, pl, &value)) {
      /* If it's in the list, it must be in the hashtable */
      RUNTIME_ASSERT(0);
    }
    RUNTIME_ASSERT(value == pl);

    /* list_iter_next() afterwards is alright since the iterator
     * preserves the node values */
    hashlist_iter_delete(&i);

    RUNTIME_ASSERT(!hashlist_get(ls->hl, pl, NULL));
    peer_lock_free(pl);
  }
}

void
peer_lock_set_add(peer_lock_set_t *ls, const net_addr_t addr, time_t now)
{
  struct peer_lock *pl;
  void *value;

  if (difftime(now, ls->last_add) > 0) {
    ls->last_add = now;
  }

  peer_lock_set_check(ls);
  if (ls->delay < 1)
    return;

  peer_lock_set_garbage_collect(ls, now);

  pl = peer_lock_alloc(addr);
  if (!pl)
    return;
  
  if (hashlist_get(ls->hl, pl, &value)) {
    RUNTIME_ASSERT(value);
    RUNTIME_ASSERT(net_addr_equal(peer_lock_get_addr(pl), addr));

    peer_lock_free(pl);
    pl = value;

    if (difftime(now, pl->stamp) > ls->delay) {
      /* peer_lock_set_garbage_collect() should have reaped this! */
      RUNTIME_ASSERT(0);
    }

    /* Only increase up to the limit, otherwise an integer overflow
     * would magically reset the lock counter */
    if (pl->count < ls->limit) {
      pl->count++;
    }
    return;
  }

  pl->stamp = now;
  pl->count = 1;
  
  if (!hashlist_append(ls->hl, pl, pl)) {
    peer_lock_free(pl);
    return;
  }

  RUNTIME_ASSERT(hashlist_get(ls->hl, pl, &value));
  RUNTIME_ASSERT(value == pl);
}

/**
 * Checks whether the given address has a lock set.
 *
 * @return  TRUE if there's a valid lock for the given address, FALSE if
 *          there's none.
 */
bool
peer_lock_set_locked(peer_lock_set_t *ls, const net_addr_t addr, time_t now)
{
  struct peer_lock *pl;
  bool is_locked = false;
  bool found;
  void *value;

  peer_lock_set_check(ls);
  if (ls->delay < 1)
    return false;

  peer_lock_set_garbage_collect(ls, now);

  pl = peer_lock_alloc(addr);
  found = hashlist_get(ls->hl, pl, &value);
  peer_lock_free(pl);
    
  if (found) {
    pl = value;
      
    RUNTIME_ASSERT(pl);
    RUNTIME_ASSERT(net_addr_equal(peer_lock_get_addr(pl), addr));

    is_locked = difftime(now, pl->stamp) <= ls->delay &&
                pl->count >= ls->limit;
  }

  return is_locked;
}

/* vi: set ai et sts=2 sw=2 cindent: */
