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

#include "lib/snode.h"

#include "slist.h"

#define SLIST_CHECK(l)                                             \
do {                                                              \
  const slist_t *slist_ = (l);                                      \
  assert(slist_ != NULL);                                          \
  assert((slist_->length == 0) ^ (slist_->first != NULL));          \
} while (0)

struct slist {
  snode_t *first;
  size_t  length;
  int     stamp;
};

slist_t *
slist_new(void)
{
  slist_t *l;

  l = calloc(1, sizeof *l);
  if (l) {
    l->first = NULL;
    l->length = 0;
    l->stamp = 1;
    SLIST_CHECK(l);
  }

  return l;
}

void
slist_free(slist_t *l)
{
  snode_t *n, *next;

  SLIST_CHECK(l);

  for (n = l->first; n != NULL; n = next) {
    next = n->next;
    snode_free(n);
  }
  
  memset(l, 0, sizeof *l);
  free(l);
}

slist_t *
slist_copy(slist_t *to_copy)
{
  snode_t *n, **prev;
  slist_t *l;

  SLIST_CHECK(to_copy);
  l = slist_new();
  if (!l)
    return NULL;
  
  prev = &l->first; 
  for (n = to_copy->first; n != NULL; n = n->next) {
    snode_t *sn;

    if (NULL == (sn = snode_new(n->ptr))) {
      slist_free(l);
      return NULL;
    }
    *prev = sn;
    prev = &sn->next;
  }
  l->length = to_copy->length;

  SLIST_CHECK(l);
  return l;
}

size_t
slist_get_length(const slist_t *l)
{
  SLIST_CHECK(l);
  return l->length;
}

bool
slist_prepend(slist_t *l, void *ptr)
{
  snode_t *n;
 
  SLIST_CHECK(l);
  
  n = snode_new(ptr);
  if (!n)
    return false;
  
  n->next = l->first;
  l->first = n;
  l->length++;

  SLIST_CHECK(l);
  return true;
}

/* Checks whether the iter is properly initialized */
#define SLIST_ITER_CHECK(i)                  \
do {                                        \
  const slist_iter_t *iter_ = (i);           \
                                            \
  assert(iter_ != NULL);                    \
  assert(iter_->l != NULL);                 \
  assert(iter_->stamp == iter_->l->stamp);  \
} while (0)

/* Checks whether the iter and the slist are in sync */
#define SLIST_ITER_CHECK2(i, l)         \
do {                                    \
  const slist_iter_t *iter_ = (i);      \
  const slist_t *slist_ = (l);          \
                                        \
  SLIST_ITER_CHECK(iter_);              \
  assert(slist_ != NULL);               \
  assert(iter_->l == slist_);           \
} while (0)

static inline bool
slist_iter_init(slist_iter_t *iter, slist_t *slist)
{
  assert(slist != NULL);
  assert(iter != NULL);
  
  SLIST_CHECK(slist);

  iter->l = slist;
  iter->stamp = slist->stamp;
  iter->node = slist->first;
  iter->prev = NULL;
  iter->removed.ptr = NULL;
  iter->removed.next = NULL;
  SLIST_ITER_CHECK(iter);
  return NULL != iter->node;
}

/**
 * Sets the slist_iter to the first item of the slist. If the slist is
 * empty, the function returns false and the slist_iter must not be
 * used for operations like get_ptr or delete.
 *
 * @param iter a slist_iter struct.
 * @param slist a valid slist
 */
bool
slist_iter_first(slist_iter_t *iter, slist_t *slist)
{
  assert(iter != NULL);
  SLIST_CHECK(slist);

  return slist_iter_init(iter, slist);
}

bool
slist_iter_has_next(slist_iter_t *iter)
{
  SLIST_ITER_CHECK(iter);

  return iter->node && iter->node->next;
}

bool
slist_iter_has_prev(slist_iter_t *iter)
{
  SLIST_ITER_CHECK(iter);

  return iter->node && iter->l->first != iter->node;
}

/**
 * Moves the slist_iter to the next node unless the slist is empty or
 * slist_iter already points to the last node.
 *
 * @param iter an initialized slist_iter.
 * @return true if the slist_iter moved to the next node, false on failure.
 */
bool
slist_iter_next(slist_iter_t *iter)
{
  SLIST_ITER_CHECK(iter);
  
  if (iter->node && iter->node->next) {
    iter->prev = iter->node;
    iter->node = iter->node->next;
    return true;
  }
  
  return false;
}

/**
 * Retrieves the payload pointer of the current node. This must not be
 * used for empty slists unless slist_iter points to the previously deleted
 * only node.
 *
 * @param iter a valid slist_iter.
 * @return the payload pointer of the node at the current position.
 */
void *
slist_iter_get_ptr(slist_iter_t *iter)
{
  SLIST_ITER_CHECK(iter);
  assert(iter->node != NULL);

  return iter->node->ptr;
}

/**
 * Deletes the item at the current position from the slist. The iterator
 * copies the values of the node, so that it's still valid for read-only
 * operations. This must not be used for empty slists.
 *
 * @param iter a valid slist_iter.
 */
void
slist_iter_delete(slist_iter_t *iter)
{
  snode_t *next;

  SLIST_ITER_CHECK(iter);
  SLIST_CHECK(iter->l);
  assert(iter->node != NULL);
 
  /* Items must not be deleted more than once! */
  assert(&iter->removed != iter->node);

  /* Copy the old values, so that we can still iterate to the next item */
  iter->removed = *iter->node;
  
  next = iter->node->next;
  if (iter->l->first == iter->node)
    iter->l->first = next;
  if (iter->prev)
    iter->prev->next = next;
    
  snode_free(iter->node);

  iter->node = &iter->removed;
  iter->stamp++;
  iter->l->stamp++;
  iter->l->length--;

  SLIST_CHECK(iter->l);
  SLIST_ITER_CHECK(iter);
}

/**
 * Inserts a new node to the slist after the current position. The nodes payload
 * pointer will be set to ``ptr''.
 *
 * @param iter a valid slist_iter.
 * @param ptr the payload pointer for the new node.
 * @return false if the item could not be prepended. Returns true on success.
 */
bool
slist_iter_append(slist_iter_t *iter, void *ptr)
{
  snode_t *n;
  
  SLIST_ITER_CHECK(iter);
  /* Items must not be appended to removed items! */
  assert(&iter->removed != iter->node);

  n = snode_new(ptr);
  if (!n)
    return false;
 
  if (!iter->l->first) {
    iter->l->first = n;
  } else {
    assert(NULL != iter->node);
    n->next = iter->node->next;
    iter->node->next = n;
  }

  iter->stamp++;
  iter->l->stamp++;
  iter->l->length++;

  SLIST_CHECK(iter->l);
  SLIST_ITER_CHECK(iter);

  return true;
}

/**
 * Inserts a new node to the slist before the current position. The nodes
 * payload pointer will be set to ``ptr''.
 *
 * @param iter a valid slist_iter.
 * @param ptr the payload pointer for the new node.
 * @return false if the item could not be prepended. Returns true on success.
 */
bool
slist_iter_prepend(slist_iter_t *iter, void *ptr)
{
  snode_t *n;
  
  SLIST_ITER_CHECK(iter);
  /* Items must not be prepended to removed items! */
  assert(&iter->removed != iter->node);

  n = snode_new(ptr);
  if (!n)
    return false;
 
  n->next = iter->node;
  
  if (iter->l->first == iter->node)
    iter->l->first = n;
  if (iter->prev)
    iter->prev->next = n;

  iter->stamp++;
  iter->l->stamp++;
  iter->l->length++;

  SLIST_CHECK(iter->l);
  SLIST_ITER_CHECK(iter);

  return true;
}

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
