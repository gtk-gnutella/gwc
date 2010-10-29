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

#include "mem.h"
#include "list.h"
#include "node.h"

#define LIST_CHECK(l)                                             \
do {                                                              \
  const list_t *list_ = (l);                                      \
  RUNTIME_ASSERT(list_ != NULL);                                          \
  RUNTIME_ASSERT((list_->length == 0) ^ (list_->first != NULL));          \
  RUNTIME_ASSERT((list_->length == 0) ^ (list_->last != NULL));           \
  RUNTIME_ASSERT((list_->length < 2) ^ (list_->last != list_->first));    \
  RUNTIME_ASSERT((list_->first != list_->last) ^                          \
      (list_->last == list_->first &&                             \
       ((list_->first == NULL) ^ (list_->length == 1))));         \
} while (0)

#undef LIST_CHECK
#define LIST_CHECK(list) ((void) (list))

struct list {
  node_t  *first;
  node_t  *last;
  size_t  length;
  int     stamp;
};

list_t *
list_new(void)
{
  list_t *list;

  list = mem_chunk_alloc(sizeof *list);
  if (list) {
    static const struct list zero_list;

    *list = zero_list;
    list->stamp = 1;
    LIST_CHECK(list);
  }
  return list;
}

void
list_free(list_t *list)
{
  if (list) {
    node_t *n, *next;

    LIST_CHECK(list);

    for (n = list->first; n != NULL; n = next) {
      next = n->next;
      node_free(n);
    }

    mem_chunk_free(list, sizeof *list);
  }
}

list_t *
list_copy(list_t *to_copy)
{
  node_t *n;
  list_t *l;

  LIST_CHECK(to_copy);
  l = list_new();
  if (!l)
    return NULL;
  
  for (n = to_copy->first; n != NULL; n = n->next) {
    if (!list_append(l, n->ptr)) {
      list_free(l);
      return NULL;
    }
  }
  
  LIST_CHECK(l);
  return l;
}

void *
list_get_last(const list_t *l)
{
  LIST_CHECK(l);
  return l->last ? l->last->ptr : NULL;
}

size_t
list_get_length(const list_t *l)
{
  LIST_CHECK(l);
  return l->length;
}

bool
list_empty(const list_t *list)
{
  LIST_CHECK(list);
  return 0 == list->length;
}

bool
list_append(list_t *l, void *ptr)
{
  node_t *n;

  LIST_CHECK(l);
  
  n = node_new(ptr);
  if (!n)
    return false;
  
  n->prev = l->last;
  n->next = NULL;
  if (!l->first) {
    l->first = n;
  }
  if (l->last) {
    l->last->next = n;
  }
  l->last = n;
  l->length++;
  
  LIST_CHECK(l);
  return true;
}

bool
list_prepend(list_t *l, void *ptr)
{
  node_t *n;
 
  LIST_CHECK(l);
  
  n = node_new(ptr);
  if (!n)
    return false;
  
  n->prev = NULL;
  n->next = l->first;
  if (l->first) {
    l->first->prev = n;
  }
  if (!l->last) {
    l->last = n;
  }
  l->first = n;
  l->length++;

  LIST_CHECK(l);
  return true;
}

/* Checks whether the iter is properly initialized */
#define LIST_ITER_CHECK(i)                  \
do {                                        \
  const list_iter_t *iter_ = (i);           \
                                            \
  RUNTIME_ASSERT(iter_ != NULL);                    \
  RUNTIME_ASSERT(iter_->l != NULL);                 \
  RUNTIME_ASSERT(iter_->stamp == iter_->l->stamp);  \
} while (0)

/* Checks whether the iter and the list are in sync */
#define LIST_ITER_CHECK2(i, l)          \
do {                                    \
  const list_iter_t *iter_ = (i);       \
  const list_t *list_ = (l);            \
                                        \
  LIST_ITER_CHECK(iter_);               \
  RUNTIME_ASSERT(list_ != NULL);                \
  RUNTIME_ASSERT(iter_->l == list_);            \
} while (0)

#undef LIST_ITER_CHECK
#define LIST_ITER_CHECK(i) ((void) i)

#undef LIST_ITER_CHECK2
#define LIST_ITER_CHECK2(i, l) ((void) i, (void) l)

static inline bool
list_iter_init(list_iter_t *iter, list_t *list, bool first)
{
  RUNTIME_ASSERT(list != NULL);
  RUNTIME_ASSERT(iter != NULL);
  
  LIST_CHECK(list);

  iter->l = list;
  iter->stamp = list->stamp;
  iter->node = first ? list->first : list->last;
  iter->removed.ptr = NULL;
  iter->removed.next = NULL;
  iter->removed.prev = NULL;
  LIST_ITER_CHECK(iter);
  return NULL != iter->node;
}

/**
 * Sets the list_iter to the first item of the list. If the list is
 * empty, the function returns false and the list_iter must not be
 * used for operations like get_ptr or delete.
 *
 * @param iter a list_iter struct.
 * @param list a valid list
 */
bool
list_iter_first(list_iter_t *iter, list_t *list)
{
  RUNTIME_ASSERT(iter != NULL);

  if (list) {
    LIST_CHECK(list);

    return list_iter_init(iter, list, true);
  } else {
    return false;
  }
}

/**
 * Sets the list_iter to the last item of the list. If the list is
 * empty, the function returns false and the list_iter must not be
 * used for operations like get_ptr or delete.
 */
bool
list_iter_last(list_iter_t *iter, list_t *list)
{
  RUNTIME_ASSERT(iter != NULL);
  LIST_CHECK(list);

  return list_iter_init(iter, list, false);
}

bool
list_iter_has_next(list_iter_t *iter)
{
  LIST_ITER_CHECK(iter);

  return iter->node && iter->node->next;
}

bool
list_iter_has_prev(list_iter_t *iter)
{
  LIST_ITER_CHECK(iter);

  return iter->node && iter->node->prev;
}

/**
 * Moves the list_iter to the next node unless the list is empty or
 * list_iter already points to the last node.
 *
 * @param iter an initialized list_iter.
 * @return true if the list_iter moved to the next node. false on failure.
 */
bool
list_iter_next(list_iter_t *iter)
{
  LIST_ITER_CHECK(iter);
  
  if (iter->node && iter->node->next) {
    iter->node = iter->node->next;
    return true;
  }
  
  return false;
}

/**
 * Moves the list_iter to the previous node unless the list is empty or
 * list_iter already points to the first node.
 *
 * @param iter an initialized list_iter.
 * @return true if the list_iter moved to the previous node. false on failure.
 */
bool
list_iter_prev(list_iter_t *iter)
{
  LIST_ITER_CHECK(iter);

  if (iter->node && iter->node->prev) {
    iter->node = iter->node->prev;
    return true;
  }

  return false;
}

/**
 * Retrieves the payload pointer of the current node. This must not be
 * used for empty lists unless list_iter points to the previously deleted
 * only node.
 *
 * @param iter a valid list_iter.
 * @return the payload pointer of the node at the current position.
 */
void *
list_iter_get_ptr(list_iter_t *iter)
{
  LIST_ITER_CHECK(iter);
  RUNTIME_ASSERT(iter->node != NULL);

  return iter->node->ptr;
}

/**
 * Deletes the item at the current position from the list. The iterator
 * copies the values of the node, so that it's still valid for read-only
 * operations. This must not be used for empty lists.
 *
 * @param iter a valid list_iter.
 */
void
list_iter_delete(list_iter_t *iter)
{
  node_t *next;

  LIST_ITER_CHECK(iter);
  LIST_CHECK(iter->l);
  RUNTIME_ASSERT(iter->node != NULL);
 
  /* Items must not be deleted more than once! */
  RUNTIME_ASSERT(&iter->removed != iter->node);

  /* Copy the old values, so that we can still iterate to the next
   * or previous item */
  iter->removed = *iter->node;
  
  next = iter->node->next;
  if (iter->l->last == iter->node)
    iter->l->last = iter->node->prev;
  if (iter->l->first == iter->node)
    iter->l->first = next;
    
  if (next)
    next->prev = iter->node->prev;
  if (iter->node->prev)
    iter->node->prev->next = next;

  node_free(iter->node);

  iter->node = &iter->removed;
  iter->stamp++;
  iter->l->stamp++;
  iter->l->length--;

  LIST_CHECK(iter->l);
  LIST_ITER_CHECK(iter);
}

/**
 * Inserts a new node to the list after the current position. The nodes payload
 * pointer will be set to ``ptr''.
 *
 * @param iter a valid list_iter.
 * @param ptr the payload pointer for the new node.
 * @return false if the item could not be prepended. Returns true on success.
 */
bool
list_iter_append(list_iter_t *iter, void *ptr)
{
  node_t *n;
  
  LIST_ITER_CHECK(iter);
  /* Items must not be appended to removed items! */
  RUNTIME_ASSERT(&iter->removed != iter->node);

  n = node_new(ptr);
  if (!n)
    return false;
 
  n->prev = iter->node;
  n->next = iter->node ? iter->node->next : NULL;
  
  if (iter->l->last == iter->node)
    iter->l->last = n;
  if (!iter->l->first)
    iter->l->first = n;

  if (iter->node)
    iter->node->next = n;

  iter->stamp++;
  iter->l->stamp++;
  iter->l->length++;

  LIST_CHECK(iter->l);
  LIST_ITER_CHECK(iter);

  return true;
}

/**
 * Inserts a new node to the list before the current position. The nodes
 * payload pointer will be set to ``ptr''.
 *
 * @param iter a valid list_iter.
 * @param ptr the payload pointer for the new node.
 * @return false if the item could not be prepended. Returns true on success.
 */
bool
list_iter_prepend(list_iter_t *iter, void *ptr)
{
  node_t *n;
  
  LIST_ITER_CHECK(iter);
  /* Items must not be prepended to removed items! */
  RUNTIME_ASSERT(&iter->removed != iter->node);

  n = node_new(ptr);
  if (!n)
    return false;
 
  n->prev = iter->node ? iter->node->prev : NULL;
  n->next = iter->node;
  
  if (!iter->l->last)
    iter->l->last = n;
  if (iter->l->first == iter->node)
    iter->l->first = n;

  if (iter->node)
    iter->node->prev = n;

  iter->stamp++;
  iter->l->stamp++;
  iter->l->length++;

  LIST_CHECK(iter->l);
  LIST_ITER_CHECK(iter);

  return true;
}

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
