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

#ifndef NODE_HEADER_FILE
#define NODE_HEADER_FILE

#include "common.h"

typedef struct node {
  void *ptr;
  struct node *prev, *next;
} node_t;

node_t *node_new(void *ptr);
void node_free(node_t *n);

static inline node_t *
node_append(node_t *first, node_t *to_append)
{
  node_t *n;
  
  if (!first)
    return n;
  
  n = first;
  while (n->next)
    n = n->next;

  n->next = to_append;
  to_append->prev = n;
  return first;
}

static inline node_t *
node_prepend(node_t *first, node_t *to_prepend)
{
  node_t *n;
  
  if (!first)
    return to_prepend;
  if (!to_prepend)
    return first;
  
  n = to_prepend;
  while (n->next)
    n = n->next;

  n->next = first;
  first->prev = n;
  return to_prepend;
}

static inline node_t *
node_reverse(node_t *n)
{
  node_t *last, *next;
  
  if (!n || !n->next)
    return n;

  last = NULL;
  while (NULL != (next = n->next)) {
    n->prev = next;
    n->next = last;
    last = n;
    n = next;
  }
  n->next = last;
  n->prev = NULL;
  
  return n;
}

static inline node_t *
node_remove(node_t *n, void *ptr, bool first_only)
{
  node_t *first;
  
  if (!n)
    return NULL;

  if (n->ptr == ptr) {
    first = n->next;
    
    if (first_only)
      return first;
  } else {
    first = n;
  }
  
  for (n = n->next; n != NULL; n = n->next) {
    if (n->ptr == ptr) {
      if (n->next)
        n->next->prev = n->prev;
      if (n->prev)
        n->prev->next = n->next;
      
      if (first_only)
        break;
    }
  }

  return first;
}

static inline node_t *
node_find(node_t *n, void *ptr)
{
  while (n != NULL) {
    if (n->ptr == ptr)
      break;
    n = n->next;
  }

  return n;
}

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
#endif /* NODE_HEADER_FILE */
