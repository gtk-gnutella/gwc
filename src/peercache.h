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

#ifndef PEER_CACHE_HEADER_FILE
#define PEER_CACHE_HEADER_FILE

#include "lib/common.h"
#include "lib/filter.h"

typedef struct peer {
  time_t      stamp;    /* time the peer was added */
  net_addr_t  addr;     /* IPv4 address of the peer */
  uint16_t    port;     /* TCP port on which the peer expects connections */
} peer_t;

typedef struct peer_cache peer_cache_t;

int peer_cache_save(const peer_cache_t *cache, const char *pathname);
peer_cache_t * peer_cache_new(size_t size, long max_age);
void peer_cache_set_filter(peer_cache_t *pc, struct addr_filter *filter);
void peer_cache_set_removed_callback(peer_cache_t *pc, 
    void (*cb)(const net_addr_t *addr, in_port_t port));
int peer_cache_load(peer_cache_t *cache, const char *pathname,
    size_t max_items);
void peer_cache_add(peer_cache_t *cache, time_t now,
    const net_addr_t addr, in_port_t port);
unsigned peer_cache_get(peer_cache_t *cache, const peer_t **peerv, unsigned n,
    time_t now, const net_addr_t addr);
bool peer_cache_lookup(const peer_cache_t *pc, const net_addr_t addr);

#endif /* PEER_CACHE_HEADER_FILE */
/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
