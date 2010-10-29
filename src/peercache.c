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

#include "lib/nettools.h"
#include "lib/append.h"
#include "lib/gwc.h"
#include "lib/hashlist.h"
#include "lib/http.h"
#include "lib/dns.h"
#include "lib/list.h"
#include "lib/mem.h"

#include "options.h"
#include "peercache.h"

struct peer_cache {
  struct addr_filter *addr_filter;
  void          (* removed)(const net_addr_t *addr, in_port_t port);
  hashlist_t    *hl;
  time_t        last_gc;
  time_t        last_add;
  long          max_age;
  bool          gc_enabled;
};

static peer_t *
peer_new(const net_addr_t addr, in_port_t port, time_t now)
{
  peer_t *p;

  p = mem_chunk_alloc(sizeof *p);
  if (p) {
    p->addr = addr;
    p->port = port;
    p->stamp = now;
  }

  return p;
}

static void
peer_free(peer_t *p)
{
  RUNTIME_ASSERT(p != NULL);
  mem_chunk_free(p, sizeof *p);
}

peer_cache_t *
peer_cache_new(size_t size, long max_age)
{
  peer_cache_t *pc;

  RUNTIME_ASSERT(size > 0);
  RUNTIME_ASSERT(max_age > 0);

  pc = calloc(1, sizeof *pc);
  if (pc) {
    pc->hl = hashlist_new(size, NULL, NULL);
    pc->addr_filter = NULL;
    pc->removed = NULL;
    pc->last_gc = 0;
    pc->last_add = 0;
    pc->max_age = max_age;
    pc->gc_enabled = true;
  }
  return pc;
}

void
peer_cache_set_filter(peer_cache_t *pc, struct addr_filter *filter)
{
  RUNTIME_ASSERT(pc != NULL);
  pc->addr_filter = filter;
}

void
peer_cache_set_removed_callback(peer_cache_t *pc,
    void (*cb)(const net_addr_t *addr, in_port_t port))
{
  RUNTIME_ASSERT(pc != NULL);
  pc->removed = cb;
}

int
peer_cache_save(const peer_cache_t *pc, const char *pathname)
{
  FILE *f;
  const peer_t *p;
  hashlist_iter_t i;
  bool v;

  RUNTIME_ASSERT(pc != NULL);
  RUNTIME_ASSERT(pathname != NULL);
  
  f = safer_fopen(pathname, SAFER_FOPEN_WR);
  if (!f) {
    WARN("could not open \"%s\": %s", pathname, compat_strerror(errno));
    return -1;
  }
 
  for (v = hashlist_iter_first(&i, pc->hl); v; v = hashlist_iter_next(&i)) {
    char peer_buf[NET_ADDR_PORT_BUFLEN];
    char time_buf[UINT64_DEC_BUFLEN];

    p = hashlist_iter_get_value(&i);
    RUNTIME_ASSERT(p != NULL);

    print_net_addr_port(peer_buf, sizeof peer_buf, p->addr, p->port);
    print_uint64(time_buf, sizeof time_buf, (uint64_t) p->stamp);

    fprintf(f, "%-21s\t%s\n", peer_buf, time_buf);
  }

  fclose(f);
  return 0;
}

static int
lookup_host(const char *hostname, net_addr_t *addr)
{
  char addr_buf[NET_ADDR_BUFLEN];
  dnslookup_ctx_t *ctx;
  int error;

  RUNTIME_ASSERT(hostname);
  RUNTIME_ASSERT(addr);
  *addr = net_addr_unspecified;

  ctx = dnslookup_ctx_new();
  if (!ctx) {
    CRIT("dnslookup_ctx_new() failed");
    return -1;
  }
  if (dnslookup(ctx, hostname, &error)) {
    INFO("Could not resolve \"%s\"", hostname);
    dnslookup_ctx_free(ctx);
    return -1;
  }

  while (dnslookup_next(ctx, addr))
    if (!net_addr_equal(*addr, net_addr_unspecified))
      break;

  print_net_addr(addr_buf, sizeof addr_buf, *addr);
  DBUG("Host \"%s\" resolved to: \"%s\"", hostname, addr_buf);

  dnslookup_ctx_free(ctx);
  return 0;
}

int
peer_cache_load(peer_cache_t *pc, const char *pathname, size_t max_items)
{
  unsigned int line_number;
  FILE *f;
  list_t *list;
  list_iter_t iter;
  bool v;
  char line[4096];
  peer_t *peer = NULL;
 
  RUNTIME_ASSERT(pc != NULL);
  RUNTIME_ASSERT(pathname != NULL);

  list = list_new();
  if (!list) {
    WARN("list_new() failed");
    return -1;
  }

  f = safer_fopen(pathname, SAFER_FOPEN_RD);
  if (!f) {
    WARN("could not open \"%s\": %s", pathname, compat_strerror(errno));
    return -1;
  }
  
  pc->gc_enabled = false;
  
  for (line_number = 1; fgets(line, sizeof line, f); line_number++) {
    char *endptr, *p;

    if (list_get_length(list) >= max_items)
        break;
      
    if (!peer) {
      peer = mem_chunk_alloc(sizeof *peer);
    } else {
      static const struct peer zero_peer;
      *peer = zero_peer;
    }
    
    endptr = strchr(line, '\n');
    if (!endptr) {
      CRIT("Non-terminated or overlong line in configuration file (%u)",
        line_number);
      goto failure;
    }
    *endptr = '\0';

    p = line;
    endptr = skip_spaces(p);
    if ('#' == *endptr || '\0' == *endptr) {
      /* skip comments and empty lines */
      continue;
    }

    if (parse_net_addr(p, &peer->addr, &endptr)) {
      if (':' != *endptr) {
        WARN("Line %u; Missing port after peer address (line ignored)",
           line_number);
        continue;
      }
    } else {
      endptr = http_parse_host(p);
      if (!endptr || ':' != *endptr) {
        WARN("Line %u; Missing port after hostname (line ignored)",
           line_number);
        continue;
      }
      *endptr = '\0';

      if (lookup_host(p, &peer->addr)) {
        continue;
      }
    }

    if (net_addr_is_private(peer->addr)) {
      WARN("Line %u: Private IP addresses are not allowed (discarding line)",
          line_number);
      continue;
    }
    if (pc->addr_filter && addr_filter_match(pc->addr_filter, peer->addr)) {
      WARN("Line %u: IP address matches address filter (discarding line)",
        line_number);
      continue;
    }

    RUNTIME_ASSERT('\0' == *endptr || ':' == *endptr);
    p = ++endptr;

    if (!parse_port_number(p, &peer->port, &endptr)) {
      WARN("Invalid data in line %u; port number", line_number);
      continue;
    }
    if (peer->port < 1024) {
      WARN("Line %u: ports below 1024 are blocked (discarding line)",
        line_number);
      continue;
    }

    /* Parse optional timestamp; addresses without one are considered
     * expired and are only used to gather fresh addresses but are
     * not reported to other peers. */
    p = skip_spaces(endptr);
    if (isdigit((unsigned char) *p)) {
      int error;
      
      peer->stamp = (time_t) parse_uint64(p, &endptr, 10, &error);
      if (!peer->stamp) {
        WARN("Invalid timestamp in line %u (ignoring)", line_number);
        peer->stamp = 1;
      }
    } else {
      peer->stamp = 1;
    }

    RUNTIME_ASSERT(peer->port);
    RUNTIME_ASSERT(peer->stamp);

#if 0 
    {
      char addr_buf[NET_ADDR_PORT_BUFLEN];
      char date_buf[RFC1123_DATE_BUFLEN];

      print_rfc1123_date(date_buf, sizeof date_buf, peer->stamp);
      print_net_addr_port(addr_buf, sizeof addr_buf, peer->addr, peer->port);
      DBUG("Peer: %15s (added: %s)", addr_buf, date_buf);
    }
#endif
    
    /* The cache contents are usually stored ordered to disk. However,
     * if the file was manually edited, the order might not be correct.
     */
    for (v = list_iter_last(&iter, list); v; v = list_iter_prev(&iter)) {
      peer_t *peer_ptr;

      peer_ptr = list_iter_get_ptr(&iter);
      RUNTIME_ASSERT(peer_ptr);
      if (difftime(peer_ptr->stamp, peer_ptr->stamp) <= 0) {
        list_iter_append(&iter, peer);
        peer = NULL;
        break;
      }
    }

    /* If all entries in the list are older than this ``peer'', ``peer'' is 
     * prepended to the list. */
    if (peer) {
      list_prepend(list, peer);
      peer = NULL;
    }
  }

  for (v = list_iter_first(&iter, list); v; v = list_iter_next(&iter)) {
    peer_t item, *peer_ptr;

    list_iter_delete(&iter);
    peer_ptr = list_iter_get_ptr(&iter);
    RUNTIME_ASSERT(peer_ptr);
    item = *peer_ptr;
    mem_chunk_free(peer_ptr, sizeof *peer_ptr);
    peer_cache_add(pc, item.stamp, item.addr, item.port);
  }

  list_free(list);
  list = NULL;

  pc->gc_enabled = true;

  INFO("Loaded %u peers into the pool", (unsigned) hashlist_fill(pc->hl));
  fclose(f);
  return 0;

failure:

  if (list) {
    list_free(list);
    list = NULL;
  }
  if (f) {
    fclose(f);
    f = NULL;
  }
  return -1;
}

/**
 * Looks whether the address is stored in the cache. The age of entry
 * is not taken in account and old entries are not removed.
 *
 * @return true if the address was found, otherwise false. 
 */
bool
peer_cache_lookup(const peer_cache_t *pc, const net_addr_t addr)
{
  void *key;
  
  RUNTIME_ASSERT(pc != NULL); 
  key = UINT2PTR(net_addr_hash(addr));
  return hashlist_get(pc->hl, key, NULL);
}

static void
peer_cache_garbage_collect(peer_cache_t *pc, time_t now)
{
  hashlist_iter_t i;
  bool v;
  
  RUNTIME_ASSERT(pc != NULL);  

  if (!pc->gc_enabled || (0 != pc->last_gc && now == pc->last_gc))
    return;
  pc->last_gc = now;
  
#if 0 
  DBUG("%s: items=%d, bins=%d", __func__,
    (int) hashlist_fill(pc->hl),
    (int) hashlist_bin_fill(pc->hl));
#endif
 
  for (v = hashlist_iter_first(&i, pc->hl); v; v = hashlist_iter_next(&i)) {
    net_addr_t addr;
    in_port_t port;
    peer_t *p;

    p = hashlist_iter_get_value(&i);
    RUNTIME_ASSERT(p != NULL);
    if (difftime(now, p->stamp) <= pc->max_age)
      continue;
    
    addr = p->addr;
    port = p->port;
    peer_free(p);
    hashlist_iter_delete(&i);
      
    if (pc->removed)
      pc->removed(&addr, port);
  }
}

void
peer_cache_add(peer_cache_t *pc, time_t now,
    const net_addr_t addr, in_port_t port)
{
  peer_t *p;
  uint32_t h;
 
  RUNTIME_ASSERT(pc != NULL);
  
  peer_cache_garbage_collect(pc, now);
  
  h = net_addr_hash(addr);
  if (hashlist_get(pc->hl, UINT2PTR(h), NULL))
    return;

  if (NULL != (p = peer_new(addr, port, now)))
    hashlist_append(pc->hl, UINT2PTR(h), p);
}

unsigned
peer_cache_get(peer_cache_t *pc, const peer_t **peerv, unsigned n,
    time_t now, const net_addr_t addr)
{
  hashlist_iter_t i, j;
  bool valid_i, valid_j;
  size_t fill, k;
 
  peer_cache_garbage_collect(pc, now);
  
  RUNTIME_ASSERT(n > 0);

  fill = hashlist_fill(pc->hl) / 2;
  n = MIN(n, fill);
  n = MIN(n, MAX_PEERS_PER_REQ);

  k = 0;
  valid_i = hashlist_iter_first(&i, pc->hl);
  valid_j = hashlist_iter_last(&j, pc->hl);
 
  while (k < n && valid_i && valid_j) {
    peer_t *p;

    if ((unsigned long) random() % 1000 < 500)
      p = hashlist_iter_get_value(&i);
    else 
      p = hashlist_iter_get_value(&j);
    
    RUNTIME_ASSERT(p != NULL);

    if (net_addr_equal_ptr(&p->addr, &addr))
      continue;

    peerv[k++] = p;

    valid_i = valid_i && hashlist_iter_next(&i);
    valid_j = valid_j && hashlist_iter_prev(&j);
  }

  return k;
}

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
