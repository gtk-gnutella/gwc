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

#ifndef GWC_HEADER_FILE
#define GWC_HEADER_FILE

#include "common.h"
#include "hashtable.h"
#include "nettools.h"

#define GWC_CLIENT_VERSION "1.0.0"
#define GWC_USER_AGENT "GhostWhiteCrab/" GWC_CLIENT_VERSION

/* Set to 1 if you want to allow peers on privileged ports (1-1023) */
#define GWC_ALLOW_PEERS_ON_PRIV_PORTS 0

/* Absolute maximum limits for returned peers resp. URLs (MUST BE PRIMES!)
 * Note that you have to respect the buffer sizes of the FIFOs. There shall
 * be no buffer overflows in any case but those represent the hard limit
 * for results. Carefully adjust them as necessary.
 */
#define MAX_GWCS_PER_REQ 59
#define MAX_PEERS_PER_REQ 173


#define MAX_BAD_CACHED_GWCS 2048
#define MAX_GOOD_CACHED_GWCS 256

/* seconds in a year (well not exactly...) */
#define ONE_YEAR (3600U * (24 * 365 + 6))

/* How many seconds a GWC or peer persists in the cache until it's removed */
#define MAX_GOOD_GWC_AGE (3600U * 5)
#define MAX_BAD_GWC_AGE (3600U * 24)
#define MAX_PEER_AGE (60U * 20)

/* Number of allowed '&'-separated request in a URL; rest will be skipped */
#define GWC_MAX_COMBINED_REQUESTS 16

/* Maximum lengths for GWC URLs which is accepted */
#define MAX_ALLOWED_GWC_URL_LENGTH 128

/***
 ***  Type definitions
 ***/

typedef enum {
  GWC_REQ_NONE      = 0,
  GWC_REQ_IP        = (1 << 0),
  GWC_REQ_URL       = (1 << 1),
  GWC_REQ_HOSTFILE  = (1 << 2),
  GWC_REQ_URLFILE   = (1 << 3),
  GWC_REQ_STATFILE  = (1 << 4),
  GWC_REQ_PING      = (1 << 5),
  GWC_REQ_GET       = (1 << 6),
  GWC_REQ_UPDATE    = (1 << 7),
  GWC_REQ_NET       = (1 << 8),
  GWC_REQ_DATA      = (1 << 9),
  GWC_REQ_CLIENT    = (1 << 10),
  GWC_REQ_VERSION   = (1 << 11),
  GWC_REQ_PROTO_VER = (1 << 12),
  GWC_REQ_GWCS      = (1 << 13),
  GWC_REQ_IPV6      = (1 << 14)

#define NUM_GWC_REQS 15
} gwc_req_t;

typedef enum {
  IP_PREF_NONE = 0,
  IP_PREF_IPV4 = (1 << 0),
  IP_PREF_IPV6 = (1 << 1)
} ip_pref_t;

typedef struct gwc_url {
  time_t    stamp;      /* time the URL was added resp. last verified */
  int       num_checks; /* how often was it checked */
  char      *url;       /* the URL of the GWC */
  size_t    len;        /* the string length of the URL *EXCLUDING* the NUL */
} gwc_url_t;

typedef struct gwc_cache gwc_cache_t;

/***
 *** Prototypes
 ***/

gwc_cache_t * gwc_new(size_t size);
char *gwc_url_normalize(char *url, int *res);
const char *gwc_url_normalize_result(int res);
gwc_url_t *gwc_url_lookup(gwc_cache_t *, const char *);
void gwc_add_entry(gwc_cache_t *cache, const char *url, time_t stamp,
    int num_checks);
void gwc_add_url(gwc_cache_t *, const char *);
bool gwc_move_url(gwc_cache_t *from, gwc_cache_t *to, const char *url);
void gwc_check_url_entry(const gwc_url_t *g);
void gwc_url_remove(gwc_cache_t *cache, const char *url, bool free_entry);
void gwc_foreach(const gwc_cache_t *cache, hashtable_foreach_cb func,
    void *udata);

/* vi: set ai et sts=2 sw=2 cindent: */
#endif /* GWC_HEADER_FILE */
