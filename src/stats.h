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

#ifndef STATS_HEADER_FILE
#define STATS_HEADER_FILE

#include "lib/common.h"
#include "lib/gwc.h"

typedef struct gwc_stats {
  uint64_t  requests,
            updates,
            ip_updates,
            url_updates,
            base_requests,
            data_requests,
            get_requests,
            hostfile_requests,
            ping_requests,
            statfile_requests,
            urlfile_requests,
            rx,
            tx,
            accepts,
            blocked,
            too_early,
            http_400s,
            http_404s,
            errors;
} gwc_stats_t;

typedef struct gwc_full_stats {
  struct timeval start_time;
  struct timeval last_time;
  gwc_stats_t total, last, hourly;
  struct rusage ru;
} gwc_full_stats_t;

gwc_full_stats_t * stats_init(const struct timeval tv);
void stats_count_request(gwc_full_stats_t *stats, const gwc_req_t req);
void stats_count_update(gwc_full_stats_t *stats, const gwc_req_t req);
void stats_count_accept(gwc_full_stats_t *stats);
void stats_count_blocked(gwc_full_stats_t *stats);
void stats_count_error(gwc_full_stats_t *stats);
void stats_count_too_early(gwc_full_stats_t *stats);
void stats_count_rx(gwc_full_stats_t *stats, const uint64_t bytes);
void stats_count_tx(gwc_full_stats_t *stats, const uint64_t bytes);
void stats_update(gwc_full_stats_t *stats, const struct timeval tv);
void stats_count_http_400(gwc_full_stats_t *stats);
void stats_count_http_404(gwc_full_stats_t *stats);
const gwc_full_stats_t *stats_get_full(gwc_full_stats_t *stats);

/* vi: set ai et sts=2 sw=2 cindent: */
#endif /* STATS_HEADER_FILE */
