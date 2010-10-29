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

#include "stats.h"

void
stats_count_request(gwc_full_stats_t *stats, const gwc_req_t req)
{
  stats->total.requests++;

  if (GWC_REQ_NONE == req) {
    stats->total.base_requests++;
  } else {
    if (GWC_REQ_GET & req) {
      stats->total.get_requests++;
    }
    if (GWC_REQ_HOSTFILE & req) {
      stats->total.hostfile_requests++;
    }
    if (GWC_REQ_URLFILE & req) {
      stats->total.urlfile_requests++;
    }
    if (GWC_REQ_PING & req) {
      stats->total.ping_requests++;
    }
    if (GWC_REQ_STATFILE & req) {
      stats->total.statfile_requests++;
    }
    if (GWC_REQ_DATA & req) {
      stats->total.data_requests++;
    }
  }
}

void
stats_count_update(gwc_full_stats_t *stats, const gwc_req_t req)
{
  stats->total.updates++;

  if (GWC_REQ_IP & req) {
    stats->total.ip_updates++;
  }
  if (GWC_REQ_URL & req) {
    stats->total.url_updates++;
  }
}

void
stats_count_accept(gwc_full_stats_t *stats)
{
  stats->total.accepts++;
}

void
stats_count_blocked(gwc_full_stats_t *stats)
{
  stats->total.blocked++;
}

void
stats_count_too_early(gwc_full_stats_t *stats)
{
  stats->total.too_early++;
}

void
stats_count_error(gwc_full_stats_t *stats)
{
  stats->total.errors++;
}

void
stats_count_http_400(gwc_full_stats_t *stats)
{
  stats->total.http_400s++;
}

void
stats_count_http_404(gwc_full_stats_t *stats)
{
  stats->total.http_404s++;
}

void
stats_count_rx(gwc_full_stats_t *stats, const uint64_t n)
{
  stats->total.rx += n;
}

void
stats_count_tx(gwc_full_stats_t *stats, const uint64_t n)
{
  stats->total.tx += n;
}

void
stats_update(gwc_full_stats_t *stats, const struct timeval tv)
{
  RUNTIME_ASSERT(stats);
  
#ifdef HAVE_GETRUSAGE
  if (getrusage(RUSAGE_SELF, &stats->ru)) {
    WARN("getrusage() failed: \"%s\"", compat_strerror(errno));
  }
#endif /* HAVE_GETRUSAGE */

#define HOURLY_STATS(x) \
  stats->hourly.x = (stats->total.x) - (stats->last.x)
    
  if (difftime(tv.tv_sec, stats->last_time.tv_sec) < 3600)
    return;
  
  HOURLY_STATS(requests);
  HOURLY_STATS(updates);
  HOURLY_STATS(url_updates);
  HOURLY_STATS(ip_updates);
  HOURLY_STATS(base_requests);
  HOURLY_STATS(data_requests);
  HOURLY_STATS(get_requests);
  HOURLY_STATS(hostfile_requests);
  HOURLY_STATS(urlfile_requests);
  HOURLY_STATS(ping_requests);
  HOURLY_STATS(statfile_requests);
  HOURLY_STATS(rx);
  HOURLY_STATS(tx);
  HOURLY_STATS(accepts);
  HOURLY_STATS(blocked);
  HOURLY_STATS(too_early);
  HOURLY_STATS(errors);
  HOURLY_STATS(http_400s);
  HOURLY_STATS(http_404s);
  stats->last = stats->total;
  stats->last_time = tv;

#undef HOURLY_STATS
}

gwc_full_stats_t *
stats_init(const struct timeval tv)
{
  gwc_full_stats_t *stats;

  stats = malloc(sizeof *stats);
  if (stats) {
    static const gwc_full_stats_t zero_stats;

    *stats = zero_stats;
    stats->start_time = tv;
    stats->last_time = tv;
  }
  return stats;
}
  
/* vi: set ai et sts=2 sw=2 cindent: */
