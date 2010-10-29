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

#ifndef TEMPLATE_HEADER_FILE
#define TEMPLATE_HEADER_FILE

#include "lib/common.h"
#include "lib/snode.h"

#include "stats.h"

enum crab_chunk_type {
  chunk_data,
  chunk_http_response,
  chunk_http_header,
  
  crab_stats_total_updates,
  crab_stats_total_updates_ip,
  crab_stats_total_updates_url,
  crab_stats_total_requests,
  crab_stats_total_requests_base,
  crab_stats_total_requests_data,
  crab_stats_total_requests_get,
  crab_stats_total_requests_hostfile,
  crab_stats_total_requests_urlfile,
  crab_stats_total_requests_ping,
  crab_stats_total_requests_statfile,
  crab_stats_total_accepts,
  crab_stats_total_blocked,
  crab_stats_total_errors,
  crab_stats_total_http_400s,
  crab_stats_total_http_404s,
  crab_stats_total_too_early,
  crab_stats_total_rx,
  crab_stats_total_tx,
  
  crab_stats_hourly_updates,
  crab_stats_hourly_updates_ip,
  crab_stats_hourly_updates_url,
  crab_stats_hourly_requests,
  crab_stats_hourly_requests_base,
  crab_stats_hourly_requests_data,
  crab_stats_hourly_requests_get,
  crab_stats_hourly_requests_hostfile,
  crab_stats_hourly_requests_urlfile,
  crab_stats_hourly_requests_ping,
  crab_stats_hourly_requests_statfile,
  crab_stats_hourly_accepts,
  crab_stats_hourly_blocked,
  crab_stats_hourly_errors,
  crab_stats_hourly_http_400s,
  crab_stats_hourly_http_404s,
  crab_stats_hourly_too_early,
  crab_stats_hourly_rx,
  crab_stats_hourly_tx,
   
  crab_startup_time,
  crab_user_agent,
  crab_uri,
  crab_url,
  crab_network_id,
  crab_contact_address,
    
  crab_rusage_utime,
  crab_rusage_stime,
  crab_rusage_utime_percent,
  crab_rusage_stime_percent,
  crab_rusage_maxrss,
  crab_rusage_ixrss,
  crab_rusage_idrss,
  crab_rusage_isrss,
  crab_rusage_minflt,
  crab_rusage_majflt,
  crab_rusage_nswap,
  crab_rusage_inblock,
  crab_rusage_oublock,
  crab_rusage_msgsnd,
  crab_rusage_msgrcv,
  crab_rusage_nsignals,
  crab_rusage_nvcsw,
  crab_rusage_nivcsw,

  num_crab_chunk_types
};

struct template_chunk {
  enum crab_chunk_type type;
  size_t size;
  char *buf;
};

typedef struct {
  snode_t *chunks;
} template_t;

template_t *template_load(const char *filename);
struct mem_buf *template_get_chunk(struct template_chunk *,
    const gwc_full_stats_t *);


/* vi: set ai et sts=2 sw=2 cindent: */
#endif /* TEMPLATE_HEADER_FILE */

