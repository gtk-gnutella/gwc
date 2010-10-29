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

#include "lib/mem.h"
#include "lib/mem_buf.h"
#include "lib/gwc.h"
#include "lib/append.h"
#include "lib/http.h"

#include "options.h"
#include "template.h"

static const options_t *opts_;
#define OPTION(x) ((opts_ != NULL ? opts_ : (opts_ = options_get()))->x)

struct template_chunk *
template_chunk_new(const char *entity)
{
  static const struct {
    enum crab_chunk_type type;
    const char *name;
  } entities[] = {
  { crab_uri,             "crab.uri" },
  { crab_url,             "crab.url" },
  { crab_startup_time,    "crab.startup.time" },
  { crab_user_agent,      "crab.user.agent" },
  { crab_network_id,      "crab.network.id" },
  { crab_contact_address, "crab.contact.address" },
  
  { crab_rusage_utime,    "crab.rusage.utime" },
  { crab_rusage_stime,    "crab.rusage.stime" },
  { crab_rusage_utime_percent,    "crab.rusage.utime.percent" },
  { crab_rusage_stime_percent,    "crab.rusage.stime.percent" },
  { crab_rusage_maxrss,   "crab.rusage.maxrss" },
  { crab_rusage_ixrss,    "crab.rusage.ixrss" },
  { crab_rusage_idrss,    "crab.rusage.idrss" },
  { crab_rusage_isrss,    "crab.rusage.isrss" },
  { crab_rusage_minflt,   "crab.rusage.minflt" },
  { crab_rusage_majflt,   "crab.rusage.majflt" },
  { crab_rusage_nswap,    "crab.rusage.nswap" },
  { crab_rusage_inblock,  "crab.rusage.inblock" },
  { crab_rusage_oublock,  "crab.rusage.oublock" },
  { crab_rusage_msgsnd,   "crab.rusage.msgsnd" },
  { crab_rusage_msgrcv,   "crab.rusage.msgrcv" },
  { crab_rusage_nsignals, "crab.rusage.nsignals" },
  { crab_rusage_nvcsw,    "crab.rusage.nvcsw" },
  { crab_rusage_nivcsw,   "crab.rusage.nivcsw" },
  
  { crab_stats_total_updates,           "crab.stats.total.updates" },
  { crab_stats_total_updates_ip,        "crab.stats.total.updates.ip" },
  { crab_stats_total_updates_url,       "crab.stats.total.updates.url" },
  { crab_stats_total_requests,          "crab.stats.total.requests" },
  { crab_stats_total_requests_base,     "crab.stats.total.requests.base" },
  { crab_stats_total_requests_data,     "crab.stats.total.requests.data" },
  { crab_stats_total_requests_get,      "crab.stats.total.requests.get" },
  { crab_stats_total_requests_hostfile, "crab.stats.total.requests.hostfile" },
  { crab_stats_total_requests_urlfile,  "crab.stats.total.requests.urlfile" },
  { crab_stats_total_requests_ping,     "crab.stats.total.requests.ping" },
  { crab_stats_total_requests_statfile, "crab.stats.total.requests.statfile" },
  { crab_stats_total_accepts,           "crab.stats.total.accepts" },
  { crab_stats_total_blocked,           "crab.stats.total.blocked" },
  { crab_stats_total_errors,            "crab.stats.total.errors" },
  { crab_stats_total_http_400s,         "crab.stats.total.http_400s" },
  { crab_stats_total_http_404s,         "crab.stats.total.http_404s" },
  { crab_stats_total_too_early,         "crab.stats.total.too_early" },
  { crab_stats_total_rx,                "crab.stats.total.rx" },
  { crab_stats_total_tx,                "crab.stats.total.tx" },
  
  { crab_stats_hourly_updates,           "crab.stats.hourly.updates" },
  { crab_stats_hourly_updates_ip,        "crab.stats.hourly.updates.ip" },
  { crab_stats_hourly_updates_url,       "crab.stats.hourly.updates.url" },
  { crab_stats_hourly_requests,          "crab.stats.hourly.requests" },
  { crab_stats_hourly_requests_base,     "crab.stats.hourly.requests.base" },
  { crab_stats_hourly_requests_data,     "crab.stats.hourly.requests.data" },
  { crab_stats_hourly_requests_get,      "crab.stats.hourly.requests.get" },
  { crab_stats_hourly_requests_hostfile, "crab.stats.hourly.requests.hostfile"},
  { crab_stats_hourly_requests_urlfile,  "crab.stats.hourly.requests.urlfile" },
  { crab_stats_hourly_requests_ping,     "crab.stats.hourly.requests.ping" },
  { crab_stats_hourly_requests_statfile, "crab.stats.hourly.requests.statfile"},
  { crab_stats_hourly_accepts,           "crab.stats.hourly.accepts" },
  { crab_stats_hourly_blocked,           "crab.stats.hourly.blocked" },
  { crab_stats_hourly_errors,            "crab.stats.hourly.errors" },
  { crab_stats_hourly_http_400s,         "crab.stats.hourly.http_400s" },
  { crab_stats_hourly_http_404s,         "crab.stats.hourly.http_404s" },
  { crab_stats_hourly_too_early,         "crab.stats.hourly.too_early" },
  { crab_stats_hourly_rx,                "crab.stats.hourly.rx" },
  { crab_stats_hourly_tx,                "crab.stats.hourly.tx" },
  };
  size_t i;
  
  RUNTIME_ASSERT(entity != NULL);
  
  for (i = 0; i < ARRAY_LEN(entities); i++) {
    struct template_chunk *chunk;
    
    if (0 != strcmp(entity, entities[i].name)) {
      continue;
    }
    
    chunk = calloc(1, sizeof *chunk);
    if (chunk) {
      chunk->buf = NULL;
      chunk->size = 0;
      chunk->type = entities[i].type;
#if 0
      DBUG("Added template chunk \"%s\"", entities[i].name);
#endif
    }
    return chunk;
  }

  if (0 == strncmp(entity, "crab", sizeof "crab" - 1)) {
    WARN("No such entity \"%s\"", entity);
  } else {
#if 0
    DBUG("No such entity \"%s\"", entity);
#endif
  }
  return NULL;
}

struct mem_buf *
template_get_chunk(struct template_chunk *chunk, const gwc_full_stats_t *stats)
{
  char buf[1024], *p = buf;
  size_t avail = sizeof buf;

  switch (chunk->type) {
  case chunk_http_response:
  case chunk_http_header:
  case chunk_data:
    /* Must be handled elsewhere */
    p = NULL;
    RUNTIME_ASSERT(0);
    break;

  case crab_stats_total_updates:
    p = append_uint64(buf, &avail, stats->total.updates);
    break;
  case crab_stats_total_updates_ip:
    p = append_uint64(buf, &avail, stats->total.ip_updates);
    break;
  case crab_stats_total_updates_url:
    p = append_uint64(buf, &avail, stats->total.url_updates);
    break;
  case crab_stats_total_requests:
    p = append_uint64(buf, &avail, stats->total.requests);
    break;
  case crab_stats_total_requests_base:
    p = append_uint64(buf, &avail, stats->total.base_requests);
    break;
  case crab_stats_total_requests_data:
    p = append_uint64(buf, &avail, stats->total.data_requests);
    break;
  case crab_stats_total_requests_get:
    p = append_uint64(buf, &avail, stats->total.get_requests);
    break;
  case crab_stats_total_requests_hostfile:
    p = append_uint64(buf, &avail, stats->total.hostfile_requests);
    break;
  case crab_stats_total_requests_urlfile:
    p = append_uint64(buf, &avail, stats->total.urlfile_requests);
    break;
  case crab_stats_total_requests_ping:
    p = append_uint64(buf, &avail, stats->total.ping_requests);
    break;
  case crab_stats_total_requests_statfile:
    p = append_uint64(buf, &avail, stats->total.statfile_requests);
    break;
  case crab_stats_total_accepts:
    p = append_uint64(buf, &avail, stats->total.accepts);
    break;
  case crab_stats_total_blocked:
    p = append_uint64(buf, &avail, stats->total.blocked);
    break;
  case crab_stats_total_errors:
    p = append_uint64(buf, &avail, stats->total.errors);
    break;
  case crab_stats_total_http_400s:
    p = append_uint64(buf, &avail, stats->total.http_400s);
    break;
  case crab_stats_total_http_404s:
    p = append_uint64(buf, &avail, stats->total.http_404s);
    break;
  case crab_stats_total_too_early:
    p = append_uint64(buf, &avail, stats->total.too_early);
    break;
  case crab_stats_total_rx:
    p = append_size(buf, &avail, stats->total.rx);
    break;
  case crab_stats_total_tx:
    p = append_size(buf, &avail, stats->total.tx);
    break;

  case crab_stats_hourly_updates:
    p = append_uint64(buf, &avail, stats->hourly.updates);
    break;
  case crab_stats_hourly_updates_ip:
    p = append_uint64(buf, &avail, stats->hourly.ip_updates);
    break;
  case crab_stats_hourly_updates_url:
    p = append_uint64(buf, &avail, stats->hourly.url_updates);
    break;
  case crab_stats_hourly_requests:
    p = append_uint64(buf, &avail, stats->hourly.requests);
    break;
  case crab_stats_hourly_requests_base:
    p = append_uint64(buf, &avail, stats->hourly.base_requests);
    break;
  case crab_stats_hourly_requests_data:
    p = append_uint64(buf, &avail, stats->hourly.data_requests);
    break;
  case crab_stats_hourly_requests_get:
    p = append_uint64(buf, &avail, stats->hourly.get_requests);
    break;
  case crab_stats_hourly_requests_hostfile:
    p = append_uint64(buf, &avail, stats->hourly.hostfile_requests);
    break;
  case crab_stats_hourly_requests_urlfile:
    p = append_uint64(buf, &avail, stats->hourly.urlfile_requests);
    break;
  case crab_stats_hourly_requests_ping:
    p = append_uint64(buf, &avail, stats->hourly.ping_requests);
    break;
  case crab_stats_hourly_requests_statfile:
    p = append_uint64(buf, &avail, stats->hourly.statfile_requests);
    break;
  case crab_stats_hourly_accepts:
    p = append_uint64(buf, &avail, stats->hourly.accepts);
    break;
  case crab_stats_hourly_blocked:
    p = append_uint64(buf, &avail, stats->hourly.blocked);
    break;
  case crab_stats_hourly_errors:
    p = append_uint64(buf, &avail, stats->hourly.errors);
    break;
  case crab_stats_hourly_http_400s:
    p = append_uint64(buf, &avail, stats->hourly.http_400s);
    break;
  case crab_stats_hourly_http_404s:
    p = append_uint64(buf, &avail, stats->hourly.http_404s);
    break;
  case crab_stats_hourly_too_early:
    p = append_uint64(buf, &avail, stats->hourly.too_early);
    break;
  case crab_stats_hourly_rx:
    p = append_size(buf, &avail, stats->hourly.rx);
    break;
  case crab_stats_hourly_tx:
    p = append_size(buf, &avail, stats->hourly.tx);
    break;

  case crab_startup_time:
    p = append_date(buf, &avail, stats->start_time.tv_sec);
    break;
    
  case crab_user_agent:
    p = append_string(buf, &avail, GWC_USER_AGENT);
    break;

  case crab_uri:
    p = append_string(buf, &avail, OPTION(gwc_uri));
    break;

  case crab_url:
    p = append_string(buf, &avail, OPTION(gwc_url));
    break;

  case crab_network_id:
    p = append_string(buf, &avail,
          OPTION(network_id) ? OPTION(network_id) : "gnutella");
    break;
    
  case crab_contact_address:
    p = append_string(buf, &avail,
          OPTION(contact_address) ? OPTION(contact_address) : "");
    break;

#if defined(HAVE_GETRUSAGE)
#define RU_TIME(x) stats->ru.x
#else
#define RU_TIME(x) 0
#endif /* HAVE_GETRUSAGE */
 
  case crab_rusage_utime:
    {
      uint64_t v;

      v = (uint64_t) RU_TIME(ru_utime.tv_sec) * 1000000 +
        RU_TIME(ru_utime.tv_usec);
      p = append_uint64(buf, &avail, v);
    }
    break;
  case crab_rusage_stime:
    {
      uint64_t v;

      v = (uint64_t) RU_TIME(ru_stime.tv_sec) * 1000000 +
        RU_TIME(ru_stime.tv_usec);
      p = append_uint64(buf, &avail, v);
    }
    break;
    
   case crab_rusage_utime_percent:
    {
      uint64_t v;

      v = (uint64_t) RU_TIME(ru_utime.tv_sec) * 1000000 +
        RU_TIME(ru_utime.tv_usec);
      p = append_uint64(buf, &avail, v);
    }
    break;
  case crab_rusage_stime_percent:
    {
      uint64_t v;

      v = (uint64_t) RU_TIME(ru_stime.tv_sec) * 1000000 +
        RU_TIME(ru_stime.tv_usec);
      p = append_uint64(buf, &avail, v);
    }
    break;
    
#if defined(HAVE_GETRUSAGE) && defined(HAVE_BSD_STRUCT_RUSAGE)
#define RU(x) stats->ru.x
#else
#define RU(x) 0
#endif /* HAVE_GETRUSAGE && HAVE_BSD_STRUCT_RUSAGE */
    
  case crab_rusage_maxrss:
    p = append_uint64(buf, &avail, RU(ru_maxrss));
    break;
  case crab_rusage_ixrss:
    p = append_uint64(buf, &avail, RU(ru_ixrss));
    break;
  case crab_rusage_idrss:
    p = append_uint64(buf, &avail, RU(ru_idrss));
    break;
  case crab_rusage_isrss:
    p = append_uint64(buf, &avail, RU(ru_isrss));
    break;
  case crab_rusage_minflt:
    p = append_uint64(buf, &avail, RU(ru_minflt));
    break;
  case crab_rusage_majflt:
    p = append_uint64(buf, &avail, RU(ru_majflt));
    break;
  case crab_rusage_nswap:
    p = append_uint64(buf, &avail, RU(ru_nswap));
    break;
  case crab_rusage_inblock:
    p = append_uint64(buf, &avail, RU(ru_inblock));
    break;
  case crab_rusage_oublock:
    p = append_uint64(buf, &avail, RU(ru_oublock));
    break;
  case crab_rusage_msgsnd:
    p = append_uint64(buf, &avail, RU(ru_msgsnd));
    break;
  case crab_rusage_msgrcv:
    p = append_uint64(buf, &avail, RU(ru_msgrcv));
    break;
  case crab_rusage_nsignals:
    p = append_uint64(buf, &avail, RU(ru_nsignals));
    break;
  case crab_rusage_nvcsw:
    p = append_uint64(buf, &avail, RU(ru_nvcsw));
    break;
  case crab_rusage_nivcsw:
    p = append_uint64(buf, &avail, RU(ru_nivcsw));
    break;
    
#undef RU

  default:
    CRIT("Unknown chunk type (%u)", (unsigned) chunk->type);
    p = NULL;
    RUNTIME_ASSERT(0);
  }

  if (p && p != buf) {
    return mem_buf_new_copy(buf, p - buf);
  }
  return NULL;
}

static struct template_chunk *
template_raw_chunk_new(enum crab_chunk_type type, const char *buf, size_t size)
{
  struct template_chunk *c;
  
  c = calloc(1, size + sizeof *c);
  if (c) {
    c->type = type;
    c->size = size;
    c->buf = (char *) &c[1];
    memcpy(c->buf, buf, size);
  }
  return c;
}
    
template_t *
template_load(const char *filename)
{
  struct template_chunk *chunk;
  FILE *f;
  char *buf = NULL, *q;
  size_t buf_len, line;
  template_t *tpl = NULL;
  int c;
  char entity[128], *e = NULL;

  RUNTIME_ASSERT(filename != NULL);
  f = safer_fopen(filename, SAFER_FOPEN_RD);
  if (!f) {
    WARN("could not open \"%s\": %s", filename, compat_strerror(errno));
    goto failure;
  }

  tpl = calloc(1, sizeof *tpl);
  if (!tpl) {
    CRIT("Out of memory");
    goto failure;
  }
  tpl->chunks = NULL;
  
  buf_len = 4096;
  buf = calloc(1, buf_len);
  if (!buf) {
    CRIT("Out of memory");
    goto failure;
  }
  
  for (line = 1; /* NOTHING */; line++) {
    char *p;
    
    p = fgets(buf, buf_len, f);
    if (!p) {
      if (!ferror(f))
        break;

      CRIT("fgets() failed: %s", compat_strerror(errno));
      goto failure;
    }

    q = strchr(buf, '\n');
    if (!q) {
      CRIT("Line too long or unterminated: \"%s\"", buf);
      goto failure;
    }
    while (isspace((unsigned char) *q)) {
      *q = '\0';
      if (q == buf)
        break;
      q--;
    }
    
    if (q == buf && *q == '\0')
      break;

    if (line == 1 && 0 == strncmp(buf, "HTTP/", sizeof "HTTP/" - 1)) {
      uint64_t code;
      char *endptr;
      int error;
      struct http_response hres;
      size_t size;
      snode_t *sn;

      p = strchr(buf, ' ');
      if (!p) {
        WARN("Invalid HTTP response: \"%s\"", buf);
        goto failure;
      }
      
      p = skip_spaces(p);
      code = parse_uint64(p, &endptr, 10, &error);
      if (code < 100 || code > 999) {
        WARN("Invalid HTTP result code: \"%s\"", buf);
        goto failure;
      }
      p = skip_spaces(endptr);

      hres.code = code;
      size = sizeof hres.msg;
      append_string(hres.msg, &size, p);
      RUNTIME_ASSERT(hres.msg == (char *) &hres);
      chunk = template_raw_chunk_new(chunk_http_response,
                (char *) &hres, sizeof hres);

      if (NULL == (sn = snode_new(chunk))) {
        CRIT("snode_new() failed");
        goto failure;
      }
      tpl->chunks = snode_prepend(tpl->chunks, sn);
    } else {
      size_t len;
      snode_t *sn;

      if (!isalpha((unsigned char) buf[0]) || NULL == strchr(buf, ':')) {
        WARN("Invalid HTTP header: \"%s\"", buf);
        goto failure;
      }

      for (p = buf; (c = (unsigned char) *p) != ':'; ++p)
        if (!isalpha(c) && c != '-') {
          WARN("Invalid character HTTP in header name: \"%s\"", buf);
          goto failure;
        }
      
      len = strlen(buf) + 1;
      chunk = template_raw_chunk_new(chunk_http_header, buf, len);
      if (NULL == (sn = snode_new(chunk))) {
        CRIT("snode_new() failed");
        goto failure;
      }
      tpl->chunks = snode_prepend(tpl->chunks, sn);
    }
  }

  if (feof(f)) {
    tpl->chunks = snode_reverse(tpl->chunks);
    return tpl;
  }
  
  q = buf;
  e = NULL;
  
  for (;;) {
    c = fgetc(f);
    if (c == EOF) {
      if (!ferror(f))
        break;
      
      CRIT("fgetc() failed: %s", compat_strerror(errno));
      goto failure;
    }
    
    if ((size_t) (q - buf) >= buf_len) {
      char *n;
      
      buf_len += 4096;
      n = realloc(buf, buf_len);
      if (!n) {
        CRIT("Out of memory");
        goto failure;
      }
      q = &n[q - buf];
      buf = n;
    }
    *q++ = c;

    if (c == ';' && e != NULL) {
      RUNTIME_ASSERT(e >= entity && e < &entity[sizeof entity]);
      *e = '\0';
      
      chunk = template_chunk_new(entity);
      if (chunk) {
        struct template_chunk *data;
        size_t data_len;
        snode_t *sn;
     
        data_len = (q - buf) - strlen(entity) - 2;
        RUNTIME_ASSERT(data_len <= INT_MAX);
        if (data_len > 0) {
          data = template_raw_chunk_new(chunk_data, buf, data_len);
          if (NULL == (sn = snode_new(data))) {
            CRIT("snode_new() failed");
            goto failure;
          }
          tpl->chunks = snode_prepend(tpl->chunks, sn);
      
          buf_len = 4096;
          buf = calloc(1, buf_len);
          if (!buf) {
            CRIT("Out of memory");
            goto failure;
          }
        }
        q = buf;
    
        if (NULL == (sn = snode_new(chunk))) {
          CRIT("snode_new() failed");
          goto failure;
        }
        tpl->chunks = snode_prepend(tpl->chunks, sn);
      }

      e = NULL;
    }
    
    if (e) {
      bool b = isalnum(c) || c == '.' || c == '_';
      
      if (b && e < &entity[sizeof entity - 1]) {
        *e++ = c;
      } else {
        e = NULL;
      }
    }
    
    if (c == '&') {
      e = entity;
    }
  }
  fclose(f);
  f = NULL;

  if (q != buf) {
    snode_t *sn;

    chunk = template_raw_chunk_new(chunk_data, buf, q - buf);
    if (NULL == (sn = snode_new(chunk))) {
      CRIT("snode_new() failed");
      goto failure;
    }
    tpl->chunks = snode_prepend(tpl->chunks, sn);
  }
  DO_FREE(buf);
 
  tpl->chunks = snode_reverse(tpl->chunks);
  
#if 0
  {
    size_t n = 0;
    
    snode_t *sn = tpl->chunks;
    while (sn) {
      struct gwc_data_chunk *data = sn->ptr;
      DBUG("data->type=%d; data->buf=%p; data->size=%d",
          (int) data->type, data->buf, (int) data->size);
      sn = sn->next;
      n += data->size;
    }
    
    DBUG("n=%d", (int) n);
  }
#endif
  
  return tpl;

failure:

  CRIT("Loading data template from \"%s\" failed.", filename);

  if (f) {
    fclose(f);
    f = NULL;
  }
  DO_FREE(buf);
  if (tpl) {
    while (tpl->chunks != NULL) {
      snode_t *sn = tpl->chunks->next;
    
      DO_FREE(tpl->chunks);
      tpl->chunks = sn;
    }
    DO_FREE(tpl);
  }
  return NULL;
}

/* vi: set ai et sts=2 sw=2 cindent: */
