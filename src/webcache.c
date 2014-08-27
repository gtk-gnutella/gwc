/*
 * Copyright (c) 2006 Christian Biere <christianbiere@gmx.de>
 * All rights reserved.
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

#include "lib/append.h"
#include "lib/mem.h"
#include "lib/http.h"
#include "lib/gwc.h"
#include "lib/peerlock.h"

#include "options.h"
#include "peercache.h"
#include "stats.h"
#include "template.h"
#include "uhc.h"
#include "webcache.h"
#include "checker.h"

#define TIME_MARK_DELAY 60

/* How often [in seconds] the caches are saved to disk */
#define SAVE_INTERVAL (15U * 60)

static volatile sig_atomic_t shutdown_request = 0;
static volatile sig_atomic_t sighup_received = 0;

static const options_t *opts_;
#define OPTION(x) ((opts_ != NULL ? opts_ : (opts_ = options_get()))->x)

static gwc_full_stats_t *stats;

static acclog_t *access_logger;
static FILE *alert_logger;

static peer_cache_t *peer_cache;

static peer_lock_set_t *update_locks;
static peer_lock_set_t *request_locks;

static template_t *base_template;
static template_t *data_template;

static struct addr_filter *addr_filter;

static ev_watcher_t *watcher;
static connection_t *listen_con, *listen6_con;

static unsigned num_incoming = 0;
static unsigned num_connections = 0;
static unsigned max_connections = INT_MAX;

static void
sigint_handler(int signo)
{
  (void) signo;
  shutdown_request = 1;
}

static void
sighup_handler(int signo)
{
  (void) signo;
  sighup_received = 1;
}

static int
setup_signal_handlers(void)
{
  if (SIG_ERR == set_signal(SIGINT, sigint_handler)) {
    CRIT("set_signal(SIGINT, sigint_handler) failed: %s",
        compat_strerror(errno));
    return -1;
  }
  if (SIG_ERR == set_signal(SIGTERM, sigint_handler)) {
    CRIT("set_signal(SIGTERM, sigint_handler) failed: %s",
        compat_strerror(errno));
    return -1;
  }
  if (SIG_ERR == set_signal(SIGHUP, sighup_handler)) {
    CRIT("set_signal(SIGHUP, sighup_handler) failed: %s",
        compat_strerror(errno));
    return -1;
  }

  return 0;
}

static void
terminate(void)
{
  fflush(NULL);
  exit(0);
  /* NOTREACHED */
  RUNTIME_ASSERT(0);
}

static inline void
main_logv(const char *fmt, va_list ap)
{
  vfprintf(stderr, fmt, ap);
  putc('\n', stderr);
}

static inline void
alert(net_addr_t addr, const struct timeval now,
    const char *user_agent, const char *msg)
{
  if (alert_logger) {
    char addr_buf[NET_ADDR_BUFLEN];
    char date_buf[RFC1123_DATE_BUFLEN];
    char buf[1024], *p = buf;
    size_t size = sizeof buf;
    const char *quote;

    print_net_addr(addr_buf, sizeof addr_buf, addr);
    print_rfc1123_date(date_buf, sizeof date_buf, now.tv_sec);
    if (user_agent) {
      p = append_escaped_string(p, &size, user_agent);
      quote = "\"";
    } else {
      p = append_string(p, &size, "-");
      quote = "";
    }
    
    fprintf(alert_logger, "%s [%s]: %s%s%s \"%s\"\n",
        addr_buf, date_buf, quote, buf, quote, msg);
  }
}

static void
log_time_mark(time_t now)
{
  static time_t last_mark;
      
  if (!now)
    now = compat_mono_time(NULL);
  if (!last_mark || difftime(now, last_mark) >= TIME_MARK_DELAY) {
    char date[RFC1123_DATE_BUFLEN];
    
    last_mark = now;
    print_rfc1123_date(date, sizeof date, now);
    fprintf(stderr, "<<< %s >>>\n", date);
    fflush(stderr);
  }
}

static int
reopen_logs(void)
{
  if (!freopen(OPTION(log_main), "a", stderr)) {
    CRIT("freopen() failed for 'log_main': \"%s\"", compat_strerror(errno));
    return -1;
  }

  if (webcache_reopen_logs()) {
    CRIT("webcache_reopen_logs() failed: \"%s\"", compat_strerror(errno));
    return -1;
  }

  if (uhc_reopen_logs()) {
    CRIT("uhc_reopen_logs() failed: \"%s\"", compat_strerror(errno));
    return -1;
  }

  log_time_mark(0);
  INFO("Reopened log file");
  return 0;
}

static struct {
  size_t in, out, n;
  peer_t peers[3600];
} removed_peers;

static inline const peer_t *
get_removed_peer(void)
{
  const peer_t *p;
  
  if (0 == removed_peers.n)
    return NULL;
  
  p = &removed_peers.peers[removed_peers.out++];
  RUNTIME_ASSERT(p->port > 1023);
  removed_peers.out %= ARRAY_LEN(removed_peers.peers);
  removed_peers.n--;
  return p;
}
 
static inline void
add_removed_peer(const peer_t *p)
{
  if (removed_peers.n == ARRAY_LEN(removed_peers.peers))
    return;
  
  removed_peers.peers[removed_peers.in++] = *p;
  removed_peers.in %= ARRAY_LEN(removed_peers.peers);
  removed_peers.n++;
}

static void
peer_removed(const net_addr_t *addr, in_port_t port)
{
  peer_t p;
  
  RUNTIME_ASSERT(addr);
  RUNTIME_ASSERT(0 != port);

  p.addr = *addr;
  p.port = port;
  add_removed_peer(&p);
}

static char *
client_id(const client_t *ctx, char *dst, size_t size)
{
  char *p = dst;
  
  RUNTIME_ASSERT(ctx != NULL);
  RUNTIME_ASSERT(dst != NULL);
  RUNTIME_ASSERT(size <= INT_MAX);
  
  if (ctx->client_id[0] == '\0' && ctx->client_ver[0] == '\0') {
    return NULL;
  }
  
  p = append_string(p, &size, ctx->client_id);
  p = append_string(p, &size, "/");
  p = append_string(p, &size, ctx->client_ver);
  return dst;
}

/**
 * Appends extra data as specified by the GWebCache protocol version 3 plus.
 *
 * @param ctx the client context.
 * @param small if "true" only the most important data is appended.
 * @param dst pointer to the destination buffer
 */
static char *
client_append_extra_data(client_t *ctx, bool small, char *dst, size_t *p_size)
{
  size_t dst_size;
  char *p;
  
  RUNTIME_ASSERT(dst);
  RUNTIME_ASSERT(p_size);
  RUNTIME_ASSERT(*p_size <= INT_MAX);
  
  if (ctx->proto_ver < 3)
    return dst;

  p = dst;
  dst_size = *p_size;
  
  if (OPTION(support_uhc)) {
    p = APPEND_STATIC_CHARS(p, p_size, "option: autarkic");
    p = APPEND_CRLF(p, p_size);
    
    if (!small && OPTION(uhc_hostname)) {
      p = APPEND_STATIC_CHARS(p, p_size, "uhc: ");
      p = append_string(p, p_size, OPTION(uhc_hostname));
      p = APPEND_STATIC_CHARS(p, p_size, ":");
      p = append_uint(p, p_size, OPTION(uhc_port));
      p = APPEND_CRLF(p, p_size);
    }
  }

  if (OPTION(network_id)) {
    p = APPEND_STATIC_CHARS(p, p_size, "net: ");
    p = append_string(p, p_size, OPTION(network_id));
    p = APPEND_CRLF(p, p_size);
  }

  if (*p_size < 2) {
    WARN("Too few buffer space for extra data");
    p = dst;
    *p_size = dst_size;
  }

  return p;
}
 
/**
 * Send a text/plain error message over HTTP to the client.
 * Always uses the v1.0 "ERROR:" prefix as the v2.0 syntax more difficult to
 * parse and not correctly implemented by many clients and GWebCache scripts.
 *
 * The message is truncated if it's longer than about 100 characters.
 */
int
gwc_return_error(client_t *ctx, const char *str)
{
  char buf[2048], *p = buf;
  size_t size = sizeof buf;

  RUNTIME_ASSERT(str != NULL);

  stats_count_error(stats);
  alert(connection_get_addr(ctx->con),
      ev_source_get_stamp(connection_get_source(ctx->con)),
      client_id(ctx, buf, sizeof buf), str);
  
  p = APPEND_STATIC_CHARS(p, &size, "ERROR: ");
  p = append_string(p, &size, str);
  p = APPEND_CRLF(p, &size);
  p = client_append_extra_data(ctx, true, p, &size);

  return http_send_text(&ctx->http, buf, p - buf);
}


int
client_process_ping_request(client_t *ctx)
{
  char buf[4096], *p = buf;
  size_t size = sizeof buf;

  RUNTIME_ASSERT(ctx);

  p = APPEND_STATIC_CHARS(p, &size, "PONG " GWC_USER_AGENT "\r\n");
  p = client_append_extra_data(ctx, true, p, &size);

  http_send_text(&ctx->http, buf, p - buf);
  return 0;
}

static const char *
client_process_ip_request(client_t *ctx, peer_cache_t *cache, const char *host)
{
  const char *msg = NULL;
  char *endptr;
  net_addr_t addr;
  in_port_t port;

  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(cache);
  RUNTIME_ASSERT(host);
  
  if (!parse_net_addr(host, &addr, &endptr)) {
    msg = "Invalid IP address";
  } else if (!net_addr_equal(addr, connection_get_addr(ctx->con))) {
    msg = "Reported different IP address";
  } else if (net_addr_is_private(addr)) {
    /* Just in case, so that private addresses don't make it to the cache */
    msg = "Private IP addresses are not allowed";
  } else if (ctx->http.proxied) {
    msg = "Proxy address rejected";
  } else if (':' != *endptr++) {
    msg = "Missing port value; expected ':'";
  } else if (!parse_port_number(endptr, &port, &endptr)) {
    msg = "Invalid port value";
  } else if (!GWC_ALLOW_PEERS_ON_PRIV_PORTS && port < 1024) {
    msg = "Ports below 1024 are blocked";
  } else if ('\0' != *endptr) {
    msg = "Trailing characters after port value";
  }

  if (!msg) {
    struct timeval now;
    
    now = ev_source_get_stamp(connection_get_source(ctx->con));
    peer_cache_add(cache, now.tv_sec, addr, port);
  }
  return msg;
}


static const char *
client_process_url_request(client_t *ctx, char *req_url)
{
  char *url = NULL;
  const char *ret = NULL;
  int res;
  
  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(req_url);

  url = gwc_url_normalize(req_url, &res);
  if (!url) {
    WARN("%s", gwc_url_normalize_result(res));
    ret = "Unacceptable URL";
  } else {
    struct timeval now;

    now = ev_source_get_stamp(connection_get_source(ctx->con));
    checker_verify_url(url, now.tv_sec, false);
  }

  if (url != req_url) {
    DO_FREE(url);
  }
  
  return ret;
}

struct gwc_url_set {
  size_t i;
  const gwc_url_t *g[256];
};

static bool
get_gwcs_helper(const void *key, const void *value, void *udata)
{
  struct gwc_url_set *gs;
  const gwc_url_t *g;

  RUNTIME_ASSERT(key != NULL);
  RUNTIME_ASSERT(value != NULL);
  RUNTIME_ASSERT(udata != NULL);

  gs = udata;
  if (gs->i >= ARRAY_LEN(gs->g))
    return true;

  g = value;
  gwc_check_url_entry(g);
  gs->g[gs->i++] = g;
  
  return false;
}

static size_t
client_get_gwcs(client_t *ctx, gwc_cache_t *cache,
    const gwc_url_t **gwcv, size_t size)
{
  struct gwc_url_set gs;
  struct timeval tv;
  size_t x, i, count = 0;

  gs.i = 0;    
  gwc_foreach(cache, get_gwcs_helper, &gs);
  
  tv = ev_source_get_stamp(connection_get_source(ctx->con));
  x = random();
  memset(gwcv, 0, sizeof gwcv[0] * size);

  for (i = 0; i < gs.i; i++) {
    const gwc_url_t *g;

    g = gs.g[(x += 37) % gs.i];
    if (g->url) {
     
      gwc_check_url_entry(g);
      if (difftime(tv.tv_sec, g->stamp) > MAX_GOOD_GWC_AGE) {
        checker_verify_url(g->url, tv.tv_sec, false);
        g = NULL; /* Might be invalid now */
        continue;
      }
      
      gwcv[count] = g;
      if (++count >= size)
        break;
    }
  }

  return count;
}


static char *
client_append_gwc_urls(client_t *ctx, gwc_cache_t *cache,
    size_t n, char *p, size_t *p_size)
{
  const gwc_url_t *gwcv[MAX_GWCS_PER_REQ];
  size_t i;
  
  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(n <= INT_MAX);
  RUNTIME_ASSERT(p);
  RUNTIME_ASSERT(p_size);
  RUNTIME_ASSERT(*p_size <= INT_MAX);
 
  n = MIN(n, ARRAY_LEN(gwcv));
  n = client_get_gwcs(ctx, cache, gwcv, n);
  RUNTIME_ASSERT(n <= ARRAY_LEN(gwcv));

  for (i = 0; i < n; i++) {
    char *last_p = p;
    size_t last_size = *p_size;
    
    p = append_chars(p, p_size, gwcv[i]->url, gwcv[i]->len);
    p = APPEND_CRLF(p, p_size);

    /*
     * If the buffer filled up, rewind to the last line start to ensure
     * we emit no truncated data.
     */
    if (*p_size < 2) {
      p = last_p;
      *p_size = last_size;
      break;
    }
  }

  return p; 
}

static int
client_process_urlfile_request(client_t *ctx, gwc_cache_t *gwc_cache)
{
  char buf[4096], *p = buf;
  size_t size = sizeof buf - 1;

  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(gwc_cache);

  p = client_append_gwc_urls(ctx, gwc_cache, OPTION(urlfile_lines), p, &size);
  p = client_append_extra_data(ctx, false, p, &size);
 
  RUNTIME_ASSERT(p >= buf && p < &buf[sizeof buf]);
#if 0
  *p = '\0';
  DBUG("buf=\"%s\"", buf);
#endif
  
  http_send_text(&ctx->http, buf, p - buf);
  return 0;
}

static int
client_get_peers(client_t *ctx, peer_cache_t *cache,
    const peer_t **peerv, ssize_t n)
{
  net_addr_t addr;
  struct timeval tv;
 
  addr = connection_get_addr(ctx->con);
  tv = ev_source_get_stamp(connection_get_source(ctx->con));

  return peer_cache_get(cache, peerv, n, tv.tv_sec, addr);
}

static int
client_process_hostfile_request(client_t *ctx,
    peer_cache_t *peers, gwc_cache_t *gwcs)
{
  static const char layout[NET_ADDR_PORT_BUFLEN + sizeof "\r\n"]; 
  const peer_t *peerv[MAX_PEERS_PER_REQ];
  char buf[sizeof layout * ARRAY_LEN(peerv) + 1024], *p = buf;
  size_t size = sizeof buf - 1;
  size_t n, i;

  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(peers);
  RUNTIME_ASSERT(gwcs);
  
  for (i = 0; i < ARRAY_LEN(peerv); i++) {
    peerv[i] = NULL;
  }
  
  if (ctx->wants_gwcs) {
    n = OPTION(urlfile_lines) / 4;
    n = MAX(1, n);
    p = client_append_gwc_urls(ctx, gwcs, n, p, &size);
  }

  n = OPTION(hostfile_lines);
  RUNTIME_ASSERT(n <= ARRAY_LEN(peerv));
  n = client_get_peers(ctx, peers, peerv, n);
  RUNTIME_ASSERT(n <= ARRAY_LEN(peerv));

  for (i = 0; i < n; i++) {
    const peer_t *peer = peerv[i];
    
    RUNTIME_ASSERT(peer);
    RUNTIME_ASSERT(peer->port >= 1024);
  
    {
      char *endptr, *last_p = p;
      size_t last_size = size;

      endptr = print_net_addr_port(p, size, peer->addr, peer->port);
      size -= endptr - p;
      p = endptr;
      p = APPEND_CRLF(p, &size);

      if (size < 2) {
        p = last_p;
        size = last_size;
        break;
      }
    }
  }

  p = client_append_extra_data(ctx, false, p, &size);
  
  RUNTIME_ASSERT(p >= buf && p < &buf[sizeof buf]);
#if 0
  *p = '\0';
  DBUG("buf=\"%s\"", buf);
#endif
  
  http_send_text(&ctx->http, buf, p - buf);
  return 0;
}

static char *
client_process_update_warning(const client_t *ctx,
    const char *msg, char *buf, size_t *p_size)
{
  char id_buf[64], *p = buf;

  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(msg);
  RUNTIME_ASSERT(buf);
  RUNTIME_ASSERT(p_size);
  RUNTIME_ASSERT(*p_size <= INT_MAX);

  alert(connection_get_addr(ctx->con),
    ev_source_get_stamp(connection_get_source(ctx->con)),
    client_id(ctx, id_buf, sizeof id_buf), msg);
  
  p = append_string(p, p_size,
        2 == ctx->proto_ver ? "I|update|WARNING|" : "WARNING: ");
  p = append_string(p, p_size, msg);
  p = APPEND_CRLF(p, p_size);
  
  return p;
}

static size_t
client_process_v2_ping_request(client_t *ctx, char *buf, size_t size)
{
  static const char msg[] = "I|pong|" GWC_USER_AGENT;
  const char *net = OPTION(network_id);
  char *p = buf;

  (void) ctx;
  RUNTIME_ASSERT(size <= INT_MAX);

  p = APPEND_STATIC_CHARS(p, &size, msg);
  if (NULL != net) {
    p = append_char(p, &size, '|');
    p = append_chars(p, &size, net, strlen(net));
  }
  p = APPEND_CRLF(p, &size);

  return p - buf;
}
 
static size_t
client_process_get_request(client_t *ctx, char *buf, size_t size,
    gwc_cache_t *gcache, peer_cache_t *pcache)
{
  char *q = buf;
  ssize_t ret, i;
  struct timeval tv;
  const peer_t *peerv[MAX_PEERS_PER_REQ];
  const gwc_url_t *gwcv[MAX_GWCS_PER_REQ];

  RUNTIME_ASSERT(q == buf);

  i = OPTION(peers_per_get);
  RUNTIME_ASSERT(i > 0);
  RUNTIME_ASSERT(i <= (ssize_t) ARRAY_LEN(peerv));

  ret = client_get_peers(ctx, pcache, peerv, i);
  RUNTIME_ASSERT(ret >= 0);
  RUNTIME_ASSERT(ret <= (ssize_t) ARRAY_LEN(peerv));
  
  tv = ev_source_get_stamp(connection_get_source(ctx->con));
  
  for (i = 0; i < ret; i++) {
    const peer_t *p = peerv[i];
    char *ep;
    size_t maxlen;
    
    maxlen = sizeof "H|" + NET_ADDR_PORT_BUFLEN +
      UINT64_DEC_BUFLEN + sizeof "|\r\n" - 1;
    
    if (maxlen > size)
      break;
      
    q = APPEND_STATIC_CHARS(q, &size, "H|");
    ep = print_net_addr_port(q, size, p->addr, p->port);
    size -= ep - q;
    q = ep;
    
    q = append_char(q, &size, '|');
    q = append_uint32(q, &size, difftime(tv.tv_sec, p->stamp));
    
    q = APPEND_CRLF(q, &size);
  }

  i = OPTION(gwcs_per_get);
  RUNTIME_ASSERT(i > 0 && i <= (ssize_t) ARRAY_LEN(gwcv));
  ret = client_get_gwcs(ctx, gcache, gwcv, i);
  RUNTIME_ASSERT(ret >= 0 && ret <= (ssize_t) ARRAY_LEN(gwcv));
   
  for (i = 0; i < ret; i++) {
    const gwc_url_t *g = gwcv[i];
    size_t maxlen;

    RUNTIME_ASSERT(g);
    RUNTIME_ASSERT(g->url);
    RUNTIME_ASSERT(g->len > sizeof http_prefix && g->len < MAX_URL_SIZE);
    RUNTIME_ASSERT(!strncmp(g->url, http_prefix, sizeof http_prefix - 1));
    
    maxlen = sizeof "U|" + g->len + sizeof "|" - 1  + UINT64_DEC_BUFLEN
      + sizeof "\r\n" - 1;
    if (maxlen > size)
      break;

    q = APPEND_STATIC_CHARS(q, &size, "U|");
    q = append_chars(q, &size, g->url, g->len);
    q = append_char(q, &size, '|');
    q = append_uint64(q, &size, difftime(tv.tv_sec, g->stamp));
    q = APPEND_CRLF(q, &size);
  }

#if 0
  /* This is super-verbose and causes *huge* log files */
  DBUG("buf=\"%s\"; q-buf=%d", buf, (int) (q - buf));
#endif
  RUNTIME_ASSERT(q >= buf && q < &buf[size]);
  
  return q - buf;
}

static int
send_template(client_t *client, const template_t *template)
{
  snode_t *sn;
  uint64_t data_size = 0;
  list_t *data;
   
  RUNTIME_ASSERT(client != NULL);
  RUNTIME_ASSERT(client->con != NULL);

  http_set_status(&client->http, 200, "OK");
  data = list_new();
  
  if (template) {
    for (sn = template->chunks; sn != NULL; sn = sn->next) {
      struct template_chunk *chunk;

      RUNTIME_ASSERT(sn->ptr != NULL);
      chunk = sn->ptr;

      switch (chunk->type) {
      case chunk_http_header:
        http_add_header(&client->http, chunk->buf);
        break;

      case chunk_http_response:
        {
          struct http_response *hres;

          hres = (void *) chunk->buf;
          http_set_status(&client->http, hres->code, hres->msg);
        }
        break;

      case chunk_data:
        {
          struct mem_buf *mb;

          mb = mem_buf_new_shallow(chunk->buf, chunk->size, NULL);
          if (mb) {
            list_append(data, mb);
            data_size += mb->fill;
          }
        }
        break;

      default:
        {
          struct mem_buf *mb;

          mb = template_get_chunk(chunk, stats);
          if (mb) {
            list_append(data, mb);
            data_size += mb->fill;
          }
        }
      }
    }
  }
    
  http_set_content_length(&client->http, data_size);
  http_send_response(&client->http);

  {
    list_iter_t i;
    bool v;

    for (v = list_iter_first(&i, data); v; v = list_iter_next(&i)) {
      struct mem_buf *mb;

      /* This could be optimized by creating shallow copies or
       * passing the ownership of the mem_buf to client. */
      mb = list_iter_get_ptr(&i);
      client_queue_mem_buf(client, mb);
      mem_buf_unref(mb);
    }
  }
  list_free(data);
  data = NULL;

  return 0;
}

static int
client_process_base_request(client_t *client)
{
  RUNTIME_ASSERT(client != NULL);
  return send_template(client, base_template);
}

static int
client_process_data_request(client_t *client)
{
  RUNTIME_ASSERT(client != NULL);
  return send_template(client, data_template);
}

static int
client_process_statfile_request(client_t *client)
{
  char buf[512], *p = buf;
  size_t size = sizeof buf;

  p = append_uint64(p, &size, stats->total.requests);
  p = APPEND_CRLF(p, &size);
    
  p = append_uint(p, &size, stats->hourly.requests);
  p = APPEND_CRLF(p, &size);
    
  p = append_uint(p, &size, stats->hourly.updates);
  p = APPEND_CRLF(p, &size);
  
  p = client_append_extra_data(client, true, p, &size);
  
  RUNTIME_ASSERT(p <= &buf[sizeof buf]);
  return http_send_text(&client->http, buf, p - buf);
}

static inline bool
network_supported(const char *network)
{
  static const char gnet[] = "gnutella";
  const char *net = OPTION(network_id);

  return (!net && !network) ||
    0 == strcmp(net ? net : gnet, network ? network : gnet);
}

static gwc_req_t
map_string_to_req(const char *s)
{
  static const struct {
    gwc_req_t req;
    const char *str;
  } req_map[] = {
    { GWC_REQ_IP,         "ip" },
    { GWC_REQ_URL,        "url" },
    { GWC_REQ_HOSTFILE,   "hostfile" },
    { GWC_REQ_URLFILE,    "urlfile" },
    { GWC_REQ_STATFILE,   "statfile" },
    { GWC_REQ_PING,       "ping" },
    { GWC_REQ_GET,        "get" },
    { GWC_REQ_UPDATE,     "update" },
    { GWC_REQ_NET,        "net" },
    { GWC_REQ_DATA,       "data" },
    { GWC_REQ_CLIENT,     "client" },
    { GWC_REQ_VERSION,    "version" },
    { GWC_REQ_PROTO_VER,  "pv" },
    { GWC_REQ_GWCS,       "gwcs" },
    { GWC_REQ_IPV6,       "ipv6" },
  };
  size_t i;
 
  STATIC_ASSERT(ARRAY_LEN(req_map) == NUM_GWC_REQS);
  RUNTIME_ASSERT(s != NULL);
  
  for (i = 0; i < ARRAY_LEN(req_map); i++) {
    if (0 == strcmp(s, req_map[i].str))
      return req_map[i].req;
  }

  return GWC_REQ_NONE;
}

/**
 * NB: modifies ``req''!
 */
static int
client_process_query(client_t *ctx, char *req)
{
  gwc_req_t     request = GWC_REQ_NONE;
  char          *cmd,
                *q,
                *url_req_uri = NULL,
                *ip_req_host = NULL,
                *data_key = NULL,
                *next = NULL;
  unsigned int  output_reqs = 0; /* # of requests requiring output */
  bool          v2 = false;
  bool          ret = false;
  const char    *url_msg = NULL, *ip_msg = NULL;
  int           req_count = 0;
  const char    *error_msg = NULL;
  const char    *network = NULL;

#define ERROR_MSG(x) do { \
  if (!error_msg) \
    error_msg = (x); \
} while (0)
 
  for (cmd = req; cmd; cmd = next) {
    gwc_req_t param;
    
    if (req_count++ >= GWC_MAX_COMBINED_REQUESTS) {
      CRIT("Too many combined requests; skipping remaining");
      break;
    }

    next = strchr(cmd, '&');
    if (next)
      *next++ = '\0';
     
    if (*cmd == '=' || *cmd == '\0') {
      ERROR_MSG("Bad request; empty parameter name");
      break;
    }
    
    for (q = cmd; *q != '='; q++) {
      if (*q == '\0') {
        ERROR_MSG("Bad request; expected '='");
        break;
      }
      *q = tolower((unsigned char) *q);
    }
    if (*q == '\0') {
      break;
    }
    *q++ = '\0';

    if (!url_decode(cmd, cmd, q - cmd)) {
      ERROR_MSG("Search part is invalidly encoded");
      break;
    }

    if (!url_decode(q, q, next ? (next - q) : (ssize_t)(strlen(q) + 1))) {
      ERROR_MSG("Parameter part is invalidly encoded");
      break;
    }

    param = map_string_to_req(cmd);
    if (request & param) {
      ERROR_MSG("Duplicate requests are unacceptable");
      break;
    }
    request |= param;
    
    switch (param) {
    case GWC_REQ_IP:
      ip_req_host = q;
      q = strchr(q, '\0');
      break;
      
    case GWC_REQ_URL:
      url_req_uri = q;
      q = strchr(q, '\0');
      break;
      
    case GWC_REQ_URLFILE:
      output_reqs++;

      if (*q != '1' || q[1] != '\0') {
        WARN("Request is not well-formed; expected '1'");
      }
      q = strchr(q, '\0');
      break;
      
    case GWC_REQ_HOSTFILE:
      output_reqs++;

      if (*q != '1' || q[1] != '\0') {
        WARN("Request is not well-formed; expected '1'");
      }
      q = strchr(q, '\0');
      break;

    case GWC_REQ_GET:
      v2 = true;

      /* "get" overrides hostfile and urlfile for backward compatibility */
      output_reqs++;

      if (*q != '1' || q[1] != '\0') {
        WARN("Request is not well-formed; expected '1'");
      }
      q = strchr(q, '\0');
      break;
      
    case GWC_REQ_PING:
      output_reqs++;

      if (*q != '1' || q[1] != '\0') {
        WARN("Request is not well-formed; expected '1'");
      }
      q = strchr(q, '\0');
      break;
      
    case GWC_REQ_CLIENT:
      {
        char *p, *end = &ctx->client_id[sizeof ctx->client_id - 1];
        bool invalid = false;
        int c;
      
        for (p = ctx->client_id; (c = (unsigned char) *q++) != '\0'; p++) {
          if (p == end)
            break;

          if (iscntrl(c) || c < 32 || c > 126) {
            invalid = true;
          }
          *p = c;
        }
        *p = '\0';

        if (invalid) {
          ERROR_MSG("Invalid character in ``client'' argument");
          break;
        }
        
        if (p - ctx->client_id > 4) {
          v2 = true;
        }
        if (p == end) {
          ERROR_MSG("``client'' argument is too long");
          break;
        }

        q = strchr(q, '\0');
      }
      break;
      
    case GWC_REQ_VERSION:
      {
        char *p, *end = &ctx->client_ver[sizeof ctx->client_ver - 1];
        bool invalid = false;
        int c;
      
        for (p = ctx->client_ver; (c = (unsigned char) *q++) != '\0'; p++) {
          if (p == end)
            break;

          if (iscntrl(c) || c < 32 || c > 126) {
            invalid = true;
          }
          *p = c;
        }
        *p = '\0';
      
        if (invalid) {
          ERROR_MSG("Invalid character in ``version'' argument");
          break;
        }
        if (p == end) {
          ERROR_MSG("``version'' argument is too long");
          break;
        }
        
        q = strchr(q, '\0');
      }
      break;
      
    case GWC_REQ_NET:
      {
        int c;
        
        network = q;
        for (/* NOTHING */; (c = (unsigned char) *q) != '\0'; q++) {
          if (isupper(c))
            *q = tolower(c);
        }
      }
      break;
      
    case GWC_REQ_GWCS:
      ctx->wants_gwcs |= ('1' == q[0] && '\0' == q[1]);
      q = strchr(q, '\0');
      break;

    case GWC_REQ_IPV6:
      if (isdigit((unsigned char) q[0]) && '\0' == q[1]) {
        switch (q[0]) {
         case '0':
          ctx->ip_pref = IP_PREF_IPV4; /* wants IPv4 addresses only */
          break;
        case '2':
          ctx->ip_pref = IP_PREF_IPV6; /* wants IPv6 addresses only */
          break;
        case '1':
        default:
          ctx->ip_pref = IP_PREF_NONE; /* No preference */
        }
      }
      q = strchr(q, '\0');
      break;
      
    case GWC_REQ_PROTO_VER:
      if (isdigit((unsigned char) q[0])) {
        char *endptr;
        uint32_t u;
        int error;

        u = parse_uint32(q, &endptr, 10, &error);
        ctx->proto_ver = (!error && '\0' == *endptr) ? u : 0;
        if (2 == ctx->proto_ver)
          v2 = true;
      }
      q = strchr(q, '\0');
      break;
 
    case GWC_REQ_UPDATE:
      /* ignore for now; who needs this anyway? */
      v2 = true;
      q = strchr(q, '\0');
      break;

    case GWC_REQ_STATFILE:
      if (*q != '1' || q[1] != '\0') {
        WARN("Request is not well-formed; expected '1'");
      }
      output_reqs++;
      q = strchr(q, '\0');
      break;
      
    case GWC_REQ_DATA:
      data_key = q;
      q = strchr(q, '\0');
      break;

    case GWC_REQ_NONE:
      INFO("Unknown request: \"%s\"", cmd);
      q = strchr(q, '\0');
      break;
    }

    if (error_msg != NULL)
      break;

    if (*q != '\0') {
      WARN("expected next request");
      ERROR_MSG("Expected next request");
      break;
    }
  }

  /* If there was an error check whether this was a V2.0 request */
  if (error_msg) {
    for (cmd = next; !v2 && cmd; cmd = next) {
      next = strchr(cmd, '&');
      if (next)
        *next++ = '\0';

      for (q = cmd; *q != '\0' && *q != '='; q++)
        *q = tolower((unsigned char) *q);
      *q++ = '\0';

      switch (map_string_to_req(cmd)) {
      case GWC_REQ_GET:
      case GWC_REQ_UPDATE:
        v2 = true;
        /* FALL THRU */
      default:
        break;
      }
    }
  }

  /* Count all requests; even invalid ones */
  stats_count_request(stats, request);

  /* "version=1.2.3" is obsolete since V2.0 */
  v2 |= *ctx->client_id != '\0' && *ctx->client_ver == '\0';
  v2 |= 2 == ctx->proto_ver;

  if (!OPTION(support_v2)) {
    /* Force v1 mode if support of v2.0 is disabled */
    v2 = false;
    request &= ~GWC_REQ_GET;
  }

  if (!network_supported(network)) {
    ERROR_MSG("Network not supported");
  }

  if (strlen(ctx->client_id) < 4 && !OPTION(allow_anonymous)) {
    ERROR_MSG("Anonymous requests are disallowed");
  }

  /* XXX: Just a hack */
  if (0 == strcmp(ctx->client_id, "GNUT")) {
    shutdown(connection_get_fd(ctx->con), SHUT_RDWR);
    ACCLOG_COMMIT(access_logger);
    return 0;
  }

  if (
      OPTION(late_filter) &&
      addr_filter &&
      addr_filter_match(addr_filter, connection_get_addr(ctx->con))
  ) {
    char buf[128];

    alert(connection_get_addr(ctx->con),
      ev_source_get_stamp(connection_get_source(ctx->con)),
      client_id(ctx, buf, sizeof buf), "Hostile");
    stats_count_blocked(stats);  
    shutdown(connection_get_fd(ctx->con), SHUT_RDWR);
    ACCLOG_COMMIT(access_logger);
    return 0;
  }
 
  if (OPTION(ban_bad_vendors)) {
    static const struct {
      const char *id;
    } vendors[] = {
      { "DNET" },
      { "MLDK" },
      { "MMMM" },
      { "MRPH" },
      { "MUTE" },
      { "RAZA" },
    };
    unsigned i;

    for (i = 0; i < ARRAY_LEN(vendors); i++)
      if (0 == strcmp(ctx->client_id, vendors[i].id)) {
#if 1
        shutdown(connection_get_fd(ctx->con), SHUT_RDWR);
        ACCLOG_COMMIT(access_logger);
        return 0;
#else
        ERROR_MSG("Vendor non grata");
        break;
#endif
      }
  }
    
  if (error_msg) {
    gwc_return_error(ctx, error_msg);
    return 0;
  }

  if (GWC_REQ_DATA & request) {
    RUNTIME_ASSERT(data_key != NULL);
    if (!OPTION(data_key) || 0 == strcmp(data_key, OPTION(data_key))) {
      client_process_data_request(ctx);
    } else {
      gwc_return_error(ctx, "Access denied");
    }
    return 0;
  }

  /* Don't apply limits to "statfile" requests. An error message is even
   * longer and you'd lose the ability to easily monitor Crab. */
  if (GWC_REQ_STATFILE & request) {
    client_process_statfile_request(ctx);
    return 0;
  }

  {
    net_addr_t addr = connection_get_addr(ctx->con);
    struct timeval now = ev_source_get_stamp(connection_get_source(ctx->con));
    bool is_update = request & (GWC_REQ_IP | GWC_REQ_URL);
    bool is_req = request & (GWC_REQ_GET | GWC_REQ_URLFILE | GWC_REQ_HOSTFILE);
   
    if (
        (is_update && peer_lock_set_locked(update_locks, addr, now.tv_sec)) ||
        (is_req && peer_lock_set_locked(request_locks, addr, now.tv_sec))
    ) {
      static const char msg[] = "Client returned too early";

      stats_count_too_early(stats);
      
      if (!v2 || !is_update) {
        gwc_return_error(ctx, msg);
      } else {
        char buf[2048], *p = buf;
        size_t size = sizeof buf;
        
        if (2 != ctx->proto_ver)
          p = APPEND_STATIC_CHARS(p, &size, "OK\r\n");

        p = client_process_update_warning(ctx, msg, p, &size);
        p = client_append_extra_data(ctx, true, p, &size);
        http_send_text(&ctx->http, buf, p - buf);
      }

      return 0;
    }

    if (is_update)
      peer_lock_set_add(update_locks, addr, now.tv_sec);
    if (is_req)
      peer_lock_set_add(request_locks, addr, now.tv_sec);
  }

  if (OPTION(send_x_remote_ip)) {
    char *p = ctx->x_remote_ip;
    size_t size = sizeof ctx->x_remote_ip;
    net_addr_t addr = connection_get_addr(ctx->con);

    p = APPEND_STATIC_CHARS(p, &size, "X-Remote-IP: ");
    print_net_addr(p, size, addr);

    http_add_header(&ctx->http, ctx->x_remote_ip);
  }

  if (OPTION(send_x_gwc_url)) {
    char *p = ctx->x_gwc_url;
    size_t size = sizeof ctx->x_gwc_url;

    p = APPEND_STATIC_CHARS(p, &size, "X-GWC-URL: ");
    p = append_string(p, &size, OPTION(gwc_url));

    http_add_header(&ctx->http, ctx->x_gwc_url);
  }

  if (v2) {
    gwc_cache_t *gcache = checker_get_good_cache();
    peer_cache_t *pcache = peer_cache;
    char buf[BUFFERSIZE], *p = buf;
    size_t size = sizeof buf;
   
    if (GWC_REQ_GET & request) {
      size_t len;

      if (GWC_REQ_PING & request) {
        len = client_process_v2_ping_request(ctx, p, size);
        p += len;
        size -= len;
      }
      len = client_process_get_request(ctx, p, size, gcache, pcache);
      RUNTIME_ASSERT(len <= size);
      p += len;
      size -= len;
    } else if (GWC_REQ_HOSTFILE & request) {
       client_process_hostfile_request(ctx, pcache, gcache);
       ret = true;
    } else if (GWC_REQ_URLFILE & request) {
       client_process_urlfile_request(ctx, gcache);
       ret = true;
    }
    
    if (GWC_REQ_IP & request) {
      ip_msg = client_process_ip_request(ctx, pcache, ip_req_host);
      if (ip_msg)
        p = client_process_update_warning(ctx, ip_msg, p, &size);
    }
    
    if (GWC_REQ_URL & request) {
      url_msg = client_process_url_request(ctx, url_req_uri);
      if (url_msg)
        p = client_process_update_warning(ctx, url_msg, p, &size);
    }
   
    if ((GWC_REQ_IP | GWC_REQ_URL) & request) {

      if (!url_msg && !ip_msg) {
        p = APPEND_STATIC_CHARS(p, &size, "I|update|OK\r\n");
        stats_count_update(stats, request);
      }

    }

    if (p == buf) {
      size_t len;
      
      len = client_process_v2_ping_request(ctx, p, size);
      p += len;
      size -= len;
    }
   
    if (!ret)
      http_send_text(&ctx->http, buf, p - buf);
      
  } else {
    bool update = false, update_ok;
    gwc_cache_t *gcache = checker_get_good_cache();
    peer_cache_t *pcache = peer_cache;

    if (output_reqs > 1) {
      /* Pick one of the requests */
      if (GWC_REQ_HOSTFILE & request) {
        request = GWC_REQ_HOSTFILE;
      } else if (GWC_REQ_URLFILE & request) {
        request = GWC_REQ_URLFILE;
      }  else if (GWC_REQ_PING & request) {
        request = GWC_REQ_PING;
      } else {
        ret = true;
      }
    }

    if (GWC_REQ_PING & request) {
      client_process_ping_request(ctx);
      ret = true;
    } else if (GWC_REQ_HOSTFILE & request) {
      client_process_hostfile_request(ctx, pcache, gcache);
      ret = true;
    } else if (GWC_REQ_URLFILE & request) {
      client_process_urlfile_request(ctx, gcache);
      ret = true;
    }

    if (GWC_REQ_URL & request) {
      url_msg = client_process_url_request(ctx, url_req_uri);
      update = true;
    }

    if (GWC_REQ_IP & request) {
      ip_msg = client_process_ip_request(ctx, pcache, ip_req_host);
      update = true;
    }

    update_ok = update && !ip_msg && !url_msg;
    if (update_ok) {
      stats_count_update(stats, request);
    }
   
    if (ret)
      return 0;

    if (update_ok) {
      char buf[2048], *p = buf;
      size_t size = sizeof buf;

      p = APPEND_STATIC_CHARS(p, &size, "OK\r\n");
      p = client_append_extra_data(ctx, true, p, &size);
      http_send_text(&ctx->http, buf, p - buf);
    } else {
      char buf[2048], *p = buf;
      size_t i, size = sizeof buf;
      const char *msg[2];
      
      msg[0] = ip_msg;
      msg[1] = url_msg;
      
      for (i = 0; i < ARRAY_LEN(msg); i++) {
        if (NULL != msg[i])
          p = client_process_update_warning(ctx, msg[i], p, &size);
      }
         
      p = client_append_extra_data(ctx, true, p, &size);
      http_send_text(&ctx->http, buf, p - buf);
    }

  }
  
  return 0;
}
#undef ERROR_MSG

/* client_process_request:
 *
 * XXX: This should be handled in http.c
 *
 *  Returns:
 *    (-1) in case of a fatal error (see http status for details)
 *    0 if the request is completely parsed (continue with headers)
 */
static int
client_process_request(client_t *ctx, char *query, size_t query_size)
{
  char line[BUFFERSIZE];
  char *p = NULL;
  char *q = NULL;
  char *endptr = NULL;
  ssize_t size, pos;
  char *search;
   
  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(query);
  RUNTIME_ASSERT(query_size > 0);
  RUNTIME_ASSERT(ctx->http.state == HTTP_STATE_REQUEST);

  if (ctx->http.debug_dump_headers) {
    INFO("request from %s:%u:",
      connection_get_addrstr(ctx->con, line, sizeof line),
      (unsigned) connection_get_port(ctx->con));
  }

  pos = fifo_findchar(ctx->input, '\n', sizeof line);
  if ((ssize_t) -1 == pos) {
    size = fifo_read(ctx->input, line, sizeof line - 1);
    RUNTIME_ASSERT((size_t) size < sizeof line);
    line[size] = '\0';
    DBUG("Request URI too long (%d bytes): \"%s\"", (int) size, line);
    http_set_status(&ctx->http, 414, "Request-URI Too Long");
    return -1;
  }
  
  RUNTIME_ASSERT(pos >= 0 && pos < (ssize_t) sizeof line);
  size = fifo_read(ctx->input, line, pos + 1);
  RUNTIME_ASSERT(size == pos + 1);
  RUNTIME_ASSERT(line[pos] == '\n');

  q = &line[pos];
  /* eat all trailing spaces */
  while (q >= line && isspace((unsigned char) *q))
    q--;

  q++;
  RUNTIME_ASSERT(isspace((unsigned char) *q));
  *q = '\0';
  
  ACCLOG_SET(ctx->http.acclog, request, line);

  for (p = line; p < q; p++) {
    int c = (unsigned char) *p;

    if (c == '\0') {
      CRIT("NUL-character in request line at column %u: \"%s\"",
          (unsigned) (p - line), line);
      goto bad_request;
    } else if (c < 32 || c >= 127) {
      CRIT("Unsafe character in request line at column %u: \"%s\"",
          (unsigned) (p - line), line);
      goto bad_request;
    }
  }

  if (q - line < (ssize_t) sizeof "X / HTTP/1.1" - 1) {
    WARN("Too short to be useful");
    goto bad_request;
  }
  if (!isalnum((unsigned char) line[0]))
    goto bad_request;
  
  p = skip_non_spaces(line);
  if (!isspace((unsigned char) *p)) {
    WARN("Method token must be followed by a whitespace");
    goto bad_request;
  }
  *p++ = '\0'; /* p points to whitespaces or parameter after GET resp. HEAD */

  if (http_get_request_method(&ctx->http, line) == HTTP_REQ_UNKNOWN) {
    WARN("Invalid or unsupported request");
  } else if (ctx->http.request == HTTP_REQ_CONNECT) {
    /* In a CONNECT request, the Host header has to be set to the target
     * host. Since this is not a proxy, ignore the value to give more
     * reasonable error messages later. */
    ctx->ignore_host_header = true;
  }

  p = skip_spaces(p); /* eat spaces after GET */
  q = skip_non_spaces(p); /* find end of URI */
  
  if (*q == '\0') {
    WARN("no space followed by HTTP/X.Y after URI");
    goto bad_request;
  }

  *q++ = '\0';  /* mark end of URI */
  q = skip_spaces(q); /* eat spaces after URI */

  endptr = http_parse_version(&ctx->http, q);
  if (!endptr) {
    goto bad_request;
  }

  if (*endptr != '\0') {
    WARN("non-space characters trailing");
    goto bad_request;
  }

  /* The '?' must be searched for in any case, so that '?' is overwritten
   * with a NUL and the URI matches. */
  search = strchr(p, '?');
  if (search) {
     *search++ = '\0';
  }

  if (ctx->http.request == HTTP_REQ_GET) {
    /* Ignore the search if this is not a GET request */
    ctx->has_search = NULL != search;
  }

  if (!url_decode(line, p, sizeof line)) {
    WARN("URI is invalid encoded");
    goto bad_request;
  }
  p = line;

  if (0 == strcmp(OPTION(gwc_uri), p)) {
    ctx->http.uri = OPTION(gwc_uri);
  } else if (0 == strcmp(OPTION(gwc_url), p)) {
    ctx->http.uri = OPTION(gwc_url);
    /* Ignore the value of the Host header if the request featured an
     * absolute URI (according to RFC 2616 5.4.1) */
    ctx->ignore_host_header = true;
  } else {
    /* Wrong URI */
    ctx->http.uri = NULL;
    http_set_status(&ctx->http, 404, "Not Found");
    /* Don't abort already so we can peek at the headers */
  }

  if (ctx->has_search) {
    RUNTIME_ASSERT(search != NULL);
    append_string(query, &query_size, search);
  }

  ctx->http.state = HTTP_STATE_HEADERS;
  return 0;

bad_request:
  
  http_set_status(&ctx->http, 400, "Bad Request");
  return -1;
}

/* client_process_input:
 *
 *  Returns:
 *    (-1) in case of an error (send pending data and close connection)
 *    0 if the request was completely handled (send data and close connection)
 */
static int
client_process_input(client_t *ctx)
{
  int ret;
  char query[BUFFERSIZE];

  query[0] = '\0';
  
  if (ctx->http.state == HTTP_STATE_REQUEST) {
    ret = client_process_request(ctx, query, sizeof query);
    if (ret) {
      RUNTIME_ASSERT(ctx->http.status_code >= 100 && ctx->http.status_code < 600);
      http_send_empty_reply(&ctx->http);
      return -1;
    }
    RUNTIME_ASSERT(ret == 0);
    RUNTIME_ASSERT(ctx->http.state == HTTP_STATE_HEADERS);
  }
  RUNTIME_ASSERT(ctx->http.state != HTTP_STATE_REQUEST);

  if (ctx->http.state == HTTP_STATE_HEADERS) {
    char headers[2 * BUFFERSIZE];

    ret = http_process_headers(&ctx->http, headers, sizeof headers);
    ctx->http.keep_alive = false; /* Suppress keep-alive completely */
    if (ret) {
      RUNTIME_ASSERT(ctx->http.status_code >= 100);
      RUNTIME_ASSERT(ctx->http.status_code < 600);

      http_send_empty_reply(&ctx->http);
      return -1;
    }
    RUNTIME_ASSERT(ret == 0);
    shutdown(connection_get_fd(ctx->con), SHUT_RD);
  }
  RUNTIME_ASSERT(ctx->http.state == HTTP_STATE_BODY);

 
  /* The Host header is checked before the HTTP method because (in theory)
   * this could be a virtual host and we shouldn't claim anything about the
   * supported methods of other hosts. */
  if (!ctx->ignore_host_header) {
    if (!ctx->http.host) {
      http_set_status(&ctx->http, 400, "Bad Request (Missing Host Header)");
    } else if (0 != ctx->http.port && OPTION(gwc_port) != ctx->http.port) {
      http_set_status(&ctx->http, 400, "Bad Request (Wrong Port)");
    } else if (0 != strcmp(ctx->http.host, OPTION(gwc_fqdn))) {
      http_set_status(&ctx->http, 400, "Bad Request (Wrong Host)");
    }

    if (400 == ctx->http.status_code) {
      http_send_empty_reply(&ctx->http);
      return -1;
    }
  }
  
  if (ctx->http.request != HTTP_REQ_GET && ctx->http.request != HTTP_REQ_HEAD) {
    http_set_status(&ctx->http, 501, "Not Implemented");
    http_send_empty_reply(&ctx->http);
    return -1;
  }

  /* The URI is checked after the HTTP method because the semantics depend
   * on the method and reporting a 404 for a unknown resp. unimplemented
   * method would be wrong. */
  if (!ctx->http.uri) {
    http_set_status(&ctx->http, 404, "Not Found");
    http_send_empty_reply(&ctx->http);
    return -1;
  }

  if (HTTP_REQ_HEAD == ctx->http.request) {
    http_send_head_reply(&ctx->http);
    return 0;
  }

  if (!ctx->has_search) {
    stats_count_request(stats, GWC_REQ_NONE);
    client_process_base_request(ctx);
    return 0;
  }

  return client_process_query(ctx, query) ? -1 : 0;
}

static void
client_log_error(connection_t *c, const char *s, int error)
{
    char addr[NET_ADDR_BUFLEN];

    connection_get_addrstr(c, addr, sizeof addr);
    VERB("%s:%u %s%s%s",
        addr,
        connection_get_port(c),
        s,
        error ? ": " : "",
        error ? compat_strerror(error) : "");
}

static client_t *
create_client_context(connection_t *c)
{
  client_t *client;
  
  RUNTIME_ASSERT(c != NULL);
  
  client = client_new(c, watcher, OPTION(request_max_size), 0);
  if (client) {
    http_ctx_init(&client->http, client->input);
    client->http.log_cb = main_logv;
    client->http.incoming = true;
    client->http.debug_dump_headers = OPTION(http_dump_headers);
    client->http.output = &client->http_out;
  } 

  return client;
}
 
static void
handle_close(connection_t *c)
{
  client_t *client;

  client = connection_get_context(c);
  if (client) {
    if (!client->finished) {
      alert(connection_get_addr(c),
          ev_source_get_stamp(connection_get_source(c)), NULL,
          0 != client->rx_count ? "Trash" : "Scan");
    }
    stats_count_rx(stats, client->rx_count);
    stats_count_tx(stats, client->tx_count);

    switch (client->http.status_code) {
    case 400: stats_count_http_400(stats); break;
    case 404: stats_count_http_404(stats); break;
    }
    http_destruct(&client->http);
    client_destruct(client);
    connection_set_context(c, NULL);
  }

  RUNTIME_ASSERT(num_connections > 0);
  num_connections--;
  connection_close(c);
  connection_unref(c);

  if (
    num_connections < max_connections && 
    (
      0 == OPTION(max_accepts_per_sec) ||
      num_incoming < OPTION(max_accepts_per_sec)
    )
  ) {
    if (
      listen_con &&
      ev_source_get_eventmask(connection_get_source(listen_con)) != EVT_READ &&
      ev_watcher_watch_source(watcher,
        connection_get_source(listen_con), EVT_READ)
    ) {
      WARN("ev_watcher_watch_source() failed");
    }
    if (
      listen6_con &&
      ev_source_get_eventmask(connection_get_source(listen6_con)) != EVT_READ &&
      ev_watcher_watch_source(watcher,
        connection_get_source(listen6_con), EVT_READ)
    ) {
      WARN("ev_watcher_watch_source() failed");
    }
  }
}

static void
handle_timeout(connection_t *c, ev_type_t ev)
{
  if (
    !(ev & EVT_TIMEOUT) &&
    ev_source_get_age(connection_get_source(c)) <= OPTION(max_connect_time)
  ) {
    return;
  }

  handle_close(c);
}

static void
handle_error(connection_t *c, ev_type_t ev)
{
  if (ev & EVT_ERROR) {
    char addr[NET_ADDR_BUFLEN];
    int fd = connection_get_fd(c), error;
    socklen_t error_len = sizeof error;
    
    connection_get_addrstr(c, addr, sizeof addr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len)) {
      WARN("handle_error: (fd=%d, addr=%s) [getsockopt failed: %s]",
        fd, addr, compat_strerror(errno));
    } else if (error != ECONNRESET) {
      WARN("handle_error: (fd=%d, addr=%s): %s",
        fd, addr, compat_strerror(error));
      client_log_error(c, "connection error", error);
    }
  }
}

static void
handle_write(connection_t *c, ev_type_t ev)
{
  client_t *client;
  ssize_t ret;

  if (ev & EVT_ERROR) {
    handle_error(c, ev);
    goto close_connection;
  }

  if (ev & EVT_HANGUP) {
    alert(connection_get_addr(c),
      ev_source_get_stamp(connection_get_source(c)), NULL, "Hangup");
    goto close_connection;
  }

  if (ev & EVT_WRITE) {
    client = connection_get_context(c);
    RUNTIME_ASSERT(client != NULL);
    RUNTIME_ASSERT(client->finished);

    if (!client_has_output(client)) {
      goto close_connection;
    }

    ret = client_send(client);
    if (0 == ret) {
      client_log_error(c, "client_send() returned zero", 0);
      goto close_connection;
    } else if ((ssize_t) -1 == ret) {
      if (!is_temporary_error(errno)) {
        client_log_error(c, "client_send() failed", errno);
        goto close_connection;
      }
    }

    if (!client_has_output(client)) {
      goto close_connection;
    }
  }
  
  handle_timeout(c, ev); /* Check for timeouts and close if necessary */
  return;

close_connection:
  
  handle_close(c);
}

static void
handle_read(connection_t *c, ev_type_t ev)
{
  if (ev & EVT_ERROR) {
    handle_error(c, ev);
    goto close_connection;
  }

  if (ev & (EVT_READ | EVT_HANGUP)) {
    ssize_t off, ret;
    client_t *client;
    bool ready;
   
    client = connection_get_context(c);
    if (!client) {
      client = create_client_context(c);
      if (!client) {
        client_log_error(c, "could not create client context", errno);
        goto close_connection;
      }
      connection_set_context(c, client);
    }
    RUNTIME_ASSERT(client != NULL);

    ret = fifo_fill(client->input);
    off = ((size_t) ret < 3) ? 0 : ret - 3;
    
    ret = client_recv(client);
    if (ret == (ssize_t) -1) {
      if (!is_temporary_error(errno)) {

        if (ECONNRESET != errno) {
          client_log_error(c, "read() failed", errno);
        }

        goto close_connection;
      }
    } else if (ret == 0) {
      /*
       * The connection is probably only half-closed. Therefore, we don't
       * abort but mark the connection as closed and handle the request.
       */
        
      if (fifo_empty(client->input)) {
        goto close_connection;
      }

      client->closed = true;
    }

    if (fifo_full(client->input)) {
      client->closed = true;
    }

    ready = (ssize_t) -1 != fifo_findstr(client->input, "\n\r\n", off) ||
      (ssize_t) -1 != fifo_findstr(client->input, "\n\n", off);

    if (ready) {
      struct timeval tv;
      bool closed;

      tv = ev_source_get_stamp(connection_get_source(c));
      ACCLOG_RESET(access_logger);
      ACCLOG_SET(access_logger, addr, connection_get_addr(c));
      ACCLOG_SET(access_logger, stamp, tv.tv_sec);
      client->http.acclog = access_logger;
      client_process_input(client);
      client->finished = true;

      fifo_destruct(client->input);
      client->input = NULL;

      connection_ref(c);
      handle_write(c, EVT_WRITE);
      closed = connection_is_closed(c);
      connection_unref(c);
      
      if (closed) {
        return;
      }
      connection_set_event_cb(c, handle_write);
      if (
        ev_watcher_watch_source(watcher, connection_get_source(c), EVT_WRITE)
      ) {
          WARN("ev_watcher_watch_source() failed");
      }
    } else {
      /* If we need more input check whether the client is still connected */
      if (client->closed)
        goto close_connection;
    }
  }

  handle_timeout(c, ev); /* Check for timeouts and close if necessary */
  return;
 
close_connection:

  handle_close(c);
}

static void
handle_incoming(connection_t *listen_c, ev_type_t ev)
{
  connection_t *c;

  RUNTIME_ASSERT(listen_c == listen_con || listen_c == listen6_con);
  
  if (!(EVT_READ & ev)) {
    return;
  }

  stats_count_accept(stats);
  c = connection_accept(listen_c);

  if (!c) {
    if (errno == EMFILE || errno == ENFILE) {
      max_connections = num_connections > 5 ? num_connections - 5 : 1;
      DBUG("Setting number of maximum connections to %d", max_connections);
      ev_watcher_watch_source(watcher,
        connection_get_source(listen_c), EVT_NONE);
    }
    return;
  }
 
  if (num_incoming < INT_MAX) {
    num_incoming++;
  }
  if (
    OPTION(max_accepts_per_sec) > 0 &&
    num_incoming >= OPTION(max_accepts_per_sec) &&
    ev_watcher_watch_source(watcher, connection_get_source(listen_c), EVT_NONE)
  ) {
    WARN("ev_watcher_watch_source() failed");
  }
  num_connections++;
  
  connection_ref(c);
  if (
      !OPTION(late_filter) &&
      addr_filter &&
      addr_filter_match(addr_filter, connection_get_addr(c))
  ) {
    alert(connection_get_addr(c),
        ev_source_get_stamp(connection_get_source(c)), NULL, "Hostile");
    stats_count_blocked(stats);  
    handle_close(c);
  } else {
    const client_t *listen_ctx;

    listen_ctx = connection_get_context(listen_c);
    RUNTIME_ASSERT(listen_ctx->watcher == watcher);

    connection_set_event_cb(c, handle_read);
    ev_source_set_timeout(connection_get_source(c), OPTION(idle_timeout));

    /* Maybe this should depend on whether accept_http_filter() is active. If
     * it's active though, it's unlikely that the read() will fail.
     */
    handle_read(c, EVT_READ);
    if (
      !connection_is_closed(c) &&
      ev_source_get_eventmask(connection_get_source(c)) == EVT_NONE &&
      ev_watcher_watch_source(watcher, connection_get_source(c), EVT_READ)
    ) {
      WARN("ev_watcher_watch_source() failed");
    }
  }
  connection_unref(c);

  if (
    num_connections >= max_connections &&
    ev_watcher_watch_source(watcher, connection_get_source(listen_c), EVT_NONE)
  ) {
      WARN("ev_watcher_watch_source() failed");
  }

  return;
}

void
webcache_save(void)
{
  if (OPTION(support_gwc)) {
    checker_save_cache(checker_get_good_cache(), OPTION(good_url_cache));
    checker_save_cache(checker_get_bad_cache(), OPTION(bad_url_cache));
  }
  peer_cache_save(peer_cache, OPTION(peer_cache));
}

static void
webcache_setup_listener(connection_t *c)
{
  client_t *ctx;

  RUNTIME_ASSERT(watcher != NULL);

  connection_set_blocking(c, false);

  /* This filters out client which send no HTTP requests */
  connection_accept_http_filter(c);
  
  /* Merges the TCP-ACK for the request with the HTTP response (TCP_QUICKACK) */
  connection_set_quick_ack(c, false);
 
  /* This is utilized for the same effect on FreeBSD (TCP_NOPUSH) */
  connection_set_nopush(c, true);

  if (OPTION(tcp_defer_accept_timeout)) {
    connection_set_defer_accept(c, OPTION(tcp_defer_accept_timeout));
  }
  if (OPTION(tcp_rcvbuf_size)) {
    connection_set_rcvbuf(c, OPTION(tcp_rcvbuf_size));
  }
  if (OPTION(tcp_sndbuf_size)) {
    connection_set_sndbuf(c, OPTION(tcp_sndbuf_size));
  }

  ctx = client_new(c, watcher, 0, 0);
  RUNTIME_ASSERT(ctx);

  connection_set_event_cb(c, handle_incoming);
  connection_set_context(c, ctx);
  ev_watcher_watch_source(watcher, connection_get_source(c), EVT_READ);
}

static int 
gwc_init(connection_t *listen_c, connection_t *listen6_c,
    int query_fd, int reply_fd)
{
  RUNTIME_ASSERT(watcher != NULL);
  RUNTIME_ASSERT(listen_c != NULL || listen6_c != NULL);
  
  listen_con = listen_c;
  listen6_con = listen6_c;

  if (checker_initialize(watcher, query_fd, reply_fd)) {
    CRIT("Could not launch GWC checker");
    return -1;
  }

  if (listen_con) {
    webcache_setup_listener(listen_con);
  }
  if (listen6_con) {
    webcache_setup_listener(listen6_con);
  }

  if (OPTION(base_template)) {
    INFO("Loading data template from \"%s\"", OPTION(base_template));
    base_template = template_load(OPTION(base_template));
  }

  if (OPTION(data_template)) {
    INFO("Loading data template from \"%s\"", OPTION(data_template));
    data_template = template_load(OPTION(data_template));
  }

  if (OPTION(address_filter)) {
    INFO("Loading address filter from \"%s\"", OPTION(address_filter));
    addr_filter = addr_filter_load(OPTION(address_filter));
    checker_set_address_filter(addr_filter);
  }

  if (OPTION(log_access)) {
    FILE *f;

    f = safer_fopen(OPTION(log_access), SAFER_FOPEN_APPEND);
    if (!f) {
      CRIT("Could not open log_access (\"%s\"): %s",
          OPTION(log_access), compat_strerror(errno));
      return -1;
    }
    access_logger = acclog_new(f);
  }

  if (OPTION(log_alert)) {
    alert_logger = safer_fopen(OPTION(log_alert), SAFER_FOPEN_APPEND);
    if (!alert_logger) {
      CRIT("Could not open log_alert (\"%s\"): %s",
          OPTION(log_alert), compat_strerror(errno));
      return -1;
    }
  }

  INFO("Loading good GWCs from \"%s\"", OPTION(good_url_cache));
  checker_load_cache(checker_get_good_cache(), OPTION(good_url_cache));
  INFO("Loading bad URLs from \"%s\"", OPTION(bad_url_cache));
  checker_load_cache(checker_get_bad_cache(), OPTION(bad_url_cache));

  update_locks = peer_lock_set_new(2000, OPTION(gwc_lock_time), 1);
  request_locks = peer_lock_set_new(2000, OPTION(gwc_lock_time), 3);
  if (!update_locks || !request_locks) {
    CRIT("Out of memory");
    return -1;
  }

  return 0;
}

static void
initialize_random(void)
{
  struct timeval tv;
  unsigned long seed;
  
  compat_mono_time(&tv);
  seed = (tv.tv_usec << 16)
    ^ (getpid() + 101 * getuid() + ~gethostid())
    ^ (tv.tv_sec << 13)
    ^ ((unsigned long) &tv >> 5);

  INFO("seed=%#08lx", seed);
  srandom(seed);
}

static void
webcache_throttle_accept(void)
{
  static struct timeval before;
  struct timeval tv;
  
  if (!OPTION(support_gwc) || 0 == OPTION(max_accepts_per_sec)) {
    return;
  }
  compat_mono_time(&tv);
  if (before.tv_sec && DIFFTIMEVAL(&tv, &before) < 1000000) {
    return;
  }
  
  if (num_connections < max_connections) {
    if (
      listen_con &&
      ev_source_get_eventmask(connection_get_source(listen_con)) != EVT_READ &&
      ev_watcher_watch_source(watcher,
          connection_get_source(listen_con), EVT_READ)
    ) {
      WARN("ev_watcher_watch_source() failed");
    }
    if (
      listen6_con &&
      ev_source_get_eventmask(connection_get_source(listen6_con)) != EVT_READ &&
      ev_watcher_watch_source(watcher,
        connection_get_source(listen6_con), EVT_READ)
    ) {
      WARN("ev_watcher_watch_source() failed");
    }
  }
  
  num_incoming = 0;
  before = tv;
}

static void
periodic_handler(ev_watcher_t *unused_watcher, const struct timeval *now)
{
  static struct timeval last;
  
  (void) unused_watcher;
  RUNTIME_ASSERT(now);

  if (!last.tv_sec)
    last = *now;
  
  if (sighup_received) {
    sighup_received = 0;
    if (reopen_logs())
      exit(EXIT_FAILURE);
  }
  
  if (shutdown_request) {
    terminate();
    /* NOTREACHED */
    RUNTIME_ASSERT(0);
  }

  webcache_throttle_accept();

  if (DIFFTIMEVAL(now, &last) > 1000000) {
    static struct timeval last_save;
    
    last = *now;
    log_time_mark(now->tv_sec);

    /* Flush log files */
    fflush(NULL);

    ACCLOG_FLUSH(access_logger);
    stats_update(stats, last);
   
    if (OPTION(support_uhc)) {
      const peer_t *peerv[10], *p;
      net_addr_t addr;
      in_port_t port;

      p = get_removed_peer();
      if (p) {
        uhc_send_ping(p->addr, p->port);
      } else {
        /* Read from the cache to trigger removal of old peers */
        peer_cache_get(peer_cache, peerv, ARRAY_LEN(peerv),
            now->tv_sec, net_addr_unspecified);
      }
      
      /* Retrieve a peer from the secondary UHC cache which contains
       * peers collected from UHC IPP pongs */
      if (uhc_get_secondary(&addr, &port)) {
        uhc_send_ping(addr, port);
      }

    }
        
    if (!last_save.tv_sec)
      last_save = *now;

    if (difftime(now->tv_sec, last_save.tv_sec) >= SAVE_INTERVAL) {
      webcache_save();
      last_save = *now;
    }
  }

}

int
webcache_init(ev_watcher_t *w,
    connection_t *listen_c, connection_t *listen6_c,
    connection_t *udp_con, connection_t *udp6_con,
    int query_fd, int reply_fd)
{
  struct timeval now;
  
  RUNTIME_ASSERT(w != NULL);
  watcher = w;

  if (setup_signal_handlers()) {
    return -1;
  }
  
  compat_mono_time(&now);
  stats = stats_init(now);
  if (!stats) {
    CRIT("stats_init() failed");
    return -1;
  } 

  if (OPTION(support_gwc)) {
    if (gwc_init(listen_c, listen6_c, query_fd, reply_fd)) {
      CRIT("gwc_init() failed");
      return -1;
    }
  }

  peer_cache = peer_cache_new(OPTION(max_cached_peers), MAX_PEER_AGE);
  if (!peer_cache) {
    CRIT("peer_cache_new() failed");
    return -1;
  }

  if (udp_con || udp6_con) {
    if (uhc_init(watcher, udp_con, udp6_con)) {
      CRIT("uhc_init() failed");
      return -1;
    }
    uhc_set_filter(addr_filter);
    uhc_set_peercache(peer_cache);
    peer_cache_set_removed_callback(peer_cache, peer_removed);
  }
  
  peer_cache_set_filter(peer_cache, addr_filter);
  {
    const char *path = OPTION(peer_cache);
    size_t max_items = OPTION(max_cached_peers);
    
    peer_cache_load(peer_cache, path, max_items);
  }
  
  ev_watcher_set_periodic_cb(watcher, periodic_handler);
  initialize_random(); 
  return 0;
}

int
webcache_reopen_logs(void)
{
  if (checker_log_reopen()) {
    CRIT("checker_reopen_logs() failed: \"%s\"", compat_strerror(errno));
    return -1;
  }
  
  if (access_logger) {
    FILE *f;
    
    f = access_logger->get_stream(access_logger);
    if (!freopen(OPTION(log_access), "w", f)) {
      CRIT("freopen() failed for log_access: %s", compat_strerror(errno));
      return -1;
    }
  }

  if (alert_logger) {
    if (!freopen(OPTION(log_alert), "w", alert_logger)) {
      CRIT("freopen() failed for log_alert: %s", compat_strerror(errno));
      return -1;
    }
  }

  return 0;
}

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
