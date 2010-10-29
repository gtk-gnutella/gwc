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

/* Tactics:
 *
 * Crab sends a "ping" request followed by a "urlfile" resp. "get" request.
 * This way we can get rid of dead caches and those that return static files.
 * As long as the ping request is proceeding the status quo is reserved and
 * the lease is extended. If any of the checks fails, the URL is moved to the
 * set of bad caches.
 */

#include "lib/http.h"
#include "lib/nettools.h"
#include "lib/gwc.h"
#include "lib/oop.h"
#include "lib/append.h"
#include "lib/hashtable.h"

#include "checker.h"
#include "dnshelper.h"
#include "options.h"

static const options_t *opts_;
#define OPTION(x) ((opts_ != NULL ? opts_ : (opts_ = options_get()))->x)

static FILE *log_file;

static const char get_req_str[] = 
    "?get=1&client=TEST&version=Crab-" GWC_CLIENT_VERSION;
static const char ping_req_str[] = 
    "?ping=1&client=TEST&version=Crab-" GWC_CLIENT_VERSION;
static const char urlfile_req_str[] = 
    "?urlfile=1&client=TEST&version=Crab-" GWC_CLIENT_VERSION;

#define MAX_REQ_SIZE (256 + sizeof urlfile_req_str)

static gwc_cache_t *bad_cache;
static gwc_cache_t *good_cache;

static connection_t *dns_reply_con = NULL;
static connection_t *dns_query_con = NULL;

static ev_watcher_t *watcher = NULL;
static struct addr_filter *addr_filter = NULL;

static const char *from_header;

typedef struct {
  hash_t  hash;
  size_t  count;
  char    *url;
} url_hash_t;

/* Number of URLs which will be parsed at maximum per urlfile request */
#define MAX_URLS_PER_URLFILE 128

typedef enum {
  URL_CHECK_MAGIC = 0x7f12d87e
} url_check_magic_t;

typedef enum {
  CHECK_PING    = 1,
  CHECK_URLFILE = 2,
  CHECK_GET     = 3
} check_t;

typedef struct {
  url_check_magic_t magic;

  client_t	    *client;
  char              *host;
  char              *url;
  hash_t            url_hash;
  size_t            queue_pos;
  http_t            http;
  fifo_t            *buffer;
  bool              closed;
  bool              bad;
  bool              pong;
  check_t           check;
  url_hash_t        urlfile[MAX_URLS_PER_URLFILE];
} url_check_ctx_t;

#define MAX_PENDING_CHECKS 256
hashtable_t *pending_checks;

static void gwc_check_event(connection_t *, ev_type_t);
static int gwc_urlfile_check_read_body(url_check_ctx_t *);
static int gwc_ping_check_read_body(url_check_ctx_t *);
static int gwc_get_check_read_body(url_check_ctx_t *);

#define TIME_MARK_DELAY 60

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
    fprintf(log_file, "<<< %s >>>\n", date);
    fflush(log_file);
  }
}

static void
checker_logv(const char *fmt, va_list ap)
{
  if (OPTION(log_checks)) {
    RUNTIME_ASSERT(log_file != NULL);
    log_time_mark(0);
    vfprintf(log_file, fmt, ap);
    fputs("\n", log_file);
    fflush(log_file);
  }
}

static void
checker_log(const char *fmt, ...) CHECK_FMT(1, 2);

static void
checker_log(const char *fmt, ...)
{
  va_list ap;

  if (OPTION(log_checks)) {
    int saved_errno = errno;
    
    RUNTIME_ASSERT(log_file != NULL);
    
    va_start(ap, fmt);
    checker_logv(fmt, ap);
    va_end(ap);
    
    errno = saved_errno;
  }
}

int
checker_log_reopen(void)
{
  if (!OPTION(log_checks))
    return 0;

  log_file = log_file != NULL
    ? freopen(OPTION(log_checks), "a", log_file)
    : safer_fopen(OPTION(log_checks), SAFER_FOPEN_APPEND);

  if (!log_file)
    return -1;
  
  checker_log("Reopened log file");
  return 0;
}

static bool
url_cmp(const void *p, const void *q)
{
  const char *a = p, *b = q;

  RUNTIME_ASSERT(a != NULL);
  RUNTIME_ASSERT(b != NULL);
  return a == b || 0 == strcmp(a, b);
}

static uint32_t
url_hash(const void *p)
{
  const char *s = p;

  RUNTIME_ASSERT(s != NULL);
  return hash_str(s);
}

static url_check_ctx_t *
pending_check(const char *url)
{
  void *ptr;

  if (hashtable_get(pending_checks, url, &ptr))
    return ptr;

  return NULL;
}

url_check_ctx_t *
url_check_ctx_new(client_t *client,
    const char *host, const char *url, check_t chk)
{
  url_check_ctx_t *ctx;

  client_check(client);
  RUNTIME_ASSERT(host != NULL);
  RUNTIME_ASSERT(url != NULL);
  RUNTIME_ASSERT(NULL != skip_prefix(url, "http://"));

  if (hashtable_fill(pending_checks) >= MAX_PENDING_CHECKS) {
    checker_log("Too many queued URL checks");
    return NULL;
  }
  
  ctx = calloc(1, sizeof *ctx);
  if (ctx) {
    ctx->magic = URL_CHECK_MAGIC;
    ctx->client = client;
    ctx->host = compat_strdup(host);
    ctx->url = compat_strdup(url);
    ctx->url_hash = hash_str(ctx->url);
    ctx->closed = false;
    ctx->bad = false;
    ctx->pong = false;
    ctx->buffer = fifo_new(BUFFERSIZE);
    ctx->check = chk;
    
    http_ctx_init(&ctx->http, client->input);
    ctx->http.debug_dump_headers = OPTION(http_dump_headers);
    ctx->http.log_cb = checker_logv;

    memset(ctx->urlfile, 0, sizeof ctx->urlfile);
    RUNTIME_ASSERT(ctx->url != NULL);
    hashtable_add(pending_checks, ctx->url, ctx);
  }
  return ctx;
}

static void
url_check_ctx_destruct(url_check_ctx_t *ctx)
{
  size_t i;
  void *ptr;
  bool found;
  time_t now = compat_mono_time(NULL);
  
  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(URL_CHECK_MAGIC == ctx->magic);
  RUNTIME_ASSERT(ctx->url != NULL);
  RUNTIME_ASSERT(ctx->url_hash == hash_str(ctx->url));
  
  found = hashtable_get(pending_checks, ctx->url, &ptr);
  RUNTIME_ASSERT(found);
  RUNTIME_ASSERT(ptr == ctx);
  hashtable_remove(pending_checks, ctx->url);
  
  DO_FREE(ctx->host);
  DO_FREE(ctx->url);
  client_destruct(ctx->client);
  fifo_destruct(ctx->buffer);
  http_destruct(&ctx->http);
  
  for (i = 0; i < ARRAY_LEN(ctx->urlfile); i++) {
    if (ctx->urlfile[i].url) {
      /* Pick up URLs from the verified GWC */
      checker_verify_url(ctx->urlfile[i].url, now, false);
      DO_FREE(ctx->urlfile[i].url);
    }
  }
  
  memset(ctx, 0, sizeof *ctx);
  DO_FREE(ctx);
}

/**
 * Moves the URL ``url'' from one cache to another. The URL doesn't need to
 * be in the cache ``from''. If the URL is already in ``to'', it's not added
 * again.
 */
void
checker_move_gwc(gwc_cache_t *from, gwc_cache_t *to, const char *url)
{
  RUNTIME_ASSERT(from != NULL);
  RUNTIME_ASSERT(to != NULL);
  RUNTIME_ASSERT(from != to);

  if (gwc_move_url(from, to, url)) {
    checker_log("Moved URL \"%s\" from set of %s caches to set of %s caches",
        url,
        from == good_cache ? "good" : "bad",
        to == good_cache ? "good" : "bad");
  }
}

void
checker_remove_gwc(gwc_cache_t *cache, const char *url)
{
  RUNTIME_ASSERT(cache != NULL);
  RUNTIME_ASSERT(url != NULL);
  
  gwc_url_remove(cache, url, true);
}

static void
analyze_results(url_check_ctx_t *ctx)
{
  gwc_url_t *g;

  if (CHECK_PING == ctx->check) {
    ctx->bad |= !ctx->pong;
  } else if (!ctx->bad) {
    int score = 0;
    size_t i, n = 0;
    
    RUNTIME_ASSERT(ctx->url != NULL);
    
    for (i = 0; i < ARRAY_LEN(ctx->urlfile); i++) {
      const char *url = ctx->urlfile[i].url;
      size_t count = ctx->urlfile[i].count;
      gwc_url_t *bad;
      
      if (!url)
        continue;
      n++;
        
      bad = gwc_url_lookup(bad_cache, url);
      if (bad && bad->num_checks != 32 && bad->num_checks > 4) {
        checker_log("Returned a bad URL: \"%s\"", url);
        score -= count / 2;
        continue;
      }
        
      score += count * (gwc_url_lookup(good_cache, url) != NULL ? 4 : 1);
    }

    if (!OPTION(url_check_strict)) {
      /* If strict checks are disabled, a single valid GWC URL is sufficient */
      ctx->bad |= n < 1;
    } else if (score < 4) {
      checker_log("Rejected URL \"%s\" (score=%d)", ctx->url, score);
      ctx->bad = true;
    }
    
  }

  g = gwc_url_lookup(bad_cache, ctx->url);
  if (!ctx->bad) {
    checker_move_gwc(bad_cache, good_cache, ctx->url);
    return;
  }

  /* The URL qualified as bad, check whether it has to be added or
   * whether it's already known to be bad. */

  if (g) {
    checker_log("Still a bad GWC: \"%s\"", ctx->url);
    return;
  }
  
  checker_move_gwc(good_cache, bad_cache, ctx->url);
}

static void
gwc_check_event(connection_t *c, ev_type_t ev)
{
  url_check_ctx_t *ctx;

  connection_check(c);

  ctx = connection_get_context(c);
  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(URL_CHECK_MAGIC == ctx->magic);
  RUNTIME_ASSERT(ctx->http.input == ctx->client->input);
  RUNTIME_ASSERT(!ctx->closed);
  
  if (ev & EVT_ERROR) {
    char addr[NET_ADDR_BUFLEN];
    int fd = connection_get_fd(c), error;
    socklen_t error_len = sizeof error;
    
    connection_get_addrstr(c, addr, sizeof addr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len)) {
      WARN("(addr=%s) [getsockopt failed: %s]", addr, compat_strerror(errno));
    } else {
      WARN("(addr=%s): %s", addr, compat_strerror(error));
    }
    goto close_connection;
  }

  if ((ev & (EVT_READ | EVT_HANGUP)) || !fifo_empty(ctx->http.input)) {
    size_t prev_fill;
    ssize_t ret;
   
    prev_fill = fifo_fill(ctx->http.input);
    RUNTIME_ASSERT((ssize_t) prev_fill >= 0);
    
    if (ev & (EVT_READ | EVT_HANGUP)) {
      ret = fifo_recv(ctx->http.input, connection_get_fd(c));
      if (ret == (ssize_t) -1) {
        if (!is_temporary_error(errno)) {
          ctx->closed = true;
          checker_log("fifo_recv() failed: %s", compat_strerror(errno));
        }
      } else if (ret == 0) {
        /* Half-closed connection (remote side sent a FIN) */
        ctx->closed = true;
      }
    }

    if (ctx->http.state == HTTP_STATE_REQUEST) {
      if (http_read_response(&ctx->http))
        goto close_connection;
        
      RUNTIME_ASSERT(
          ctx->http.state == HTTP_STATE_REQUEST || HTTP_STATE_HEADERS);
    }
    /* FALL THROUGH */
    
    if (ctx->http.state == HTTP_STATE_HEADERS) {
      static const char term1[] = "\n\r\n", term2[] = "\n\n";
      size_t off;

      off = (size_t) prev_fill < STATIC_STRLEN(term1) 
        ? 0 : prev_fill - STATIC_STRLEN(term1);

      if (
          fifo_findstr(ctx->http.input, term1, off) >= 0 ||
          fifo_findstr(ctx->http.input, term2, off) >= 0
      ) {
        char headers[2 * BUFFERSIZE];
        
        if (http_process_headers(&ctx->http, headers, sizeof headers))
          goto close_connection;

        RUNTIME_ASSERT(ctx->http.state == HTTP_STATE_BODY);
      }

    }
    /* FALL THROUGH */
    
    if (ctx->http.state == HTTP_STATE_BODY) {
      char buf[BUFFERSIZE];
      ssize_t size;

      size = fifo_space(ctx->buffer);
      RUNTIME_ASSERT(size >= 0);

      /* In theory all 2xx indicate success, in practice this is just theory */
      if (ctx->http.status_code != 200)
        goto close_connection;

      if (fifo_fill(ctx->http.input) > 0) {
        ret = http_read_body(&ctx->http, buf, MIN((size_t) size, sizeof buf));
        if (ret < 0) {
          if (!is_temporary_error(errno)) {
            checker_log("http_read_body() failed: %s", compat_strerror(errno));
            ctx->closed = true;
          }
        } else if (ret == 0) {
          checker_log(" ");
          /* End of body reached */
        } else {
          fifo_write(ctx->buffer, buf, ret);
          if (fifo_full(ctx->buffer)) {
            ctx->closed = true;
          }
        }  
      } 

      if (fifo_fill(ctx->buffer) < 1 && ctx->closed)
        goto close_connection;

      switch (ctx->check) {
      case CHECK_PING:
        ret = gwc_ping_check_read_body(ctx);
        break;
      case CHECK_URLFILE:
        ret = gwc_urlfile_check_read_body(ctx);
        break;
      case CHECK_GET:
        ret = gwc_get_check_read_body(ctx);
        break;
      default:
        ret = 0;
        RUNTIME_ASSERT(0);
      }
      
      if (
            ret ||
            ctx->http.received > (size_t) OPTION(url_check_max_size) ||
            (
              ctx->closed && fifo_empty(ctx->http.input)
            )
      ) {
        goto close_connection;
      }

    }

  }

  if (ev & EVT_WRITE) {
    ssize_t ret;

    ret = client_send(ctx->client);
    if ((ssize_t) -1 == ret) {
      if (!is_temporary_error(errno)) {
        checker_log("client_send() failed: %s", compat_strerror(errno));
        goto close_connection;
      }
    }
    if (!client_has_output(ctx->client)) {
      if (
        ev_watcher_watch_source(watcher, connection_get_source(c), EVT_READ)
      ) {
        WARN("ev_watcher_watch_source() failed");
      }
      shutdown(connection_get_fd(c), SHUT_WR);
    }
  }

  if (ev & EVT_TIMEOUT) {
    checker_log("%s: connection closed: timeout", __func__);
    goto close_connection;
  }

  if (
    ev_source_get_age(connection_get_source(c))
      > MAX(30, OPTION(max_connect_time))
  ) {
    ssize_t ret;
    char buf[256];

    ret = fifo_read(ctx->http.input, buf, sizeof buf - 1);
    RUNTIME_ASSERT(ret >= 0 && (size_t) ret < sizeof buf);
    buf[ret] = '\0';
    checker_log("Time limit exceeded but response isn't terminated yet: "
        "\"%s\"", buf);
    goto close_connection;
  }

  if (fifo_full(ctx->http.input)) {
    ssize_t ret;
    char buf[256];

    ret = fifo_read(ctx->http.input, buf, sizeof buf - 1);
    RUNTIME_ASSERT(ret > 0 && (size_t) ret < sizeof buf);
    buf[ret] = '\0';
    checker_log("FIFO is full but response isn't terminated yet: \"%s\"", buf);
    goto close_connection;
  }

  if (ctx->closed)
    goto close_connection;

  return;

close_connection:

  if (ctx->http.encoding == HTTP_TRANSFER_ENCODING_CHUNKED) {
    if (ctx->http.chunk_size > 0) {
      checker_log("Didn't reach last chunk");
    } else {
      checker_log("Received %" PRIu64 " of %" PRIu64 " bytes",
        ctx->http.received, ctx->http.chunk_sum_received);
    }
  } else {
    if ((uint64_t) -1 != ctx->http.content_length) {
      checker_log("Received %" PRIu64 " of %" PRIu64 " bytes",
        ctx->http.received, ctx->http.content_length);
    } else {
      checker_log("Received %" PRIu64 " bytes (message length unknown)",
        ctx->http.received);
    }
  }

  if (CHECK_PING == ctx->check && !ctx->bad && ctx->pong) {
    struct timeval tv;
    char url[MAX_URL_SIZE];
    size_t size = sizeof url;

    append_string(url, &size, ctx->url);
    if (!size) {
      RUNTIME_ASSERT(0);
      exit(EXIT_FAILURE);
    }
    tv = ev_source_get_stamp(connection_get_source(c));
    checker_verify_url(url, tv.tv_sec, true); /* Force verification */
  } else {
    analyze_results(ctx);
    url_check_ctx_destruct(ctx);
  }
  
  connection_set_context(c, NULL);
  connection_close(c);

  return;
}

static connection_t *
gwc_check_connect(const net_addr_t addr, in_port_t port, int *error)
{
  const struct sockaddr *sa;
  char addr_str[NET_ADDR_BUFLEN];
  connection_t *c = NULL;
  int fd = -1;
  socklen_t len;

  print_net_addr(addr_str, sizeof addr_str, addr);
  
  if (net_addr_is_private(addr)) {
    checker_log("Not connecting to private address: \"%s\"", addr_str);
    *error = EACCES;
    return NULL;
  }

  if (addr_filter && addr_filter_match(addr_filter, addr)) {
    checker_log("Not connecting to blocked address: \"%s\"", addr_str);
    *error = EACCES;
    return NULL;
  }

  checker_log("Connecting to \"%s\"", addr_str);
  fd = socket(net_addr_family(addr), SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) {
    /* XXX: If socket() failed with errno ENFILE, EMFILE. ENOBUFS,
     *      the limit of simultaneously open descriptors must be
     *      reduced. */
    checker_log("socket() failed: \"%s\"", compat_strerror(errno));
    *error = errno;
    return NULL;
  }

  c = connection_new(addr, port);
  if (c) {
    connection_set_source(c, ev_source_new(fd));
    connection_set_blocking(c, false);
    if (OPTION(tcp_sndbuf_size)) {
      connection_set_sndbuf(c, OPTION(tcp_sndbuf_size));
    }
    if (OPTION(tcp_rcvbuf_size)) {
      connection_set_rcvbuf(c, OPTION(tcp_rcvbuf_size));
    }
  } else {
    close(fd);
    checker_log("Out of memory");
    return NULL;
  }

  len = net_addr_sockaddr(addr, port, &sa);
  if (connect(fd, sa, len)) {
    if (errno != EINPROGRESS) {
      *error = errno;
      checker_log("connect() failed: \"%s\"", compat_strerror(errno));
      connection_close(c);
      connection_unref(c);
      fd = -1;
      return NULL;
    }
  }
  if (!c)
    *error = errno;
  return c;
}

void
checker_verify_url(const char *url, time_t now, bool force)
{
  char host[MAX_URL_SIZE];
  const char *path;
  gwc_url_t *g;
  uint16_t port;
  int error;
  gwc_cache_t *cache;
  size_t url_len;
    
  RUNTIME_ASSERT(url != NULL);
 
  if (0 == strcmp(OPTION(gwc_url), url)) {
    /* Don't check our own URL */
    return;
  }
  
  if (!force && NULL != pending_check(url)) {
#if 0
    checker_log("Check for URL is already pending: \"%s\"", url);
#endif
    return;
  }
 
  g = gwc_url_lookup(good_cache, url);
  if (g) {
    cache = good_cache;
  } else {
    g = gwc_url_lookup(bad_cache, url);
    cache = g ? bad_cache : NULL;
  }
  
  if (!force && g != NULL) {
    long d;
    
    RUNTIME_ASSERT(cache == good_cache || cache == bad_cache);
    gwc_check_url_entry(g);
    d = difftime(now, g->stamp);
 
    if (cache == good_cache && d < (long) MAX_GOOD_GWC_AGE)
      return;
    
    if (cache == bad_cache) {
      if (g->num_checks > 12 || d < (1 << g->num_checks) * 3600)
        return;
    }

    g->num_checks++;
    g->stamp = now; /* Extend lease */
  }

  /* FALL THROUGH */

  *host = '\0';
  path = NULL;
  port = 0;
  error = url_split(url, host, sizeof host, &port, &path);
  RUNTIME_ASSERT(port != 0);
  RUNTIME_ASSERT(path != NULL);
  RUNTIME_ASSERT(!error);

  if (addr_filter && addr_filter_match_name(addr_filter, host)) {
#if 0
    /* This is a bit too verbose */
    checker_log("Host of URL matches block list: \"%s\"", url);
#endif
    return;
  }

  url_len = strlen(path) + MAX_REQ_SIZE;
  if (OPTION(network_id)) {
    url_len += strlen(OPTION(network_id)) + sizeof "&net=";
  }
    
  if (url_len >= MAX_URL_SIZE) {
    checker_log("URI is too long; skipping");
    return;
  }

  if (!cache) {
    checker_log("New URL: \"%s\"", url);
    gwc_add_url(bad_cache, url);
    g = gwc_url_lookup(bad_cache, url);
    RUNTIME_ASSERT(g != NULL);
    g->num_checks = 32; /* This means the URL is new */
      
    if (!OPTION(auto_discovery))
      return;
  }
  
  checker_log("Checking URL %s\"%s\"", force ? "(forced) " : "", url);
  if (0 != dns_helper_lookup(dns_query_con, host, url)) {
    checker_log("dns_helper_lookup() failed; putting \"%s\" to bad URLs", url);
    if (cache == bad_cache) {
      g->stamp = now; /* Extend lease */
    } else {
      checker_move_gwc(good_cache, bad_cache, url);
    }
  }
}

static int
checker_urlcheck_run(const char *url, const struct address_batch batch,
    check_t chk)
{
  connection_t *c = NULL;
  int error = 0;
  size_t i;
  uint16_t port;
  size_t url_len;
  const char *path;
  char host[MAX_URL_SIZE];

  RUNTIME_ASSERT(url != NULL);
  RUNTIME_ASSERT(strlen(url) < MAX_URL_SIZE);
  error = url_split(url, host, sizeof host, &port, &path);
  RUNTIME_ASSERT(!error);

  url_len = strlen(path) + MAX_REQ_SIZE;
  if (OPTION(network_id)) {
    url_len += strlen(OPTION(network_id)) + sizeof "&net=";
  }
 
  if (url_len >= MAX_URL_SIZE) {
    checker_log("URI is too long; skipping");
    return -1;
  }

  for (i = 0; i < ARRAY_LEN(batch.addr); i++) {
    if (net_addr_equal(batch.addr[i], net_addr_unspecified))
      break;
    c = gwc_check_connect(batch.addr[i], port, &error);
    if (c) {
      break;
    }
  }
  
  if (c) {
    const char *net = OPTION(network_id);
    url_check_ctx_t *url_ctx;
    client_t *client;
    char path_part[MAX_URL_SIZE], *p = path_part;
    size_t size = sizeof path_part;
   
    checker_log("Connected to %s:%u", host, (unsigned) port);
    p = append_string(path_part, &size, path);

    switch (chk) {
    case CHECK_URLFILE:
      p = APPEND_STATIC_CHARS(p, &size, urlfile_req_str);
      break;
    case CHECK_PING:
      p = APPEND_STATIC_CHARS(p, &size, ping_req_str);
      break;
    case CHECK_GET:
      p = APPEND_STATIC_CHARS(p, &size, get_req_str);
      break;
    default:
      RUNTIME_ASSERT(0);
      return -1;
    }

    if (net) {
      p = APPEND_STATIC_CHARS(p, &size, "&net=");
      p = append_string(p, &size, net);
    }
    
    p = append_string(p, &size, OPTION(support_v2) ? "&pv=2" : "&pv=3");

    if (size < 2) {
      checker_log("Path is too long; skipping");
      return -1;
    }

    p = append_char(p, &size, '\0');

    client = client_new(c, watcher, BUFFERSIZE, 0);
    if (!client) {
      connection_close(c);
      connection_unref(c);
      return -1;
    }

    url_ctx = url_check_ctx_new(client, host, url, chk);
    if (!url_ctx) {
      client_destruct(client);
      connection_close(c);
      connection_unref(c);
      return -1;
    }

    connection_set_context(c, url_ctx);
    http_ctx_init(&client->http, client->input);
    client->http.debug_dump_headers = OPTION(http_dump_headers);
    client->http.log_cb = checker_logv;
    client->http.output = &client->http_out;

    if (from_header) {
      http_add_header(&client->http, from_header);
    }
    http_request_get(&client->http, host, port, path_part);
    http_terminate_headers(&client->http);

    connection_set_event_cb(c, &gwc_check_event);
    ev_source_set_timeout(connection_get_source(c),
        MAX(20, OPTION(idle_timeout)));

    if (ev_watcher_watch_source(watcher, connection_get_source(c), EVT_WRITE)) {
      WARN("ev_watcher_watch_source() failed");
    }

    return 0;
  } else {
    checker_log("Could not connect to \"%s\"", host);
   
    /* Keep good URLs when socket() fails with ENOBUFS. This means
     * the server is low on resources and it would run out of URLs
     * otherwise. */
    if (ENOBUFS == error && NULL != gwc_url_lookup(good_cache, url)) {
      INFO("Keeping \"%s\" as good cache because of ENOBUFS.", url);
    } else {
      checker_move_gwc(good_cache, bad_cache, url);
    }
  }

  return -1;
}

/**
 * Tries to extract one line from ctx->buffer into ``buf'' with a maximum
 * length length of ``size'' - 1. Trailing traces will be stripped and the
 * string will always be NUL-terminated. However, if the return value is
 * not 1 (one) the contents of ``buf'' are undefined.
 *
 * @param buf  The buffer into which the line will be copied
 * @param size The size of buffer in bytes.
 *
 * @return 0 - if more input is necessary.
 *         1 - if a line was successfully extracted.
 *        -1 - if the end was reached.
 */
static int
extract_line(url_check_ctx_t *ctx, char *buf, size_t size)
{
  ssize_t ret, ret2;

  RUNTIME_ASSERT(ctx != NULL);
  RUNTIME_ASSERT(buf != NULL);
  RUNTIME_ASSERT((ssize_t) size > 0);
 
  /* Some caches are so shitty that the body is terminated by \r\n
   * but every single line before only by a \r or \n. Use whatever
   * comes first as line termination. */
  ret = fifo_findchar(ctx->buffer, '\r', size);
  ret2 = fifo_findchar(ctx->buffer, '\n', MAX(ret + 1, (ssize_t) size));

  /* If '\n' comes before '\r', the line is terminated by "\r\n" or there
   * was no '\r' at all, read up to '\n'. Otherwise, up to '\r'. */
  if (ret2 >= 0 && (ret < 0 || ret > ret2 || ret2 == (ret + 1))) {
    ret = ret2;
  }
    
  if ((ssize_t) -1 == ret) {
    ret = fifo_fill(ctx->buffer);

    if ((size_t) ret >= size) {
      /* If the line is too long for the buffer, look at what's in it and
       * close the connection. */
      ctx->closed = true;
    } else if (ret == 0 && ctx->closed) {
      /* If the connection was already closed there won't be any further
       * input so this is the end. */
      return -1;
    }

    if (ctx->closed) {
      /* The last line might not be terminated */
      if ((size_t) ret >= size) {
        /* Truncate line if necessary */
        ret = size;
      }
      ret--;
    } else {
      /* Need more input */
      buf[0] = '\0';
      return 0;
    }
  }
  
  RUNTIME_ASSERT(ret >= 0 && (size_t) ret < size);
  ret2 = fifo_read(ctx->buffer, buf, ret + 1);
  RUNTIME_ASSERT(ret2 == ret + 1);
  /* If the (last) line is not terminated, it gets truncated if necessary. */
  buf[(size_t) ret2 < size ? ret2 : ret] = '\0';

  /* Remove trailing spaces */
  while (ret >= 0) {
    if (isspace((unsigned char) buf[ret]))
      buf[ret--] = '\0';
    else
      break;
  }

  if ('\0' == buf[0]) {
    return 0;
  }
  
  checker_log("\t%s", buf);
  return 1;
}

/*
 * Note: Might modify data in ``buf''.
 */
static int
gwc_parse_url(url_check_ctx_t *ctx, char *buf)
{
  char *url;
  hash_t h;
  size_t i;
  int res;
  
  /* Abort if the line doesn't even start with "http://" */
  if (NULL == skip_ci_prefix(buf, "http://")) {
    checker_log("Line doesn't contain an HTTP URL: \"%s\"", buf);
    return 0;
  }

  /* Normalize and verify the URL */
  url = gwc_url_normalize(buf, &res);
  if (!url) {
     checker_log("Not a valid GWC URL (\"%s\"): \"%s\"", buf,
         gwc_url_normalize_result(res));
     /* Do not abort so that we can check whether the cache returns also
      * dupes in which case the cache would qualify as "bad" */
     return 1;
  }

  /* Check whether this URL has been returned before */
  h = hash_str(url);
  for (i = 0; i < ARRAY_LEN(ctx->urlfile); i++) {
    url_hash_t *uh = &ctx->urlfile[i];
      
    if (h == uh->hash && uh->url && !strcmp(uh->url, url)) {
      checker_log("GWC returned duplicate URL: \"%s\"", url);
      uh->count++;
      return OPTION(url_check_allow_dupes) ? 1 : -1;
    }
  }
   
  if (url == buf && NULL == (url = compat_strdup(buf))) {
     /* Running out of memory? Abort. */
     return 0;
  }

  /* Record the URL */
  for (i = 0; i < ARRAY_LEN(ctx->urlfile); i++)
    if (!ctx->urlfile[i].url) {
      ctx->urlfile[i].url = url;
      ctx->urlfile[i].hash = h;
      ctx->urlfile[i].count = 1;
      url = NULL; /* Indicates that there was a free entry */
    }
    
  if (!url)
    return 1; /* Success */
  
  /* The table is full, abort */
  DO_FREE(url);
  return 0;
}

static int
gwc_parse_line(url_check_ctx_t *ctx, char *buf)
{
  char *p, *colon;

  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(buf);
  
  colon = strchr(buf, ':');
  if (!colon) {
    /* Non-parseable, abort */
    return 0;
  }

  for (p = buf; p != colon; p++) {
    unsigned char c = *p;
    
    if (!isalnum(c) && '-' != c) {
      /* Non-parseable, abort */
      return 0;
    }
    if (isupper(c))
      *p = tolower(c);
  }
  *p++ = '\0';
 
  if (0 == strcmp(buf, "net")) {
    const char *net = OPTION(network_id) ? OPTION(network_id) : "gnutella";
    char *q;

    /* FIXME: Allow a list of network IDs instead of a single ID */

    p = skip_spaces(p);
    q = skip_ci_prefix(p, net);
    if (!q)
      q = skip_ci_prefix(p, "*"); /* wildcard -> supports any network */

    if (NULL == q || '\0' != *(q = skip_spaces(q))) {
      ctx->bad = true;
      ctx->closed = true;
      checker_log("Wrong network: \"%s\"", p);
      return -1;
    }
  } else if (0 == strcmp(buf, "option")) {
    /* Nothing to do */
  } else if (0 == strcmp(buf, "uhc")) {
    /* Nothing to do */
  }

  return 1; /* Everything OK */
}

static int
gwc_ping_check_read_body(url_check_ctx_t *ctx)
{
  char buf[BUFFERSIZE];

  for (;;) {
    int ret;

    ret = extract_line(ctx, buf, sizeof buf);
    if (ret != 1) {
      return ret;
    }

    if (!ctx->pong) {
      const char *net = OPTION(network_id) ? OPTION(network_id) : "gnutella";
      const char *endptr;
      
      if (
        NULL != (endptr = skip_prefix(buf, "PONG")) &&
        ('\0' == *endptr || isspace((unsigned char) *endptr))
      ) {
        if (
          skip_prefix(skip_spaces(endptr), "MWebCache") &&
          0 != strcmp(net, "mute")
        ) {
          checker_log("Buggy MWebCache: \"%s\"", buf);
          ctx->bad = true;
          ctx->closed = true;
          return -1;
        } else {
          checker_log("Received PONG: \"%s\"", buf);
          ctx->pong = true;
        }
      } else if (OPTION(support_v2) && NULL != skip_ci_prefix(buf, "i|pong|")) {
        /*
         * XXX: Is it guaranteed/required that the pong occurs in the
         *      first line?
         */
        
        checker_log("Received PONG v2.0: \"%s\"", buf);
        ctx->pong = true;
        ctx->closed = true;
        /* v2 does not parse extra data */
        return -1;
      } else {
        checker_log("Not a PONG: \"%s\"", buf);
        ctx->bad = true;
        ctx->closed = true;
        return -1;
      }
    }
    
    /* Ignore empty lines */
    if ('\0' == buf[0])
      continue;
   
    ret = gwc_parse_line(ctx, buf);
        
    switch (ret) {
    case  0: goto end_of_reply;
    case -1: goto failure;
    default: ;
    }

  }
  
  return 0;

failure:
  ctx->bad = true;

end_of_reply:
 
  ctx->closed = true;
  return -1;
}

static int
gwc_urlfile_check_read_body(url_check_ctx_t *ctx)
{
  char buf[BUFFERSIZE];

  for (;;) {
    int ret;

    ret = extract_line(ctx, buf, sizeof buf);
    if (ret != 1) {
      return ret;
    }
    
    /* Ignore empty lines */
    if ('\0' == buf[0])
      continue;
   
    ret = NULL != skip_ci_prefix(buf, "http://")
      ? gwc_parse_url(ctx, buf)
      : gwc_parse_line(ctx, buf);

    switch (ret) {
    case  0: goto end_of_reply;
    case -1: goto failure;
    default: ;
    }

  }
  
  return 0;

failure:
  ctx->bad = true;

end_of_reply:
 
  ctx->closed = true;
  return -1;
}


static int
gwc_get_check_read_body(url_check_ctx_t *ctx)
{
  char buf[256];

  for (;;) {
    int ret;
    char *p, *q;
    int c;

    ret = extract_line(ctx, buf, sizeof buf);
    if (ret != 1) {
      return ret;
    }
    
    if (buf[0] == '\0') {
      /* Ignore empty lines */
      continue;
    }
  
    p = strchr(buf, '|');
    if (!p || p == buf) {
      checker_log("Line doesn't look like GWC 2.0: \"%s\"", buf);
      goto end_of_reply;
    }
    *p++ = '\0';
    q = strchr(p, '|');
    if (q) {
      *q = '\0';
    }
   
    RUNTIME_ASSERT(buf[0] != '\0');
    if (buf[1] != '\0') {
      checker_log("Unsupported GWC 2.0 entry: \"%s|%s\"", buf, p);
      continue;
    }
    RUNTIME_ASSERT(buf[1] == '\0');
      
    c = toupper((unsigned char) buf[0]);
    switch (c) {
    case 'I':
      /* Informational entry */
      checker_log("Informational entry: \"%s\"", p);
      if (0 == strcasecmp(p, "net-not-supported")) {
        goto failure;
      }
      break;
      
    case 'H':
      {
        /* Host entry */
        net_addr_t addr;
        uint16_t port;
        char *ep;

        if (!parse_net_addr(p, &addr, &ep)) {
          checker_log("GWC listed an invalid address: \"%s\"", p);
          goto failure;
        } else if (net_addr_is_private(addr)) {
          checker_log("GWC listed a private address: \"%s\"", p);
          goto failure;
        } else if (net_addr_is_multicast(addr)) {
          checker_log("GWC listed a multicast address: \"%s\"", p);
          goto failure;
        } else if (':' != *(q = ep)) {
          checker_log("GWC listed host without port: \"%s\"", p);
          goto failure;
        } else if (!parse_port_number(++q, &port, &ep)) {
          checker_log("GWC listed host with invalid port: \"%s\"", p);
          goto failure;
        } else if (*ep != '\0') {
          checker_log("GWC listed host followed by dirt: \"%s\"", p);
          goto failure;
        }
        
        /* XXX: Check age field */
      }
      break;
      
    case 'U':
      {
        /* URL entry */
      
        ret = gwc_parse_url(ctx, p);
        switch (ret) {
        case  0: goto end_of_reply;
        case -1: goto failure;
        default: ;
        }
      
        /* XXX: Check age field */
      }
      break;
      
    default:
      /* Unsupported type of entry */
      checker_log("Unknown GWC 2.0 data: \"%s|%s\"", buf, p);
    }
    
  }
  
  return 0;

failure:
  ctx->bad = true;

end_of_reply:
  ctx->closed = true;
  return -1;
}

/* Reads replies from the DNS helper */
static void
checker_get_dns_reply(connection_t *c, ev_type_t ev)
{
  static struct timeval last_check;
  struct timeval now;
  
  connection_check(c);

  now = ev_source_get_stamp(connection_get_source(c));
  if (ev & EVT_ERROR) {
    checker_log("%s: shutting down due to error", __func__);
    exit(EXIT_FAILURE);
  }
  
  if (ev & EVT_HANGUP) {
    checker_log("%s: shutting down due to hangup", __func__);
    exit(EXIT_FAILURE);
  }

  if (ev_watcher_watch_source(watcher, connection_get_source(c), EVT_READ)) {
    WARN("ev_watcher_watch_source() failed");
  }
  
  for (;;) {
    client_t *ctx;
    url_check_ctx_t *pending;
    ssize_t ret;
    size_t size;
    char url[MAX_URL_SIZE];
    struct address_batch batch;
    check_t chk;
    gwc_url_t *bad;
    
    ctx = connection_get_context(c);
    client_check(ctx);
    ret = client_recv(ctx);
    if (ret == (ssize_t) -1) {
      if (!is_temporary_error(errno)) {
        checker_log("client_recv() failed: %s", compat_strerror(errno));
        exit(EXIT_FAILURE);
      }
    } else if (ret == 0) {
      checker_log("client_recv() returned zero");
      exit(EXIT_FAILURE);
    }
    
    ret = fifo_findchar(ctx->input, '\0', sizeof url);
    if ((ssize_t) -1 == ret) {
      return;
    }
    size = ret + 1 + sizeof batch;
    if (fifo_fill(ctx->input) < size) {
      return;
    }
    
    RUNTIME_ASSERT(ret >= 0 && ret < (ssize_t) sizeof url);
    ret = fifo_read(ctx->input, url, ret + 1);
    RUNTIME_ASSERT(ret > 0 && ret < (ssize_t) sizeof url);
    RUNTIME_ASSERT(url[ret - 1] == '\0');
    RUNTIME_ASSERT(NULL != skip_prefix(url, "http://"));

    ret = fifo_read(ctx->input, cast_to_void_ptr(&batch), sizeof batch);
    RUNTIME_ASSERT(ret == sizeof batch);
    
    bad = gwc_url_lookup(bad_cache, url);
    if (net_addr_equal(batch.addr[0], net_addr_unspecified)) {
      
      if (!bad) {
        /* If the DNS lookup failed and the URL was in the good cache, move it
         * to the bad cache */
        checker_log("Moving URL \"%s\" to bad cache due to DNS failure", url);
        checker_move_gwc(good_cache, bad_cache, url);
      } else if (bad->num_checks == 32) {
        /* This could cause too frequent DNS lookups */
#if 0
        checker_log("Dropping new URL \"%s\" due to DNS failure", url);
        checker_remove_gwc(bad_cache, url);
#endif
      }
      
      return;
    }

    if (bad != NULL && bad->num_checks == 32) {
      RUNTIME_ASSERT(OPTION(auto_discovery));
      /* Reset to one to remove the "is new" mark */
      bad->num_checks = 1;
    }

    /* There might have been a previous queued request for this URL.
     * Check whether the status information for this URL is in of the
     * caches or whether there's already an active check pending. */

    pending = pending_check(url);
    if (pending && !pending->pong) {
      checker_log("URL check is already pending");
      return;
    }
 
    if (pending) {
      RUNTIME_ASSERT(pending->check == CHECK_PING);
      RUNTIME_ASSERT(pending->pong);
      url_check_ctx_destruct(pending);
      pending = NULL;
      
      chk = OPTION(support_v2) ? CHECK_GET : CHECK_URLFILE;
    } else {
      chk = CHECK_PING;
    }
    
    checker_urlcheck_run(url, batch, chk);

    if (difftime(now.tv_sec, last_check.tv_sec) < OPTION(url_check_delay)) {
      /* enter a sleeping phase */
      if (
        ev_watcher_watch_source(watcher, connection_get_source(c), EVT_NONE)
      ) {
        WARN("ev_watcher_watch_source() failed");
      }
      return;
    }

    last_check = now;
  }
}

/* sends a query to the URL checker to verify the URL */
static void
checker_send_dns_query(connection_t *c, ev_type_t ev)
{
  client_t *client = connection_get_context(c);
  
  if (ev & EVT_ERROR) {
    checker_log("%s: shutting down due to error", __func__);
    exit(EXIT_FAILURE);
  }
  
  if (ev & EVT_HANGUP) {
    checker_log("%s: shutting down due to hangup", __func__);
    exit(EXIT_FAILURE);
  }

  if (ev & EVT_WRITE) {
    ssize_t ret;

    ret = client_send(client);
    if (0 == ret) {
      checker_log("%s: client_send() returned zero", __func__);
      exit(EXIT_FAILURE);
    } else if ((ssize_t) -1 == ret) {
      if (!is_temporary_error(errno)) {
        checker_log("%s: client_send() failed: %s", __func__,
            compat_strerror(errno));
        exit(EXIT_FAILURE);
      }
    }
  }
 
  {
    ev_type_t mask;

    mask = client_has_output(client) ? EVT_WRITE : EVT_NONE;
    if (ev_watcher_watch_source(watcher, connection_get_source(c), mask)) {
      WARN("ev_watcher_watch_source() failed");
    }
  }
}

void
checker_set_address_filter(struct addr_filter *af)
{
  addr_filter = af;
}

gwc_cache_t *
checker_get_good_cache(void)
{
  RUNTIME_ASSERT(NULL != good_cache);
  return good_cache;
}

gwc_cache_t *
checker_get_bad_cache(void)
{
  RUNTIME_ASSERT(NULL != bad_cache);
  return bad_cache;
}

static bool
save_cache_helper(const void *key, const void *value, void *udata)
{
  FILE *f;
  const gwc_url_t *g;

  RUNTIME_ASSERT(key != NULL);
  RUNTIME_ASSERT(value != NULL);
  RUNTIME_ASSERT(udata != NULL);

  g = value;
  f = udata;
  gwc_check_url_entry(g);
  fprintf(f, "%s %" PRIu64 " %d\n", g->url, (uint64_t) g->stamp, g->num_checks);
  return false;
}

int
checker_save_cache(const gwc_cache_t *cache, const char *pathname)
{
  FILE *f;

  RUNTIME_ASSERT(pathname);
  RUNTIME_ASSERT(pathname[0] == '/');
  RUNTIME_ASSERT(cache);
  
  f = safer_fopen(pathname, SAFER_FOPEN_WR);
  if (!f) {
    checker_log("could not open \"%s\": %s", pathname, compat_strerror(errno));
    return -1;
  }

  gwc_foreach(cache, save_cache_helper, f);
  fclose(f);
  return 0;
}

int
checker_load_cache(gwc_cache_t *cache, const char *pathname)
{
  FILE *f;
  unsigned int line_number;
  char line[4096];
  char *url = NULL;
  
  RUNTIME_ASSERT(pathname);
  RUNTIME_ASSERT(pathname[0] == '/');
  RUNTIME_ASSERT(cache);
  
  f = safer_fopen(pathname, SAFER_FOPEN_RD);
  if (!f) {
    checker_log("could not open \"%s\": %s", pathname, compat_strerror(errno));
    return -1;
  }
 
  for (line_number = 1; fgets(line, sizeof line, f); line_number++) {
    char *p, *endptr;
    int res;
    unsigned num_checks;
    time_t stamp;

    DO_FREE(url); /* In case "continue" was used */

    endptr = strchr(line, '\n');
    if (!endptr) {
      checker_log("Non-terminated or overlong line (%u)", line_number);
      goto failure;
    }
    *endptr = '\0';

    endptr = skip_spaces(line);
    if ('#' == *endptr || '\0' == *endptr) {
      /* skip comments and empty lines */
      continue;
    }

    /* Skip all non-spaces */
    endptr = line;
    while ('\0' != *endptr && !isspace((unsigned char) *endptr)) {
      endptr++;
    }
    if ('\0' != *endptr) {
      *endptr++ = '\0';
    } else {
      *endptr = '\0';
    }

    p = line;
    url = gwc_url_normalize(p, &res);
    if (!url) {
      checker_log("Invalid GWC URL (\"%s\") in line %u (line ignored): %s",
          p, line_number, gwc_url_normalize_result(res));
      continue;
    }
    if (url == p) {
      url = compat_strdup(p);
      if (!url) {
        checker_log("compat_strdup() failed");
        continue;
      }
    }

    if (addr_filter) {
      char host[MAX_URL_SIZE];
      int error;

      error = url_split(url, host, sizeof host, NULL, NULL);
      if (error) {
        checker_log("url_split() failed; removed: \"%s\"", url);
        DO_FREE(url);
        continue;
      }
      printf("host=\"%s\"", host);

      if (addr_filter_match_name(addr_filter, host)) {
        checker_log("Found blocked URL in cache; removed: \"%s\"", url);
        DO_FREE(url);
        continue;
      }
    }

    if (hash_str(url) == OPTION(gwc_url_hash) &&
        0 == strcmp(OPTION(gwc_url), url)
    ) {
      checker_log("Found own URL in cache; removed: \"%s\"", url);
      DO_FREE(url);
      continue;
    }
    
    if (gwc_url_lookup(cache, url)) {
      checker_log("Rejected duplicate URL: \"%s\"", url);
      DO_FREE(url);
      continue;
    }
  
    p = skip_spaces(endptr);
    if ('\0' == *p) {
      num_checks = 0;
      stamp = 1;
    } else {
      int error;
      uint32_t u;

      stamp = (time_t) parse_uint64(p, &endptr, 10, &error);
      if (error || !isspace((unsigned char) *endptr)) {
        checker_log("Invalid timestamp in line %u (line ignored): \"%s\"",
            line_number, p);
        continue;
      }
      p = skip_spaces(endptr);
      
      u = parse_uint32(p, &endptr, 10, &error);
      if (error || u >= INT_MAX) {
        checker_log("Invalid check counter in line %u (line ignored): \"%s\"",
            line_number, p);
        continue;
      }
      num_checks = u;
    }

    if (0 == num_checks) {
      gwc_add_entry(bad_cache, url, 1, 0);
      checker_verify_url(url, compat_mono_time(NULL), false);
    } else {
      gwc_add_entry(cache, url, stamp, num_checks);
    }

#if 0
      {
        char date[RFC1123_DATE_BUFLEN];
      
        print_rfc1123_date(date, sizeof date, stamp);
        checker_log("URL: %s (added: %s; checks: %u)", url, date, num_checks);
      }
#endif

    DO_FREE(url);
  }
  
  fclose(f);
  return 0;

failure:
  if (f) {
    fclose(f);
    f = NULL;
  }
  return -1;
}

int
checker_initialize(ev_watcher_t *w, int query_fd, int reply_fd)
{
  struct timeval now;
  
  RUNTIME_ASSERT(w != NULL);
  watcher = w;

  /*
   * Create the optional HTTP From header to be sent when verifying URLs. We
   * either send the "contact_address" or otherwise our own URL.
   */
  if (OPTION(send_from_header)) {
    char header[128], *p = header;
    size_t avail = sizeof header;

    p = append_string(header, &avail, "From: ");
    if (OPTION(contact_address)) {
      p = append_string(p, &avail, OPTION(contact_address));
    } else {
      p = append_string(p, &avail, OPTION(gwc_url));
    }
    if (avail < 2) {
      WARN("The \"From\" header would be too long; ignoring.");
    } else {
      from_header = compat_protect_strdup(header);
    }
  }
  
  compat_mono_time(&now);
  bad_cache = gwc_new(MAX_BAD_CACHED_GWCS);
  good_cache = gwc_new(MAX_GOOD_CACHED_GWCS);
  if (!good_cache || !bad_cache) {
    CRIT("gwc_new() failed");
    return -1;
  }
  
  pending_checks = hashtable_new(MAX_PENDING_CHECKS, url_hash, url_cmp);
  if (!pending_checks) {
    CRIT("hashtable_new() failed");
    return -1;
  }

  dns_reply_con = connection_new(net_addr_unspecified, 0);
  if (dns_reply_con) {
    client_t *client;

    connection_set_source(dns_reply_con, ev_source_new(reply_fd));
    connection_set_blocking(dns_reply_con, false);
    client = client_new(dns_reply_con, w, BUFFERSIZE, 0);
    if (!client) {
      CRIT("client_new() failed");
      return -1;
    }
    connection_set_context(dns_reply_con, client);
    connection_set_event_cb(dns_reply_con, checker_get_dns_reply);
    ev_source_set_timeout(connection_get_source(dns_reply_con),
      OPTION(url_check_delay));
    ev_watcher_watch_source(w, connection_get_source(dns_reply_con), EVT_READ);
  } else {
    close(reply_fd);
    CRIT("connection_new() failed");
    return -1;
  }
  
  dns_query_con = connection_new(net_addr_unspecified, 0);
  if (dns_query_con) {
    client_t *client;

    connection_set_source(dns_query_con, ev_source_new(query_fd));
    connection_set_blocking(dns_query_con, false);
    client = client_new(dns_query_con, w, 0, 0);
    if (!client) {
      CRIT("client_new() failed");
      return -1;
    }
    connection_set_context(dns_query_con, client);
    connection_set_event_cb(dns_query_con, checker_send_dns_query);
    ev_source_set_timeout(connection_get_source(dns_query_con),
        OPTION(url_check_delay));
    ev_watcher_watch_source(w, connection_get_source(dns_query_con), EVT_NONE);
  } else {
    close(query_fd);
    CRIT("connection_new() failed");
    return -1;
  }
  
  return 0;
}

/* vi: set ai et sts=2 sw=2 cindent: */
