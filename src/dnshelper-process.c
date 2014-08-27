/*
 * Copyright (c) 2004 Christian Biere <christianbiere@gmx.de>
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

#include "dnshelper.h"

#if !defined(HAVE_PTHREAD_SUPPORT)

#include "lib/fifo.h"
#include "lib/connection.h"
#include "lib/event_watcher.h"
#include "lib/dns.h"

#include "options.h"
#include "client.h"

static const options_t *opts_;
#define OPTION(x) ((opts_ != NULL ? opts_ : (opts_ = options_get()))->x)

static ev_watcher_t *watcher = NULL;
static connection_t *dns_query_con = NULL;
static connection_t *dns_reply_con = NULL;

static sig_atomic_t sighup_received = 0;

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
    fprintf(stderr, "<<< %s >>>\n", date);
    fflush(stderr);
  }
}

static int
dns_helper_lookup_host(const char *host, struct address_batch *batch,
    int *error)
{
  char addr_str[NET_ADDR_BUFLEN];
  dnslookup_ctx_t *ctx;
  net_addr_t addr;
  size_t i;

  for (i = 0; i < ARRAY_LEN(batch->addr); i++) {
    batch->addr[i] = net_addr_unspecified;
  }
    
  ctx = dnslookup_ctx_new();
  if (!ctx) {
    CRIT("dnslookup_ctx_new() failed");
    return -1;
  }
  if (dnslookup(ctx, host, error)) {
    INFO("Could not resolve \"%s\"", host);
    dnslookup_ctx_free(ctx);
    return -1;
  }

  for (i = 0; i < ARRAY_LEN(batch->addr); /* NOTHING */) {
    size_t j;
    
    if (!dnslookup_next(ctx, &addr))
      break;
   
    /* Check for dupes; getaddrinfo() usually returns the same
     * address multiple times when giving few hints. */
    for (j = 0; j < i; j++) {    
      if (net_addr_equal_ptr(&addr, &batch->addr[j]))
        break;
    }
    if (j < i)
      continue; /* ignore dupe */
    
    print_net_addr(addr_str, sizeof addr_str, addr);
    
    if (net_addr_is_private(addr)) {
      WARN("Not connecting to private address: \"%s\"", addr_str);
      *error = EACCES;
      continue;
    }

    DBUG("Host \"%s\" resolved to: \"%s\"", host, addr_str);
    batch->addr[i++] = addr;
  }

  dnslookup_ctx_free(ctx);
  return i > 0 ? 0 : -1;
}

int 
dns_helper_lookup(connection_t *c, const char *host, const char *url)
{
  client_t *client;
  ssize_t host_len, url_len;
  ssize_t size;
  
  connection_check(c);
  client = connection_get_context(c);
  client_check(client);

  host_len = strlen(host);
  RUNTIME_ASSERT(host_len > 0);
  url_len = strlen(url);
  RUNTIME_ASSERT(url_len > 0);

  size = host_len + 1 + url_len + 1;
  if (size < 0 || size > 4096) {
    CRIT("URL too big, cannot be queued");
    return -1;
  }

  client_queue_data(client, host, host_len);
  client_queue_data(client, "\n", 1);
  client_queue_data(client, url, 1 + url_len);

  ev_watcher_watch_source(client->watcher, connection_get_source(c), EVT_WRITE);

#if 0
  DBUG("Queued URL \"%s\"; ret=%d", url, (int) ret);
#endif
  return 0;
}

static int
dns_helper_reopen_logs(const char *filename)
{
  RUNTIME_ASSERT(filename != NULL);
 
  fflush(stderr);
  if (!freopen(filename, "a", stderr)) {
    return -1;
  } else {
    log_time_mark(0);
    INFO("Reopened log file");
    return 0;
  }
}

static void
dns_helper_periodic(ev_watcher_t *w, const struct timeval *now)
{
  ev_watcher_check(w);

  if (sighup_received) {
    sighup_received = 0;
    if (dns_helper_reopen_logs(OPTION(log_dns))) {
      exit(EXIT_FAILURE);
    }
  }
  log_time_mark(now->tv_sec);
}
 
static void
sighup_handler(int signo)
{
  (void) signo;
  sighup_received = 1;
}

/* DNS helper process writes a reply */
static void
dns_helper_event_write(connection_t *c, ev_type_t ev)
{
  client_t *client;

  connection_check(c);
  client = connection_get_context(c);
  client_check(client);
  RUNTIME_ASSERT(connection_get_fd(c) != connection_get_fd(dns_query_con));
  
  if (ev & EVT_ERROR) {
    CRIT("%s: shutting down due to error", __func__);
    exit(EXIT_FAILURE);
    return;
  }
  
  if (ev & EVT_HANGUP) {
    INFO("%s: hangup", __func__);
    exit(EXIT_SUCCESS);
    return;
  }
  
  {
    ssize_t ret;
    
    ret = client_send(client);
    if ((ssize_t) -1 == ret) {
      if (!is_temporary_error(errno)) {
        CRIT("%s: fifo_writev() failed: %s", __func__, compat_strerror(errno));
        exit(EXIT_FAILURE);
      }
    } else if (0 == ret) {
      CRIT("%s: fifo_writev() returned zero", __func__);
      exit(EXIT_FAILURE);
    }
  }
  
  if (client_has_output(client)) {
    ev_watcher_watch_source(watcher, connection_get_source(c), EVT_WRITE);
    ev_watcher_watch_source(watcher, connection_get_source(dns_query_con),
      EVT_NONE);
  } else {
    ev_watcher_watch_source(watcher, connection_get_source(c), EVT_NONE);
    ev_watcher_watch_source(watcher, connection_get_source(dns_query_con),
      EVT_READ);
  }
}

/* DNS helper process reads a request */
static void
dns_helper_event_read(connection_t *c, ev_type_t ev)
{
  client_t *client;

  connection_check(c);
  client = connection_get_context(c);
  client_check(client);
  RUNTIME_ASSERT(connection_get_fd(c) == connection_get_fd(dns_query_con));

  (void) ev_source_get_stamp(connection_get_source(c));
  if (ev & EVT_ERROR) {
    CRIT("%s: shutting down due to error", __func__);
    exit(EXIT_FAILURE);
    return;
  }
  
  if (ev & EVT_HANGUP) {
    INFO("%s: hangup", __func__);
    exit(EXIT_SUCCESS);
    return;
  }
  
  for (;;) {
    struct address_batch batch;
    ssize_t ret, size;
    char req[MAX_URL_SIZE * 2];
    char *url;
    int error;

    RUNTIME_ASSERT(client->input);
    ret = client_recv(client);
    if ((ssize_t) -1 == ret) {
      if (!is_temporary_error(errno)) {
        DBUG("%s: client_recv() failed: %s", __func__, compat_strerror(errno));
        exit(EXIT_FAILURE);
      }
    } else if (0 == ret) {
      DBUG("%s: client_recv() returned zero", __func__);
      exit(EXIT_FAILURE);
    }
    
    ret = fifo_findchar(client->input, '\0', sizeof req);
    if ((ssize_t) -1 == ret) {
      RUNTIME_ASSERT(fifo_fill(client->input) < sizeof req);
      break;
    }
    RUNTIME_ASSERT(ret >= 0 && ret < (ssize_t) sizeof req);
    size = fifo_read(client->input, req, ret + 1);
    RUNTIME_ASSERT(size == ret + 1);
    RUNTIME_ASSERT(req[ret] == '\0');
    url = strchr(req, '\n');
    RUNTIME_ASSERT(url);
    
    if (!url) {
      FATAL("BAD DNS lookup request");
      exit(EXIT_FAILURE);
    }
    
    *url++ = '\0';
    RUNTIME_ASSERT(NULL != skip_prefix(url, "http://"));

    if (dns_helper_lookup_host(req, &batch, &error)) {
      size_t i;

      for (i = 0; i < ARRAY_LEN(batch.addr); i++) {
        batch.addr[i] = net_addr_unspecified;
      }
    
      /* DNS lookup failed */
      DBUG("Could not resolve hostname");
    }
      
    size = strlen(url) + 1 + sizeof batch;
   
    {
      client_t *ctx;

      ctx = connection_get_context(dns_reply_con);
      client_queue_data(ctx, url, 1 + strlen(url));
      client_queue_data(ctx, cast_to_void_ptr(&batch), sizeof batch);
      dns_helper_event_write(dns_reply_con, EVT_WRITE);
      if (client_has_output(ctx))
        break;
    }
  }
}

static void
parent_exited(ev_watcher_t *w, pid_t pid)
{
  ev_watcher_check(w);
  (void) pid;

  INFO("Parent process exited");
  exit(EXIT_FAILURE);
}

static void
dns_helper_process(int query, int reply)
{
  connection_t *c;
  client_t *client;

  RUNTIME_ASSERT(query >= 0);
  RUNTIME_ASSERT(reply >= 0);
  RUNTIME_ASSERT(query != reply);
  watcher = ev_watcher_new();
  RUNTIME_ASSERT(watcher != NULL);

  c = connection_new(net_addr_unspecified, 0);
  if (c) {
    connection_set_source(c, ev_source_new(reply));
    client = client_new(c, watcher, 0, 0);
    if (!client) {
      goto out_of_memory;
    }
    connection_set_context(c, client);
    connection_set_blocking(c, false);
    connection_set_event_cb(c, dns_helper_event_write);
    ev_watcher_watch_source(watcher, connection_get_source(c), EVT_NONE);
  } else { 
    goto out_of_memory;
  }
  dns_reply_con = c;

  c = connection_new(net_addr_unspecified, 0);
  if (c) {
    connection_set_source(c, ev_source_new(query));
    client = client_new(c, watcher, BUFFERSIZE, 0); 
    if (!client) {
      goto out_of_memory;
    }
    connection_set_context(c, client);
    connection_set_event_cb(c, dns_helper_event_read);
    connection_set_blocking(c, false);
    ev_watcher_watch_source(watcher, connection_get_source(c), EVT_READ);
  } else {
    goto out_of_memory;
  }
  dns_query_con = c;
  
  ev_watcher_set_timeout(watcher, 300);
  ev_watcher_set_periodic_cb(watcher, dns_helper_periodic);
  ev_watcher_watch_process(watcher, getppid(), parent_exited);
  ev_watcher_mainloop(watcher);

  CRIT("%s: mainloop terminated", __func__);
  _exit(EXIT_FAILURE);

out_of_memory:

  CRIT("%s: Out of memory", __func__);
  _exit(EXIT_FAILURE);
}


int
dns_helper_initialize(int query, int reply)
{
  RUNTIME_ASSERT(getuid() != 0);
  RUNTIME_ASSERT(geteuid() != 0);
  
  if (!freopen(DEV_NULL, "r", stdin)) {
    CRIT("freopen() failed: %s", compat_strerror(errno));
    return -1;
  }
  if (!freopen(DEV_NULL, "w", stdout)) {
    CRIT("freopen() failed: %s", compat_strerror(errno));
    return -1;
  }
 
  if (dns_helper_reopen_logs(OPTION(log_dns))) {
    return -1;
  }
  
  if (SIG_ERR == set_signal(SIGHUP, sighup_handler)) {
    CRIT("set_signal(SIGHUP, sighup_handler) failed: %s",
        compat_strerror(errno));
    return -1;
  }

  dns_helper_process(query, reply);

  _exit(EXIT_FAILURE);
  /* NOT REACHED */
  return 0;
}

#endif /* ! HAVE_PTHREAD_SUPPORT */

/* vi: set ai et sts=2 sw=2 cindent: */
