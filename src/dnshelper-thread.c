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

#include "dnshelper.h"

#if defined(HAVE_PTHREAD_SUPPORT)

#include "lib/fifo.h"
#include "lib/connection.h"
#include "lib/event_watcher.h"
#include "lib/dns.h"

#include "options.h"
#include "client.h"

static ev_watcher_t *watcher;
static connection_t *dns_query_con;
static connection_t *dns_reply_con;
static dnslookup_ctx_t *dns_ctx;

static void *
lookup(void *arg)
{
  (void) arg;

  ev_watcher_mainloop(watcher);
  return NULL;
}

static int
dns_helper_lookup_host(const char *host, struct address_batch *batch,
    int *error)
{
  net_addr_t addr;
  size_t i;

  RUNTIME_ASSERT(dns_ctx != NULL);
  
  for (i = 0; i < ARRAY_LEN(batch->addr); i++) {
    batch->addr[i] = net_addr_unspecified;
  }
  
  if (dnslookup(dns_ctx, host, error)) {
    /* Could not resolve */
    dnslookup_ctx_reset(dns_ctx);
    return -1;
  }

  for (i = 0; i < ARRAY_LEN(batch->addr); /* NOTHING */) {
    size_t j;

    if (!dnslookup_next(dns_ctx, &addr))
      break;

    /* Check for dupes; getaddrinfo() usually returns the same
     * address multiple times when giving few hints. */
    for (j = 0; j < i; j++) {    
      if (net_addr_equal_ptr(&addr, &batch->addr[j]))
        break;
    }
    if (j < i)
      continue; /* ignore dupe */

    if (net_addr_is_private(addr)) {
      /* Not connecting to private address */
      *error = EACCES;
      continue;
    }
    
    batch->addr[i] = addr;
    i++;
  }

  dnslookup_ctx_reset(dns_ctx);
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
    return -1;
  }

  client_queue_data(client, host, host_len);
  client_queue_data(client, "\n", 1);
  client_queue_data(client, url, 1 + url_len);
 
  ev_watcher_watch_source(watcher, connection_get_source(c), EVT_WRITE);

  return 0;
}

/* DNS helper thread writes a reply */
static void
dns_helper_event_write(connection_t *c, ev_type_t ev)
{
  client_t *client;

  connection_check(c);
  client = connection_get_context(c);
  client_check(client);

  RUNTIME_ASSERT(connection_get_fd(c) != connection_get_fd(dns_query_con));
  
  if (ev & EVT_ERROR) {
    exit(EXIT_FAILURE);
    return;
  }
  
  if (ev & EVT_HANGUP) {
    exit(EXIT_SUCCESS);
    return;
  }
  
  if (ev & EVT_WRITE) {
    ssize_t ret;

    ret = client_send(client);
    if ((ssize_t) -1 == ret) {
      if (!is_temporary_error(errno)) {
        exit(EXIT_FAILURE);
      }
    } else if (0 == ret) {
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
  static struct timeval last_check;
  struct timeval now;
  client_t *client;

  connection_check(c);
  client = connection_get_context(c);
  client_check(client);

  RUNTIME_ASSERT(connection_get_fd(c) == connection_get_fd(dns_query_con));

  now = ev_source_get_stamp(connection_get_source(c));
  if (ev & EVT_ERROR) {
    /* shutting down due to error */
    exit(EXIT_FAILURE);
    return;
  }
  
  if (ev & EVT_HANGUP) {
    /* hangup */
    exit(EXIT_SUCCESS);
    return;
  }
  
  for (;;) { 
    struct address_batch batch;
    char req[MAX_URL_SIZE * 2];
    ssize_t ret, size;
    char *url;
    int error;
    
    RUNTIME_ASSERT(client->input);
    ret = client_recv(client);
    if ((ssize_t) -1 == ret) {
      if (!is_temporary_error(errno)) {
        /* client_recv() failed */;
        exit(EXIT_FAILURE);
      }
    } else if (ret == 0) {
      /* client_recv() returned zero */
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
      /* BAD DNS lookup request */
      exit(EXIT_FAILURE);
    }
    
    *url++ = '\0';
    RUNTIME_ASSERT(NULL != skip_prefix(url, "http://"));
    
    if (dns_helper_lookup_host(req, &batch, &error)) {
      size_t i;

      /* DNS lookup failed */
      for (i = 0; i < ARRAY_LEN(batch.addr); i++) {
        batch.addr[i] = net_addr_unspecified;
      }
    }
      
    last_check = now;
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

static int 
dns_helper_thread(int query, int reply)
{
  client_t *ctx;
  pthread_t t;

  RUNTIME_ASSERT(query >= 0);
  RUNTIME_ASSERT(reply >= 0);
  RUNTIME_ASSERT(query != reply);

  watcher = ev_watcher_new();
  ev_watcher_check(watcher);

  dns_reply_con = connection_new(net_addr_unspecified, 0);
  if (dns_reply_con) {
    connection_set_source(dns_reply_con, ev_source_new(reply));
    /* It is necessary to use the send FIFO because otherwise
     * client_queue_data() allocates buffer dynamically which would
     * not be thread-safe. */
    ctx = client_new(dns_reply_con, watcher, 0, BUFFERSIZE);
    if (!ctx)
      goto out_of_memory;

    connection_set_context(dns_reply_con, ctx);
    connection_set_blocking(dns_reply_con, false);
    connection_set_event_cb(dns_reply_con, dns_helper_event_write);
    ev_watcher_watch_source(watcher, connection_get_source(dns_reply_con),
      EVT_NONE);
  } else { 
    goto out_of_memory;
  }

  dns_query_con = connection_new(net_addr_unspecified, 0);
  if (dns_query_con) {
    connection_set_source(dns_query_con, ev_source_new(query));
    ctx = client_new(dns_query_con, watcher, BUFFERSIZE, 0); 
    if (!ctx)
      goto out_of_memory;
  
    connection_set_context(dns_query_con, ctx);
    connection_set_event_cb(dns_query_con, dns_helper_event_read);
    connection_set_blocking(dns_query_con, false);
    ev_watcher_watch_source(watcher, connection_get_source(dns_query_con),
      EVT_READ);
  } else {
    goto out_of_memory;
  }
  
  /* Set a timeout just to prevent that poll() spins in a tight loop */
  ev_watcher_set_timeout(watcher, 30000);
  
  if (NULL == (dns_ctx = dnslookup_ctx_new()))
      goto out_of_memory;

  if (pthread_create(&t, NULL, lookup, NULL)) {
    CRIT("pthread_create() failed: %s", compat_strerror(errno));
    return -1;
  }
  
  return 0;

out_of_memory:

  CRIT("%s: Out of memory", __func__);
  return -1;
}

int
dns_helper_initialize(int query, int reply)
{
  RUNTIME_ASSERT(getuid() != 0);
  RUNTIME_ASSERT(geteuid() != 0);
  
  return dns_helper_thread(query, reply);
}

#endif /* HAVE_PTHREAD_SUPPORT */

/* vi: set ai et sts=2 sw=2 cindent: */
