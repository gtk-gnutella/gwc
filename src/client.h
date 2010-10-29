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

#ifndef CLIENT_HEADER_FILE
#define CLIENT_HEADER_FILE

#include "lib/common.h"
#include "lib/connection.h"
#include "lib/event_watcher.h"
#include "lib/fifo.h"
#include "lib/list.h"
#include "lib/http.h"
#include "lib/nettools.h"
#include "lib/gwc.h"
#include "lib/mem_buf.h"

typedef enum {
  CLIENT_MAGIC = 0xfa189de3
} client_magic_t;

typedef struct client {
  client_magic_t magic;
  
  bool          finished;
  bool          closed;
  bool          has_search;
  bool          ignore_host_header;
  bool          wants_gwcs;
  uint32_t      proto_ver;
  uint64_t      rx_count;
  uint64_t      tx_count;
  ip_pref_t     ip_pref;
  connection_t  *con;
  fifo_t        *input;
  fifo_t        *fifo;
  list_t        *output;
  size_t        output_offset;
  ev_watcher_t  *watcher;
  http_t        http;
  http_output_t http_out;
  char          client_id[24];
  char          client_ver[24];
  char          x_gwc_url[sizeof "X-GWC-URL: \r\n" + MAX_ALLOWED_GWC_URL_LENGTH];
  char          x_remote_ip[sizeof "X-Remote-IP: \r\n" + NET_ADDR_BUFLEN];
} client_t;

void client_check(const client_t * const client);

client_t *client_new(connection_t *c, ev_watcher_t *w,
            size_t recv_fifo_buf, size_t send_fifo_buf);
int client_queue_mem_buf(client_t *client, struct mem_buf *mb);
int client_queue_data(client_t *client, const void *data, size_t size);
ssize_t client_send(client_t *);
ssize_t client_recv(client_t *client);
bool client_has_output(const client_t * const client);
void client_destruct(client_t *);

/* vi: set ai et sts=2 sw=2 cindent: */
#endif /* CLIENT_HEADER_FILE */
