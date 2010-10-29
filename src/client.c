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

#include "client.h"
#include "lib/mem.h"
#include "lib/mem_buf.h"

void
client_check(const client_t * const client)
{
  RUNTIME_ASSERT(client);
  RUNTIME_ASSERT(CLIENT_MAGIC == client->magic);
}

bool
client_has_output(const client_t * const client)
{
  client_check(client);
  return (client->output && !list_empty(client->output)) ||
    (client->fifo && !fifo_empty(client->fifo));
}

int 
client_queue_data(client_t *client, const void *data, size_t size)
{
  static const size_t bufsize = 1024;
  struct mem_buf *mb;
  const char *p = data;

  client_check(client);
  RUNTIME_ASSERT(client->output);
  RUNTIME_ASSERT(data);
  RUNTIME_ASSERT(size > 0);

  if (client->fifo) {
    return fifo_write(client->fifo, data, size);
  }

  mb = list_get_last(client->output);

  while (size > 0) {
    size_t len;

    if (mb) {
      RUNTIME_ASSERT(mb->base);
      RUNTIME_ASSERT(mb->size > 0);
      RUNTIME_ASSERT(mb->fill > 0);
      RUNTIME_ASSERT(mb->fill <= mb->size);
    }
    
    if (!mb || mb->fill == mb->size) {
      if (size > bufsize) {
        mb = mem_buf_new_copy(p, size);
        RUNTIME_ASSERT(mb);
        list_append(client->output, mb);
        break;
      } else {
        mb = mem_buf_new_chunk(bufsize);
        RUNTIME_ASSERT(mb);
        list_append(client->output, mb);
      }
    }

    len = mb->size - mb->fill;
    len = MIN(len, size);
    memcpy((char *) mb->base + mb->fill, p, len);
    mb->fill += len;
    p += len;
    size -= len;
  }

  return 0;
}

int 
client_queue_mem_buf(client_t *client, struct mem_buf *mb)
{
  client_check(client);
  RUNTIME_ASSERT(client->output);
  RUNTIME_ASSERT(mb);
  RUNTIME_ASSERT(mb->refs > 0);

  if (mb->fill < 1024) {
    client_queue_data(client, mb->base, mb->fill);
  } else {
    mem_buf_ref(mb); 
    list_append(client->output, mb);
  }
  return 0;
}

static int 
client_http_send(struct http_output *http_out, const void *data, size_t size)
{
  client_t *client;
  
  RUNTIME_ASSERT(http_out);
  RUNTIME_ASSERT(http_out->data);
  RUNTIME_ASSERT(data);

  client = http_out->data;
  client_check(client);
  return client_queue_data(client, data, size);
}

client_t *
client_new(connection_t *c, ev_watcher_t *w,
    size_t recv_fifo_buf, size_t send_fifo_buf)
{
  client_t *client;
  
  connection_check(c);
  ev_watcher_check(w);
  RUNTIME_ASSERT(connection_get_fd(c) >= 0);
  
  client = mem_chunk_alloc(sizeof *client);
  if (client) {
    static const client_t zero_client;

    *client = zero_client;
    client->magic = CLIENT_MAGIC;
    client->con = c;
    client->watcher = w;
    client->input = recv_fifo_buf > 0 ? fifo_new(recv_fifo_buf) : NULL;
    client->fifo = send_fifo_buf > 0 ? fifo_new(send_fifo_buf) : NULL;
    client->output = list_new();
    client->ip_pref = IP_PREF_NONE;
    client->http_out.data = client;
    client->http_out.send = client_http_send;
  }
  return client;
}

static ssize_t
client_send_buffers(client_t *client)
{
  ssize_t ret = 0;
  list_iter_t i;
  struct iovec vec[16];
  unsigned n = 0;
  bool v;

  client_check(client);
  RUNTIME_ASSERT(client->output);
  
  for (v = list_iter_first(&i, client->output); v; v = list_iter_next(&i)) {
    const struct mem_buf *mb;

    mb = list_iter_get_ptr(&i);
    RUNTIME_ASSERT(mb);
    RUNTIME_ASSERT(mb->base);
    RUNTIME_ASSERT(mb->size > 0);
    RUNTIME_ASSERT(mb->fill > 0);
    RUNTIME_ASSERT(mb->fill <= mb->size);

    if (0 == n) {
      RUNTIME_ASSERT(mb->fill > client->output_offset);

      vec[n].iov_base = (char *) mb->base + client->output_offset;
      vec[n].iov_len = mb->fill - client->output_offset;
    } else {
      vec[n].iov_base = mb->base;
      vec[n].iov_len = mb->fill;
    }

    if (++n >= ARRAY_LEN(vec))
      break;
   }
 
  if (n > 0) {
    int fd;

    fd = connection_get_fd(client->con);
    ret = writev(fd, vec, n);
  }

  if ((ssize_t) -1 != ret) {
    size_t written = (size_t) ret;
  
    for (v = list_iter_first(&i, client->output); v; v = list_iter_next(&i)) {
      struct mem_buf *mb;
      size_t len;

      mb = list_iter_get_ptr(&i);
      RUNTIME_ASSERT(mb->fill >= client->output_offset);
      len = mb->fill - client->output_offset;

      if (written >= len) {
        written -= len;
        client->output_offset = 0;
        mem_buf_unref(mb);
        list_iter_delete(&i);
      } else {
        client->output_offset += written;
        break;
      }
    }
  }

  return ret;
}

ssize_t
client_send(client_t *client)
{
  ssize_t ret;

  client_check(client);

  if (client->fifo && !fifo_empty(client->fifo)) {
    ret = fifo_writev(client->fifo, connection_get_fd(client->con));
  } else {
    ret = client_send_buffers(client);
  }
  if ((ssize_t) -1 != ret) {
    client->tx_count += ret;
  }
  return ret;
}

ssize_t
client_recv(client_t *client)
{
  ssize_t ret;
  int fd;
  
  client_check(client);
  RUNTIME_ASSERT(client->input);

  fd = connection_get_fd(client->con);
  RUNTIME_ASSERT(fd >= 0);

  ret = fifo_recv(client->input, fd);
  if ((ssize_t) -1 != ret) {
    client->rx_count += (size_t) ret;
  }
  return ret;
}

void
client_destruct(client_t *client)
{
  client_check(client);

  {
    list_iter_t i;
    bool v;

    for (v = list_iter_first(&i, client->output); v; v = list_iter_next(&i)) {
      mem_buf_unref(list_iter_get_ptr(&i));
    }
  }
  list_free(client->output);
  client->output = NULL;

  fifo_destruct(client->input);
  client->input = NULL;

  fifo_destruct(client->fifo);
  client->fifo = NULL;

  mem_chunk_free(client, sizeof *client);
}

/* vi: set ai et sts=2 sw=2 cindent: */
