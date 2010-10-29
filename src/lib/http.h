/*
 * Copyright (c) 2005
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

#ifndef HTTP_HEADER_FILE
#define HTTP_HEADER_FILE

#include "common.h"
#include "oop.h"
#include "mem.h"
#include "snode.h"
#include "fifo.h"
#include "acclog.h"

#ifndef HTTP_DEFAULT_USER_AGENT
#define HTTP_DEFAULT_USER_AGENT "GhostWhiteCrab"
#endif /* HTTP_DEFAULT_USER_AGENT */

#define HTTP_DEFAULT_PORT 80

#define http_at_least_ver(http, a, b) \
  ((http)->major > (a) || ((http)->major == (a) && (http)->minor == (b)))
 
typedef enum {
  HTTP_REQ_UNKNOWN,
  HTTP_REQ_GET,
  HTTP_REQ_HEAD,
  HTTP_REQ_OPTIONS,
  HTTP_REQ_POST,
  HTTP_REQ_PUT,
  HTTP_REQ_TRACE,
  HTTP_REQ_CONNECT
} http_req_t;

typedef enum {
  HTTP_STATE_REQUEST,
  HTTP_STATE_HEADERS,
  HTTP_STATE_BODY
} http_state_t;

typedef enum {
  HTTP_TRANSFER_ENCODING_IDENTITY,
  HTTP_TRANSFER_ENCODING_CHUNKED,
  HTTP_TRANSFER_ENCODING_UNKNOWN
} http_transfer_encoding_t;

struct byte_range {
    uint64_t start, end;
};

struct byte_range_set {
  size_t n;                   /* The number of used ranges */
  size_t size;                /* The size of ranges in elements */
  struct byte_range ranges[1 /* Pseudo size*/];
};

typedef struct http_output {
  void *data;
  int (*send)(struct http_output *, const void *data, size_t size);
} http_output_t;

typedef struct http_header_cb {
  void *data;
  int (*parse)(struct http_header_cb *, const char *name, const char *value);
} http_header_cb_t;

typedef struct http {
  unsigned long             major, minor;
  http_req_t                request;
  const char                *uri;
  bool                      debug_dump_headers;
  bool                      keep_alive;
  http_state_t              state;
  unsigned int              status_code;
  const char                *status_msg;
  http_transfer_encoding_t  encoding;
  bool                      last_chunk;
  bool                      sane;
  bool                      incoming;
  bool                      proxied;
  uint64_t                  chunk_received;
  uint64_t                  chunk_sum_received;
  uint64_t                  chunk_size;
  uint64_t                  received;
  uint64_t                  content_length;
  char                      *host;
  size_t                    host_size;
  in_port_t                 port;
  const struct tm           *if_modified_since;
  struct byte_range_set     *range_set;
  fifo_t                    *input;
  snode_t                   *extra_headers;
  acclog_t                  *acclog;
  void                     (*log_cb)(const char *fmt, va_list ap);
  struct http_header_cb     *header_cb;
  struct http_output        *output;
  
  union {
    char pseudo_;    /* just to allow initialization with { 0, } */
    struct tm tm;
  } ims_buf;     /* ``struct tm'' buffer for if-modified-since */

} http_t;

struct http_response {
  char  msg[128]; /* must be the first member */
  int   code;
};

static const char http_prefix[] = "http://";

int http_send_line(http_t *, const char *);
int http_send_status_line(http_t *, unsigned int, const char *);
int http_send_ok(http_t *);
void http_request_get(http_t *, const char *, uint16_t, const char *);
void http_request_head(http_t *, const char *, uint16_t, const char *);
char * http_parse_version(http_t *, const char *);
char *http_parse_host(const char *s);
int http_terminate_headers(http_t *);
int http_send_data(http_t *, const char *, size_t);
int http_send_document(http_t *ctx,  const char *data, size_t size);
int http_send_text(http_t *, const char *data, ssize_t size);
int http_send_html(http_t *, const char *data, ssize_t size);
int http_send_head_reply(http_t *);
int http_redirect(http_t *, const char *url, bool permamnent);
bool http_is_separator(char c);
bool http_is_tokenchar(char c);
ssize_t http_read_body(http_t *, char *, ssize_t);
http_t * http_ctx_init(http_t *, fifo_t *);
void http_set_status(http_t *, unsigned int, const char *);
int http_send_response(http_t *ctx);
int http_send_empty_reply(http_t *);
int http_process_headers(http_t *ctx, char *buf, size_t buf_size);
int http_read_response(http_t *ctx);
int http_set_useragent(const char *s);
void http_set_content_length(http_t *ctx, uint64_t size);
void http_set_host(http_t *ctx, const char *host);
const char *http_get_host(const http_t *ctx);
http_req_t http_get_request_method(http_t *ctx, const char *token);
int http_add_header(http_t *ctx, const char *header);
void http_set_defaults(http_t *ctx);
void http_destruct(http_t *ctx);

/* vi: set ai et sts=2 sw=2 cindent: */
#endif /* HTTP_HEADER_FILE */
