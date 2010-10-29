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

#include "http.h"

#include "nettools.h"
#include "append.h"

static const char http_default_useragent_header[] =
  "User-Agent: " HTTP_DEFAULT_USER_AGENT "\r\n";
static const char http_default_server_header[] =
  "Server: " HTTP_DEFAULT_USER_AGENT "\r\n";

static const char *http_useragent_header = http_default_useragent_header;
static const char *http_server_header = http_default_server_header;

int
http_set_useragent(const char *s)
{
  char *p;
  static const char ua_prefix[] = "User-Agent: ";
  static const char server_prefix[] = "Server: ";
  size_t len, size;
  
  if (!s) {
    if (http_useragent_header != http_default_useragent_header) {
      DO_FREE(http_useragent_header);
      http_server_header = http_default_server_header;
    }
    if (http_server_header != http_default_server_header) {
      DO_FREE(http_server_header);
      http_useragent_header = http_default_useragent_header;
    }
    return 0;
  }

  len = strlen(s);
  size = sizeof ua_prefix + len + sizeof "\r\n";
  p = calloc(1, size);
  if (!p) {
    WARN("calloc() failed");
    return -1;
  }
  if (http_useragent_header != http_default_useragent_header) {
    DO_FREE(http_useragent_header);
  }
  http_useragent_header = p;
  p = append_string(p, &size, ua_prefix);
  p = append_string(p, &size, s);
  p = APPEND_CRLF(p, &size);
 
  size = sizeof server_prefix + len + sizeof "\r\n";
  p = calloc(1, size);
  if (!p) {
    WARN("calloc() failed");
    return -1;
  }
  if (http_server_header != http_default_server_header) {
    DO_FREE(http_server_header);
  }
  http_server_header = p;
  p = append_string(p, &size, server_prefix);
  p = append_string(p, &size, s);
  p = APPEND_CRLF(p, &size);
  
  return 0;
}

static inline void
http_log(http_t *ctx, const char *fmt, ...) CHECK_FMT(2, 3);
  
static inline void
http_log(http_t *ctx, const char *fmt, ...)
{
  va_list ap;
  
  RUNTIME_ASSERT(ctx != NULL);
  RUNTIME_ASSERT(fmt != NULL);

  if (ctx->log_cb != NULL) {
    int saved_errno = errno;
    
    va_start(ap, fmt);
    ctx->log_cb(fmt, ap);
    va_end(ap);

    errno = saved_errno;
  }
}

static const char *
http_connection_header(const http_t *ctx)
{
  return ctx->keep_alive ? "Connection: keep-alive" : "Connection: close";
}

static int
http_send(http_t *ctx, const void *data, size_t size)
{
  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(ctx->output);
  RUNTIME_ASSERT(ctx->output->send);
  
  return ctx->output->send(ctx->output, data, size);
}

static int
http_send_str(http_t *ctx, const char *s)
{
  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(s);

  return http_send(ctx, s, strlen(s));
}


int
http_send_line(http_t *ctx, const char *header)
{
  RUNTIME_ASSERT(ctx != NULL);
  RUNTIME_ASSERT(header != NULL);

  if (0 != http_send_str(ctx, header) || 0 != http_send_str(ctx, "\r\n"))
    return -1;
  return 0;
}

int
http_send_status_line(http_t *ctx, unsigned int code, const char *msg)
{
  char buf[256], *p = buf;
  size_t size = sizeof buf;

  RUNTIME_ASSERT(code >= 100 && code <= 999);
  ACCLOG_SET(ctx->acclog, code, code);

  p = append_string(p, &size, "HTTP/1.1 ");
  p = append_uint(p, &size, code);
  p = append_char(p, &size, ' ');
  p = append_string(p, &size, msg);

#if 0
  DBUG("Sending HTTP response \"%s\"", buf);
#endif

  p = APPEND_CRLF(p, &size);
  
  p = APPEND_STATIC_CHARS(p, &size, "Date: ");
  p = append_date(p, &size, compat_mono_time(NULL));
  p = APPEND_CRLF(p, &size);

  if (
    0 != http_send(ctx, buf, sizeof buf - size) ||
    0 != http_send_str(ctx, http_server_header)
  )
    return -1;

  return 0;
}

/**
 * Marks the end of the message headers.
 */
int
http_terminate_headers(http_t *ctx)
{
  const char crlf[] = "\r\n";
  int ret;
  
  ret = http_send(ctx, crlf, STATIC_STRLEN(crlf));
  ACCLOG_COMMIT(ctx->acclog);
  return 0 != ret ? -1 : 0;
}

void
http_send_extra_headers(http_t *ctx)
{
  const snode_t *sn;
 
  ctx->extra_headers = snode_reverse(ctx->extra_headers);
  for (sn = ctx->extra_headers; NULL != sn; sn = sn->next) {
    http_send_line(ctx, sn->ptr);
  }
}

int
http_send_data(http_t *ctx, const char *data, size_t size)
{
  return http_send(ctx, data, size);
}

int
http_redirect(http_t *ctx, const char *url, bool permanent)
{
  static const char location[] = "Location: ";
  
  RUNTIME_ASSERT(url && strlen(url) > 0);

  if (permanent)
    http_send_status_line(ctx, 301, "Moved Permanently");
  else
    http_send_status_line(ctx, 307, "Temporary Redirect");
  
  http_send_line(ctx, http_connection_header(ctx));
  http_send_data(ctx, location, sizeof location - 1);
  http_send_line(ctx, url);
  http_send_extra_headers(ctx);
  http_terminate_headers(ctx);

  return 0;
}

void
http_set_content_length(http_t *ctx, uint64_t size)
{
  ctx->content_length = size;
}

int
http_send_content_length_header(http_t *ctx)
{
  if ((uint64_t) -1 != ctx->content_length) {
    static const char length_hdr[] = "Content-Length: ";
    char buf[UINT64_DEC_BUFLEN];

    http_send_data(ctx, length_hdr, sizeof length_hdr - 1);
    if (ctx->content_length > (uint32_t) -1) {
      print_uint64(buf, sizeof buf, ctx->content_length);
    } else {
      print_uint32(buf, sizeof buf, ctx->content_length);
    }
    return http_send_line(ctx, buf);
  }
  return 0;
}

int
http_send_document(http_t *ctx, const char *data, size_t size)
{
  RUNTIME_ASSERT(ctx != NULL);

  if (!ctx->status_code) {
    ctx->status_code = 200;
    ctx->status_msg = "OK";
  }
  http_send_status_line(ctx, ctx->status_code, ctx->status_msg);
  http_set_content_length(ctx, size);
  http_send_content_length_header(ctx);
  http_send_line(ctx, http_connection_header(ctx));
  http_send_extra_headers(ctx);
  ACCLOG_SET(ctx->acclog, size, size);
  http_terminate_headers(ctx);

  if (size > 0)
    http_send_data(ctx, data, size);
  
  return 0;
}

int
http_send_response(http_t *ctx)
{
  RUNTIME_ASSERT(ctx != NULL);

  if (!ctx->status_code) {
    ctx->status_code = 500;
    ctx->status_msg = "Internal Server Error";
  }

  http_send_status_line(ctx, ctx->status_code, ctx->status_msg);
  http_send_content_length_header(ctx);
  http_send_line(ctx, http_connection_header(ctx));
  http_send_extra_headers(ctx);
  http_terminate_headers(ctx);

  return 0;
}

int
http_send_text(http_t *ctx, const char *data, ssize_t size)
{
  http_add_header(ctx, "Content-Type: text/plain");
  http_send_document(ctx, data, size);
  return 0;
}

int
http_send_html(http_t *ctx, const char *data, ssize_t size)
{
  http_add_header(ctx, "Content-Type: text/html");
  http_send_document(ctx, data, size);
  return 0;
}

int
http_send_head_reply(http_t *ctx)
{
  
  http_send_status_line(ctx, 200, "OK");
  http_send_line(ctx, "Content-Type: text/plain");
  http_send_line(ctx, http_connection_header(ctx));
  http_terminate_headers(ctx);

  return 0;
}

int
http_send_ok(http_t *ctx)
{
  static const char msg[] = "OK\r\n";

  return http_send_text(ctx, msg, sizeof msg - 1);
}

void
http_request(http_t *ctx,
    const char *verb, const char *host, uint16_t port, const char *uri)
{
  http_log(ctx, "%s: host=\"%s\" uri=\"%s\"", __func__, host, uri);
  http_send_str(ctx, verb);
  http_send_str(ctx, " ");
  http_send_str(ctx, uri);
  http_send_line(ctx, " HTTP/1.1");

  http_send_str(ctx, "Host: ");
  http_send_str(ctx, host);
  if (port != HTTP_DEFAULT_PORT) {
    char buf[32], *p = buf;
    size_t size = sizeof buf;
    
    p = append_char(p, &size, ':');
    p = append_uint(p, &size, port);
    http_send_str(ctx, buf);
  }
  http_send_str(ctx, "\r\n");
  http_send_str(ctx, http_useragent_header);
  http_send_line(ctx, http_connection_header(ctx));
  http_send_extra_headers(ctx);
}

void
http_request_get(http_t *ctx, const char *host, uint16_t port, const char *uri)
{
  http_request(ctx, "GET", host, port, uri);
}

void
http_request_head(http_t *ctx, const char *host, uint16_t port, const char *uri)
{
  http_request(ctx, "HEAD", host, port, uri);
}

char *
http_parse_version(http_t *ctx, const char *s)
{
  char *endptr;
  uint32_t u;
  int error;

  RUNTIME_ASSERT(ctx);
 
  s = skip_prefix(s, "HTTP/");
  if (!s) {
    /* Not a valid HTTP version */
    return NULL;
  }

  u = parse_uint32(s, &endptr, 10, &error);
  if (error || 0 == u) {
    /* No valid http major version */
    return NULL;
  }
  ctx->major = u;
  if ('.' != *endptr) {
    /* Missing dot after major version number */
    return NULL;
  }
  s = ++endptr;
  
  u = parse_uint32(s, &endptr, 10, &error);
  if (error) {
    /* No valid http minor version */
    return NULL;
  }
  if (*endptr != '\0' && !isspace((unsigned char) *endptr)) {
    /* Invalid http minor version */
    return NULL;
  }
  ctx->minor = u;

  return endptr;
}

bool
http_is_separator(char c)
{
  switch (c) {
  case 9:   case 32:  case '(': case ')': case '<': case '>': case '@':
  case ',': case ';': case ':': case '\\': case '/': case '"': case '[':
  case ']': case '?': case '=': case '{': case '}':
    return true;

  default:
    return false;
  }
}

bool
http_is_tokenchar(char c)
{
  return c > 31 && c < 127 && !http_is_separator(c);
}

int
http_parse_date(const char *s, struct tm *tm)
{
  char *ep = NULL;

  RUNTIME_ASSERT(s);
  RUNTIME_ASSERT(tm);

  if (0 != parse_rfc1123_date(s, &ep, tm))
    if (0 != parse_asctime_date(s, &ep, tm))
      if (0 != parse_rfc850_date(s, &ep, tm))
        return -1;

  RUNTIME_ASSERT(NULL != ep);

  if ('\0' == *ep || http_is_separator(*ep))
    return 0;

  DBUG("Trailing character disqualifies date: \"%s\"", ep);
  return -1;
}

/**
 * Parses the payload of a HTTP "Range" header.
 *
 * A range with an "open end", is indicated by "end == (uint64_t) -1".
 *
 * @param s a NUL-terminated string containing the payload of a Ranger header.
 * @return 0 on failure, otherwise the amount of byte ranges in the header.
 */
size_t
http_parse_range(const char *s, struct byte_range_set **set_ptr)
{
  char *ep;
  int error;
  size_t n = 0;

  RUNTIME_ASSERT(s);

  if (set_ptr)
    *set_ptr = NULL;

  s = skip_spaces(s);
  s = skip_prefix(s, "bytes=");
  if (!s) {
    DBUG("Expected \"bytes=\"");
    goto failure;
  }
  
  while ('\0' != *s) {
    uint64_t start, end;
    
    s = skip_spaces(s);
    if (',' == *s) {
      s++;
      continue;
    }
    
    if ('-' == *s) {
      start = (uint64_t) -1;
      s++;

      if (!isdigit((unsigned char) *s)) {
        DBUG("Neither start nor end given");
        goto failure;
      }

    } else {
      start = parse_uint64(s, &ep, 10, &error);
      if (error || (uint64_t) -1 == start) {
        DBUG("Invalid range start");
        goto failure;
      }

      if ('-' != *ep) {
        DBUG("Expected '-'");
        goto failure;
      }

      s = ++ep;
    }

    if (!isdigit((unsigned char) *s)) {
      end = (uint64_t) -1;
    } else {
      end = parse_uint64(s, &ep, 10, &error);
      if (error || (uint64_t) -1 == end) {
        DBUG("Invalid range end");
        goto failure;
      }
      s = ep;
    }

    if ((uint64_t) -1 != start && start > end) {
      DBUG("range start is beyond range end");
      goto failure;
    }

    s = skip_spaces(s);
    if (',' == *s) {
      s++;
    } else if ('\0' != *s) {
      DBUG("bad character after byte range");
      goto failure;
    }

    n++;
    if (set_ptr) {
      struct byte_range_set *set = *set_ptr;

      if (!set) {
        const size_t min_num = 8;
        
        set = malloc(min_num * sizeof set->ranges + sizeof *set);
        if (!set) {
          CRIT("malloc() failed");
          goto failure;
        }
        set->n = 0;
        set->size = min_num;
        *set_ptr = set;
      }
      
      RUNTIME_ASSERT(*set_ptr);
      RUNTIME_ASSERT(set);
      
      if (set->n >= set->size) {
        void *p;

        set->size = 0 == set->size ? 8 : 2 * set->size;
        p = realloc(set, set->size * sizeof *set);
        if (!p) {
          CRIT("realloc() failed");
          goto failure;
        }
        *set_ptr = set = p;
      }

      set->ranges[set->n].start = start;
      set->ranges[set->n].end = end;
      set->n++;
    }
  }

  return n;

failure:

  DO_FREE(*set_ptr);
  
  return -1;
}
  
/**
 * Reads data from the http context buffer (decodes it if the transfer-
 * encoding isn't "identity") and transfers up to ``buflen'' bytes into
 * ``buf''. The http context MUST be in state HTTP_STATE_BODY.
 *
 * @returns (ssize_t) -1 on failure and sets errno. If errno is set to EAGAIN
 *          further data may be available later.
 *           
 *          If there's a transfer-encoding
 *          error, errno will be set to EIO. If (-1) is returned and errno
 *          has any other value than EAGAIN, the function MUST NOT be called
 *          again.
 */
ssize_t
http_read_body(http_t *ctx, char *buf, ssize_t buflen)
{
  ssize_t ret = 0, count = 0;
  uint64_t left;
  
  RUNTIME_ASSERT(ctx != NULL);
  RUNTIME_ASSERT(buf != NULL);
  RUNTIME_ASSERT(buflen >= 0);

  RUNTIME_ASSERT(ctx->sane);
  RUNTIME_ASSERT(ctx->state == HTTP_STATE_BODY);
  
  switch (ctx->encoding) {
  case HTTP_TRANSFER_ENCODING_IDENTITY:
    
    RUNTIME_ASSERT(ctx->content_length >= ctx->received);
    left = ctx->content_length - ctx->received;
    if (left == 0) {
      return 0;
    }

    RUNTIME_ASSERT(left > 0);
    ret = fifo_read(ctx->input, buf, MIN(left, (size_t) buflen));
    if (ret > 0) {
      ctx->received += ret;
    } else if (ret == 0) {
      errno = EAGAIN;
      return -1;
    }
    count = ret;
    break;

  case HTTP_TRANSFER_ENCODING_CHUNKED:

    while (!ctx->last_chunk && buflen > 0) {

      RUNTIME_ASSERT(ctx->content_length >= ctx->received);
      left = ctx->chunk_size - ctx->chunk_received;
      if (left > 0) {
        ret = fifo_read(ctx->input, buf, MIN(left, (size_t) buflen));
        if (ret > 0) {
          RUNTIME_ASSERT(ret <= buflen);
          ctx->chunk_received += ret;
          ctx->received += ret;
          buf += ret;
          buflen -= ret;
          count += ret;
        } else {
          if (ret == 0 && count == 0) {
            errno = EAGAIN;
            return -1;
          }
          return count;
        }
      } else {
        char chunk_intro[1024];
        ssize_t pos, size;
        uint64_t v;
        char *endptr;
        int error;

        /* If this isn't the first chunk, wait for trailing <CR><LF> */
        if (ctx->chunk_size > 0) {
          pos = fifo_findchar(ctx->input, '\n', sizeof chunk_intro);
          if (pos == (ssize_t) -1) {
            if (count > 0)
              return count;
            
            errno = EAGAIN;
            return -1;
          }

          RUNTIME_ASSERT(pos >= 0 && (size_t) pos < sizeof chunk_intro);
          size = fifo_read(ctx->input, chunk_intro, pos + 1);
          RUNTIME_ASSERT(size == pos + 1);
          RUNTIME_ASSERT(chunk_intro[pos] == '\n');
          chunk_intro[pos] = '\0';
        }
        RUNTIME_ASSERT(ctx->chunk_received == ctx->chunk_size);
        /* Mark the previous chunk as completely handled */
        ctx->chunk_sum_received += ctx->chunk_size;
        ctx->chunk_size = 0;
        ctx->chunk_received = 0;

        /* Determine the size of the next chunk */
        pos = fifo_findchar(ctx->input, '\n', sizeof chunk_intro);
        if (pos == (ssize_t) -1) {
          if (count > 0)
            return count;
          errno = EAGAIN;
          return -1;
        }
      
        RUNTIME_ASSERT(pos >= 0 && (size_t) pos < sizeof chunk_intro);
        size = fifo_read(ctx->input, chunk_intro, pos + 1);
        RUNTIME_ASSERT(size == pos + 1);
        RUNTIME_ASSERT(chunk_intro[pos] == '\n');
        chunk_intro[pos] = '\0';

        /* Read the chunk header and determine its size (hex value) */
        v = parse_uint64(chunk_intro, &endptr, 16, &error);
        if (
            (!v && error) ||
            (*endptr != '\0' && !isspace((unsigned char) *endptr))
        ) {
          errno = EIO;
          ctx->sane = false;
          return -1;
        }
        if (v == 0) {
          /* Only the last chunk has a zero length */
#if 1 
          http_log(ctx, "Last chunk reached");
#endif
          ctx->last_chunk = true;
          return count > 0 ? count : 0;
        }
#if 0 
        http_log(ctx, "chunk_size=%" PRIu64, v);
#endif
        ctx->chunk_size = v;
      }
    }
    break;

  default:
    RUNTIME_ASSERT(0);
  }

  return count;
}

static const struct tm http_zero_tm_;

static const http_t http_default_ctx = {
  (unsigned long) -1, /* major */
  (unsigned long) -1, /* minor */
  HTTP_REQ_UNKNOWN,   /* request */
  NULL,               /* uri */
  false,              /* debug_dump_headers */
  false,              /* keep_alive */
  HTTP_STATE_REQUEST, /* state */
  0,                  /* status_code */
  NULL,               /* status_msg */
  HTTP_TRANSFER_ENCODING_IDENTITY,  /* encoding */
  false,              /* last_chunk */
  true,               /* sane */
  false,              /* incoming */
  false,              /* proxied */
  0,                  /* chunk_received */
  0,                  /* chunk_sum_received */
  0,                  /* chunk_size */
  0,                  /* received */
  ~((uint64_t) 0U),   /* content_length */
  NULL,               /* host */
  (size_t) 0,         /* host_size */
  (in_port_t) 0,      /* port */
  NULL,               /* if_modified_since */
  NULL,               /* range_set */
  NULL,               /* input */
  NULL,               /* extra_headers */
  NULL,               /* acclog */
  NULL,               /* log_cb */
  NULL,               /* header_cb */
  NULL,               /* output */

  { 0, },             /* ims_buf */
};

http_t *
http_ctx_init(http_t *ctx, fifo_t *input)
{
  if (ctx) {
    *ctx = http_default_ctx;
    ctx->input = input;
  }
  return ctx;
}

void
http_set_status(http_t *ctx, unsigned int code, const char *msg)
{
  RUNTIME_ASSERT(ctx);
  if (ctx) {
    ctx->status_code = code;
    ctx->status_msg = msg;
  }
}

int
http_send_empty_reply(http_t *ctx)
{
  RUNTIME_ASSERT(ctx);
  
  ACCLOG_SET(ctx->acclog, size, 0);
  http_send_status_line(ctx, ctx->status_code, ctx->status_msg);
  http_send_line(ctx, http_connection_header(ctx));
  http_send_line(ctx, "Content-Length: 0");
  http_send_extra_headers(ctx);
  return http_terminate_headers(ctx);
}

/**
 * Reads a single HTTP header line from ctx->input and parses it.
 * Header continuation is handled transparently. Trailing space characters
 * are discarded from the header line and the line is NUL-terminated.
 * 
 * @param ctx an initialized ``http_t'' in state HTTP_STATE_HEADERS.
 * @param buf a work buffer.
 * @param buf_size the size of buf; this defines the maximum length of
 *        headers that can be handled.
 *
 * @return
 *   -1 if a header was invalid (see http status for details).
 *    0 if the end-of-headers was reached.
 *    1 if a header was successfully parsed.
 */
int
http_read_header(http_t *ctx, char *buf, size_t buf_size)
{
  char *p;
  size_t size;
 
  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(buf);
  RUNTIME_ASSERT(buf_size > 0);
  RUNTIME_ASSERT(ctx->state == HTTP_STATE_HEADERS);

  p = buf;
  size = buf_size;

  for (;;) {
    ssize_t r;
    
    r = fifo_findchar(ctx->input, '\n', size);
    if ((ssize_t) -1 == r) {
      if ((size_t) fifo_fill(ctx->input) > size)
        DBUG("Header line is too long");
      else
        DBUG("Header line is not yet terminated");

      ctx->keep_alive = false;
      http_set_status(ctx, 413, "Request Entity Too Large");
      return -1;
    }

    RUNTIME_ASSERT(r >= 0 && (size_t) r < size);

    /* Make sure the headers don't contain any NUL characters */
    if ((ssize_t) -1 != fifo_findchar(ctx->input, '\0', r)) {
      ctx->keep_alive = false;
      http_set_status(ctx, 400, "Bad Request (NUL in Header)");
      return -1;
    }

    fifo_read(ctx->input, p, 1 + r);
    RUNTIME_ASSERT('\n' == p[r]);

    /* Discard trailing '\r' characters */
    for (/* NOTHING*/; r > 0; r--) {
      if ('\r' != p[r - 1])
        break;
    }
    
    RUNTIME_ASSERT('\n' == p[r] || '\r' == p[r]);
    p[r] = '\0';

    /* Check for a header continuation with HT (0x09) or a space (0x20) */
    if (
      0 != fifo_findchar(ctx->input, 0x09, 1) &&
      0 != fifo_findchar(ctx->input, 0x20, 1)
    ) {
     
      /* Discard all trailing spaces */
      if (isspace((unsigned char) p[r])) {
        while (r > 0 && isspace((unsigned char) p[r - 1]))
          r--;

        p[r] = '\0';
      }
    
      break;
    }

    p += r;
    size -= r;

    /* Discard all consecutive HT and SP characters */
    fifo_skip_chars(ctx->input, fifo_fill(ctx->input), "\x09\x20");

    /* Replace all skipped space by a single space character */
    if (size > 0) {
      *p++ = 0x20;
      size--;
    }
  }
 
  if (ctx->debug_dump_headers) {
    http_log(ctx, "\t%s", buf);
  }

  if ('\0' == *buf) {
    ctx->state = HTTP_STATE_BODY;
    return 0;
  }
  
  return 1;
}

/**
 * Parses a HTTP header. If the header name contains illegal characters or has
 * a zero length, NULL is returned. The header name is converted to
 * lower-case and the ':' after the header name is overwritten with a NUL.
 *
 * @param buf a NUL-terminated string containing a HTTP header line.
 *
 * @return NULL on failure, a pointer the first character after the ':'.
 */
char *
http_parse_header_name(char *buf)
{
  char *p;
  int c;

  for (p = buf; '\0' != (c = (unsigned char) *p); p++) {
    /* RFC 822 Section 3.1.2 defines field-names */
    if (':' == c || c <= 32 || c >= 127)
      break;

    if (isupper(c))
      *p = tolower(c);
  }
   
  if (p == buf || ':' != *p) {
    return NULL;
  }

  *p++ = '\0';

  return p;
}

/**
 *  @return
 *   -1 if a header was invalid (see http status for details).
 *    0 if the end-of-headers was reached.
 *    1 if a header was successfully parsed.
 */
int
http_parse_header(http_t *ctx, char *buf, size_t buf_size,
    char **name_ptr, char **value_ptr)
{
  char *value;
 
  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(HTTP_STATE_HEADERS == ctx->state);

  if (name_ptr)
    *name_ptr = NULL;
  if (value_ptr)
    *value_ptr = NULL;
  
  switch (http_read_header(ctx, buf, buf_size)) {
  case -1:
    DBUG("http_read_header() failed: %u \"%s\"",
    ctx->status_code, ctx->status_msg);
    return -1;
    
  case 0:
    ctx->state = HTTP_STATE_BODY;
    return 0;

  case 1:
    break;

  default:
    RUNTIME_ASSERT(0);
    http_set_status(ctx, 500, "Internal Server Error");
    return -1;
  }

  value = http_parse_header_name(buf);
  if (!value) {
    http_set_status(ctx, 400, "Bad Request (Bad Header)");
    return -1;
  }

  if (name_ptr)
    *name_ptr = buf;
  
  if (value_ptr)
    *value_ptr = skip_spaces(value);
 
  return 1;
}

static int
http_handle_connection_header(http_t *ctx, const char *name, char *value)
{
  const char *p;

  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(name);
  RUNTIME_ASSERT(value);
  
  for (p = skip_spaces(value); '\0' != *p; p = skip_spaces(p)) {
    const char *token;
    size_t len;
    
    token = p;
    while (http_is_tokenchar(*p))
      p++;
    
    len = p - token; 

    while ('\0' != *p && !http_is_tokenchar(*p))
      p++;

#define TOKEN_MATCHES(x) \
    (len == (sizeof (x) - 1) && NULL != skip_ci_prefix(token, (x)))
    
    if (len > 0) {
      if (TOKEN_MATCHES("close")) {
        ctx->keep_alive = false;
#if 0
        DBUG("keep-alive disabled");
#endif
      } else if (TOKEN_MATCHES("keep-alive")) {
        ctx->keep_alive = true;
#if 0
        DBUG("keep-alive enabled");
#endif
      } else {
        DBUG("Unknown Connection value: \"%s\"", token);
      }
    }
    
#undef TOKEN_MATCHES
    
  }

  return 0;
}

/**
 * @return NULL if the host is invalid, otherwise a pointer to first character
 *         after the host.
 */
char *
http_parse_host(const char *s)
{
  const char *p;
  int c;
  
  RUNTIME_ASSERT(s);

  {
    char *ep;
    
    if (parse_net_addr(s, NULL, &ep))
      return ep;
  }
  
  p = s;
  c = (unsigned char) *p++;
  if (!isalnum(c))
    return NULL;

  for (;; p++) {
    int b;

    b = c;
    c = (unsigned char) *p;
   
    switch (c) {
    case '.':
      {
        int d;
        
        if (!isalnum(b))
          return NULL;
        
        d = (unsigned char) p[1];
        if (!isalnum(d) && ':' != d && '/' != d)
          return NULL;
      }
      break;

    case '-':
      {
        int d;
        
        if (!isalnum(b) && '-' != b)
          return NULL;
        
        d = (unsigned char) p[1];
        if (!isalnum(d) && '-' != d)
          return NULL;
      }
      break;
      
    case '/':
    case ':':
    case '\0':
      if ('.' != b && !isalnum(b))
        return NULL;

      return deconstify_char_ptr(p);
      
    default:
      if (!isalnum(c))
        return NULL;
    }

  }
  
  return NULL;
}

void
http_set_host(http_t *ctx, const char *host)
{
  if (ctx->host) {
    mem_chunk_free(ctx->host, ctx->host_size);
    ctx->host = NULL;
    ctx->host_size = 0;
  }
  if (host) {
    const char *endptr;
    size_t len;

    endptr = strchr(host, ':');
    if (!endptr) {
      endptr = strchr(host, '\0');
    }
    len = endptr - host;
    ctx->host_size = 1 + len;
    ctx->host = mem_chunk_copy(host, ctx->host_size);
    ctx->host[len] = '\0';
  }
}

const char *
http_get_host(const http_t *ctx)
{
  return ctx->host;
}

static int
http_handle_host_header(http_t *ctx, const char *name, char *value)
{
  size_t size;
  char *ep;

  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(name);
  RUNTIME_ASSERT(value);
 
  if ('\0' != value[0]) {
    ep = http_parse_host(value);
    if (!ep) {
      goto bad_host;
    }
  } else {
    ep = value;
  }

  size = 1 + ep - value;

  if (':' != *ep) {
    ctx->port = 0;
  } else {
    ep++;
    if (!parse_port_number(ep, &ctx->port, &ep)) {
      http_set_status(ctx, 400, "Bad Request (Bad Port)");
      return -1;
    }
  }

  ep = skip_spaces(ep);
  if ('\0' != *ep) {
    goto bad_host;
  }

  http_set_host(ctx, value);

  return 0;

bad_host:
  
  http_set_status(ctx, 400, "Bad Request (Bad Host)");
  return -1;
}

static int
http_handle_transfer_encoding_header(http_t *ctx,
    const char *name, char *value)
{
  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(name);
  RUNTIME_ASSERT(value);

  if (0 == strcasecmp(value, "chunked")) {
    ctx->encoding = HTTP_TRANSFER_ENCODING_CHUNKED;
    return 0;
  }
  
  http_set_status(ctx, 400, "Bad Request (Bad Transfer-Encoding)");
  return -1;
}

static int
http_handle_content_length_header(http_t *ctx, const char *name, char *value)
{
  uint64_t u;
  int error;
  char *ep;

  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(name);
  RUNTIME_ASSERT(value);
  
  u = parse_uint64(value, &ep, 10, &error);
  if (error || '\0' != *ep) {
    http_set_status(ctx, 400, "Bad Request (Bad Content-Length)");
    return -1;
  }
  ctx->content_length = u;

  return 0;
}

static int
http_handle_user_agent_header(http_t *ctx, const char *name, char *value)
{
  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(name);
  RUNTIME_ASSERT(value);
  
  ACCLOG_SET(ctx->acclog, user_agent, value);
  return 0;
}

static int
http_handle_referer_header(http_t *ctx, const char *name, char *value)
{
  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(name);
  RUNTIME_ASSERT(value);
  
  ACCLOG_SET(ctx->acclog, referer, value);
  return 0;
}

static int
http_handle_proxy_header(http_t *ctx, const char *name, char *value)
{
  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(name);
  RUNTIME_ASSERT(value);
  
  ctx->proxied = true;
  return 0;
}
    
static int
http_handle_if_modified_since_header(http_t *ctx, const char *name, char *value)
{
  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(name);
  RUNTIME_ASSERT(value);
  
  ctx->if_modified_since = 0 == http_parse_date(value, &ctx->ims_buf.tm)
    ? &ctx->ims_buf.tm
    : NULL;

  return 0;
}

static int
http_handle_range_header(http_t *ctx, const char *name, char *value)
{
  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(name);
  RUNTIME_ASSERT(value);
  
  if (0 == http_parse_range(value, &ctx->range_set)) {
    DBUG("Ignoring unparsable Range header");
  }

  return 0;
}

int
http_handle_header(http_t *ctx, const char *name, char *value)
{
  static const struct {
    const char *name;
    int (* func)(http_t *, const char *, char *);
  } headers[] = {
    { "client-ip",          http_handle_content_length_header },
    { "connection",         http_handle_connection_header },
    { "content-length",     http_handle_content_length_header },
    { "forwarded",          http_handle_proxy_header },
    { "host",               http_handle_host_header },
    { "if-modified-since",  http_handle_if_modified_since_header },
    { "user-agent",         http_handle_user_agent_header },
    { "range",              http_handle_range_header },
    { "referer",            http_handle_referer_header },
    { "transfer-encoding",  http_handle_transfer_encoding_header },
    { "via",                http_handle_proxy_header },
    { "x-forwarded-for",    http_handle_proxy_header },
  };
  size_t i;

  if (ctx->header_cb && ctx->header_cb->parse) {
    int ret;

    ret = ctx->header_cb->parse(ctx->header_cb, name, value);
    if (ret < 0)
      return -1;
    if (0 != ret)
      return 0;
  }

  for (i = 0; i < ARRAY_LEN(headers); i++) {
    if (0 == strcmp(name, headers[i].name)) {
      return headers[i].func(ctx, name, value);
    }
  }

#if 0
  DBUG("Unhandled header: \"%s\"", name);
#endif
  return 0;
}

/**
 *  @return
 *   -1 if a header was invalid (see http status for details)
 *    0 if all headers are successfully handled (end-of-header reached)
 */
int
http_process_headers(http_t *ctx, char *buf, size_t buf_size)
{
  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(HTTP_STATE_HEADERS == ctx->state);
  
  for (;;) {
    char *name, *value;
    
    name = value =  NULL;
    switch (http_parse_header(ctx, buf, buf_size, &name, &value)) {
    case -1:
      DBUG("http_parse_header() failed: %u \"%s\"",
        ctx->status_code, ctx->status_msg);
      return -1;
      
    case 0:
      RUNTIME_ASSERT(HTTP_STATE_BODY == ctx->state);
      return 0;

    case 1:
      break;

    default:
      RUNTIME_ASSERT(0);
      http_set_status(ctx, 500, "Internal Server Error");
      return -1;
    }

    RUNTIME_ASSERT(HTTP_STATE_HEADERS == ctx->state);
    RUNTIME_ASSERT(name);
    RUNTIME_ASSERT(value);

#if 0
    http_log(ctx, "name=\"%s\"; value=\"%s\"", name, value);
#endif
    
    if (0 != http_handle_header(ctx, name, value))
      break;
  }

  return -1;
}


/*
 * Determines the HTTP method from the NUL-terminated string ``token''.
 * If ``ctx'' is not NULL, ctx->req will be set to the result.
 */
http_req_t
http_get_request_method(http_t *ctx, const char *token)
{
  static const struct {
    const http_req_t method;
    const char * const str;
  } methods[] = {
    { HTTP_REQ_GET,     "GET"     }, 
    { HTTP_REQ_HEAD,    "HEAD"    }, 
    { HTTP_REQ_OPTIONS, "OPTIONS" }, 
    { HTTP_REQ_POST,    "POST"    }, 
    { HTTP_REQ_PUT,     "PUT"     }, 
    { HTTP_REQ_TRACE,   "TRACE"   },
    { HTTP_REQ_CONNECT, "CONNECT" }
  };
  http_req_t req = HTTP_REQ_UNKNOWN;
  unsigned int i;
  
  for (i = 0; i < ARRAY_LEN(methods); i++)
    if (!strcmp(methods[i].str, token))
      req = methods[i].method;
  
  if (ctx)
    ctx->request = req;
  
  return req;
}

int
http_read_response(http_t *ctx)
{
  char buf[BUFFERSIZE];
  char *p, *endptr;
  uint32_t code;
  ssize_t ret, size;
  int error;

  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(ctx->state == HTTP_STATE_REQUEST);
  
  ret = fifo_findchar(ctx->input, '\n', sizeof buf);
  if (ret < 0) {
    return 0;
  }
  if ((size_t) ret >= sizeof buf) {
    http_log(ctx, "HTTP response line is too long");
    return -1;
  }
  size = ret + 1;
  ret = fifo_read(ctx->input, buf, size);
  RUNTIME_ASSERT(ret > 0 && (size_t) ret <= sizeof buf);
  ret--;
  RUNTIME_ASSERT(buf[ret] == '\n');

  while (ret >= 0 && isspace((unsigned char) buf[ret]))
    buf[ret--] = '\0';

  http_log(ctx, "buf=\"%s\"", buf);
  
  p = http_parse_version(ctx, buf);
  if (!p) {
    http_log(ctx, "Not a HTTP reply: %s", buf);
    return -1;
  }
  if (!isspace((unsigned char) *p)) {
    http_log(ctx, "Missing space after HTTP/x.y: %s", buf);
    return -1;
  }

  p = skip_spaces(p);
  
  if (!isdigit((unsigned char) *p)) {
    http_log(ctx, "Invalid HTTP status code: %s", buf);
    return -1;
  }

  code = parse_uint32(p, &endptr, 10, &error);
  if (*endptr != '\0' && !isspace((unsigned char) *endptr)) {
    http_log(ctx, "Invalid HTTP status code: %s", buf);
    return -1;
  }
  if (code < 100 || code > 999) {
    http_log(ctx, "HTTP status code is out-of-range: %s", buf);
    return -1;
  }

  /* Don't care about the rest of the line */

  ctx->status_code = code;
  ctx->state = HTTP_STATE_HEADERS;
  return 0;
}

int
http_add_header(http_t *ctx, const char *header)
{
  snode_t *sn;

  sn = snode_new(deconstify_char_ptr(header));
  if (!sn)
    return -1;
    
  ctx->extra_headers = snode_prepend(ctx->extra_headers, sn);
  return 0;
}

/**
 * Sets the default values for the given <major>.<minor> HTTP version.
 */
void
http_set_defaults(http_t *ctx)
{
  RUNTIME_ASSERT(ctx);

  ctx->keep_alive = http_at_least_ver(ctx, 1, 1) ? true : false;
}

void
http_destruct(http_t *ctx)
{
  DO_FREE(ctx->range_set);
  mem_chunk_free(ctx->host, ctx->host_size);
  ctx->host = NULL;

  /* Free the extra headers, if any */
  while (ctx->extra_headers) {
    snode_t *next;
  
    next = ctx->extra_headers->next;
    snode_free(ctx->extra_headers);
    ctx->extra_headers = next;
  }
}

/* vi: set ai et sts=2 sw=2 cindent: */
