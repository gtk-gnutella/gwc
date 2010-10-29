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

#ifndef APPEND_HEADER_FILE
#define APPEND_HEADER_FILE

#include "common.h"
#include "nettools.h"

/**
 * The purpose of these functions is provide convinient and fast buffer
 * handling. They should protect against buffer overflows but they do not
 * protect against truncation. Thus, provide sufficient provide sufficiently
 * large destination buffers - or use something else. They DO NOT provide
 * high-level (mindless) string functions.
 *
 * The prefix ``append_'' derives from the idea to return a pointer to the
 * end of the string instead of the beginning.
 *
 * Note that only the ``string'' functions add a terminating NUL. The other
 * functions DO NOT terminate the buffer and DO NOT reserve a single byte
 * for a NUL either.
 */

static inline char *
append_string(char *dst, size_t *size, const char *src)
{
  size_t left;
  const char *p;
  char *q;
  int c;
  
  RUNTIME_ASSERT(dst != NULL);
  RUNTIME_ASSERT(size != NULL);
  RUNTIME_ASSERT(*size <= INT_MAX);

  q = dst;
  left = *size;
  if (left != 0) {
    for (p = src; (c = *p) != '\0' && --left != 0; ++p, ++q) {
      *q = c;
    }
 
    *q = '\0';
    *size = left;
  }
  RUNTIME_ASSERT(*size <= INT_MAX);
  return q;
}

/**
 * Escapes ``unsafe'' characters but copies safe characters as-is.
 *
 * @return ``dst'' if the ``size'' is too small, a pointer after the last
 * character of the escaped string in ``dst''.
 */
static inline char *
append_escaped_char(char *dst, size_t *size, char ch)
{
  int c = (unsigned char) ch;
  char *q = dst;
  
  RUNTIME_ASSERT(dst != NULL);
  RUNTIME_ASSERT(size != NULL);
  RUNTIME_ASSERT(*size <= INT_MAX);
  
  if (*size < 1)
    return q;

  if (c < 32 || c > 126) {
    int e;

    switch (c) {
    case '\a': e = 'a'; break;
    case '\b': e = 'b'; break;
    case   27: e = 'e'; break;
    case '\f': e = 'f'; break;
    case '\n': e = 'n'; break;
    case '\r': e = 'r'; break;
    case '\t': e = 't'; break;
    case '\v': e = 'v'; break;
    default:
      e = 0;
    }

    if (e != 0) {
      if (*size >= 2) {
        *q++ = '\\';
        *q++ = e;
      }
    } else {
    
      if (*size >= 4) {
        int i;

        *q++ = '\\';
        for (i = 2; i >= 0; --i)
          *q++ = '0' + ((c >> (3 * i)) & 7);
      }
    }

  } else if (c == '"' || c == '\'' || c == '\\') {
    
    if (*size >= 2) {
      *q++ = '\\';
      *q++ = c;
    }

  } else {
    *q++ = c;
  }

  *size -= q - dst;
  RUNTIME_ASSERT(*size <= INT_MAX);
  return q;
}

static inline char *
append_escaped_string(char *dst, size_t *size, const char *src)
{
  size_t left;
  const char *p;
  char *q;
  int c;
  
  RUNTIME_ASSERT(dst != NULL);
  RUNTIME_ASSERT(size != NULL);
  RUNTIME_ASSERT(*size <= INT_MAX);

  q = dst;
  left = *size;
  if (left-- != 0) {
    
    for (p = src; (c = (unsigned char) *p) != '\0' && left > 1; ++p) {
      char *r;
      
      r = append_escaped_char(q, &left, c);
      if (q == r)
        break;
      q = r;
    }
 
    *q = '\0';
    *size = left;
  }
  RUNTIME_ASSERT(*size <= INT_MAX);
  return q;
}

static inline char *
append_escaped_chars(char *dst, size_t *size, const char *src, size_t len)
{
  size_t left;
  const char *p;
  char *q;
  
  RUNTIME_ASSERT(dst != NULL);
  RUNTIME_ASSERT(size != NULL);
  RUNTIME_ASSERT(*size <= INT_MAX);

  q = dst;
  left = *size;
  if (left != 0 && len != 0) {
    
    for (p = src; len-- > 0; ++p) {
      char *r;
      
      r = append_escaped_char(q, &left, *p);
      if (q == r)
        break;
      q = r;
    }
 
    *size = left;
  }
  RUNTIME_ASSERT(left <= INT_MAX);
  RUNTIME_ASSERT(*size <= INT_MAX);
  return q;
}

static inline char *
append_char(char *dst, size_t *size, char c)
{
  RUNTIME_ASSERT(dst != NULL);
  RUNTIME_ASSERT(size != NULL);
  RUNTIME_ASSERT(*size <= INT_MAX);

  if (*size > 0) {
    *dst++ = c;
    *size -= 1;
  }
  RUNTIME_ASSERT(*size <= INT_MAX);
  return dst;
}

static inline char *
append_chars(char *dst, size_t *size, const char *src, size_t len)
{
  RUNTIME_ASSERT(dst != NULL);
  RUNTIME_ASSERT(size != NULL);
  RUNTIME_ASSERT(len <= INT_MAX);
  RUNTIME_ASSERT(*size <= INT_MAX);

  if (len > *size)
    len = *size;

  if (len > 0) {
    memcpy(dst, src, len);
    *size -= len;
  }
  RUNTIME_ASSERT(*size <= INT_MAX);
  return &dst[len];
}

#define APPEND_STATIC_CHARS(dst, size, chars) \
  append_chars((dst), (size), (chars), sizeof (chars) - 1)

#define APPEND_CRLF(dst, size) APPEND_STATIC_CHARS(dst, size, "\r\n")

static inline char *
append_uint16(char *buf, size_t *size, uint16_t v)
{
  char *p;
  
  RUNTIME_ASSERT(buf != NULL);
  RUNTIME_ASSERT(size != NULL);
  RUNTIME_ASSERT(*size <= INT_MAX);
  
  p = print_uint16(buf, *size, v);
  *size -= p - buf;
  return p;
}

static inline char *
append_uint32(char *buf, size_t *size, uint32_t v)
{
  char *p;
  
  RUNTIME_ASSERT(buf != NULL);
  RUNTIME_ASSERT(size != NULL);
  RUNTIME_ASSERT(*size <= INT_MAX);
  
  p = print_uint32(buf, *size, v);
  *size -= p - buf;
  return p;
}

static inline char *
append_uint64(char *buf, size_t *size, uint64_t v)
{
  char *p;
  
  RUNTIME_ASSERT(buf != NULL);
  RUNTIME_ASSERT(size != NULL);
  RUNTIME_ASSERT(*size <= INT_MAX);
  
  p = print_uint64(buf, *size, v);
  *size -= p - buf;
  return p;
}

static inline char *
append_uint(char *buf, size_t *size, unsigned int v)
{
  char *p;
  
  RUNTIME_ASSERT(buf != NULL);
  RUNTIME_ASSERT(size != NULL);
  RUNTIME_ASSERT(*size <= INT_MAX);
  
  p = print_uint(buf, *size, v);
  *size -= p - buf;
  return p;
}

static inline char *
append_date(char *dst, size_t *size, time_t t)
{
  char *p;
  
  RUNTIME_ASSERT(dst != NULL);
  RUNTIME_ASSERT(size != NULL);
  RUNTIME_ASSERT(*size <= INT_MAX);
  
  p = print_rfc1123_date(dst, *size, t);
  *size -= p - dst;
  return p;
}

static inline char *
append_size(char *buf, size_t *size, uint64_t v)
{
  char *p;
  uint64_t i, f;
  const char *suf;
  
  RUNTIME_ASSERT(buf != NULL);
  RUNTIME_ASSERT(size != NULL);
  RUNTIME_ASSERT(*size <= INT_MAX);
  
  p = buf;
  suf = humanize_value(v, &i, &f);
  p = append_uint64(p, size, i);
  if (suf[0] != '\0') {
    p = append_char(p, size, '.');
    p = append_uint64(p, size, f);
    p = append_char(p, size, ' ');
    p = append_chars(p, size, suf, strlen(suf));
    p = append_char(p, size, 'B');
  } else {
    p = APPEND_STATIC_CHARS(p, size, " B");
  }
  return p;
}

/* vi: set ai et sts=2 sw=2 cindent: */
#endif /* APPEND_HEADER_FILE */
