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

#ifndef COBS_HEADER_FILE
#define COBS_HEADER_FILE

#include "common.h"

/**
 * Encodes data using COBS. It's not possible (except in special case) to
 * encode in-place, thus ``dst' and ``src'' must be different buffers.
 *
 * @param dst the destination buffer to hold the COBS encoded data, must be
 *        sufficiently large.
 * @param src the input data.
 * @param src_len the amount of input data in bytes.
 * @return the length of the COBS encoded data.
 */
static inline size_t
cobs_encode(char *dst, const char *src, size_t src_len)
{
  const char *end;
  char *d;
  
  RUNTIME_ASSERT(dst);
  RUNTIME_ASSERT(src);

  if (0 == src_len)
    return 0;
  
  end = &src[src_len];
  d = dst;
 
  do { 
    char c, *p;
    uint8_t n;
  
    n = 0x01;
    for (p = d++; 0x00 != (c = *src++); /* NOTHING */) {
      *d++ = c;
      if (0xff == ++n || src == end)
        break;
    }
    *p = n;
  } while (src != end);

  return d - dst;
}

/**
 * Calculates the amount of bytes needed for the COBS encoded data.
 *
 * @param src the input data.
 * @param src_len the amount of input data in bytes.
 * @return the length of COBS encoded data in bytes.
 */
static inline size_t
cobs_calc_len(const char *src, size_t src_len)
{
  size_t len = 0;
  uint8_t n = 0;
  
  RUNTIME_ASSERT(src);

  while (src_len-- > 0) {
    len++;
    if (0x00 != *src++ && 0xfe == ++n) {
      n = 0;
      len++;
    }
  }

  return len;
}

/**
 * Decodes COBS encoded data. COBS data must not contain zeros, such bytes
 * are ignored by the decoder. Decoding in-place is possible as COBS does
 * not compress data but may expand it slightly. Thus ``dst'' and ``src''
 * maybe be identical but must not overlap otherwise.
 *
 * @param dst the destination buffer, must be sufficiently large.
 * @param src the COBS encoded data.
 * @param src_len the amount of COBS data in bytes.
 * @return the length of the decoded data.
 */
static inline size_t
cobs_decode(char *dst, const char *src, size_t src_len)
{
  const char *end;
  char *d;
  
  RUNTIME_ASSERT(dst);
  RUNTIME_ASSERT(src);

  end = &src[src_len];
  d = dst;
  
  while (src != end) {
    uint8_t n;

    n = *src++;
    if (0x00 == n--) {
      /* Ignore invalid NUL bytes */
    } else {
      size_t left;
      const char *q;

      left = end - src;
      q = &src[MIN(n, left)];
      while (src != q) {
        *d++ = *src++;
      }

      if ((uint8_t) 0xfe != n && src != end) {
        *d++ = 0x00;
      }
    }
  }

  return d - dst;
}

/* vi: set ai et sts=2 sw=2 cindent: */
#endif /* COBS_HEADER_FILE */
