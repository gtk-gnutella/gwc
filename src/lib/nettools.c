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

#include "nettools.h"
#include "append.h"
#include "base32.h"

#include "debug.h"

hash_t
hash_str(const char *src)
{
  uint32_t h = 0x2346ad27;
  const char *s = src;

  while (*s) {
    h ^= *s++ ^ (h >> 31) ^ (h >> 13) ^ (h << 4);
    h <<= 1;
  }
  return h ^ (hash_t)(s - src);
}

bool
cmp_str(const char *a, const char *b)
{
  return a == b || 0 == strcmp(a, b);
}

/**
 * Converts an integer to a single hexadecimal ASCII digit. The are no checks,
 * this is just a convenience function.
 *
 * @param x An integer between 0 and 15.
 * @return The ASCII character corresponding to the hex digit [0-9a-f].
 */
static inline char
hex_digit(unsigned char x)
{
  static const char hex_alphabet[] = "0123456789abcdef";
  return hex_alphabet[x & 0xf]; 
}

/**
 * Converts an integer to a single decimal ASCII digit. The are no checks,
 * this is just a convenience function.
 *
 * @param x An integer between 0 and 9.
 * @return The ASCII character corresponding to the decimal digit [0-9].
 */
static inline char
dec_digit(unsigned char x)
{
  static const char dec_alphabet[] = "0123456789";
  return dec_alphabet[x % 10];
}


char *
print_uint(char *dst, size_t size, unsigned int v)
{
  char buf[UINT64_DEC_BUFLEN];
  char *p, *q;

  RUNTIME_ASSERT(size <= INT_MAX);  
  if (size < 1)
    return dst;

  p = &buf[sizeof buf - 1];
  do {
    *p = v % 10 + '0';
    if (v < 10)
      break;
    v /= 10;
  } while (--p != buf);

  for (q = dst; --size > 0 && p != &buf[sizeof buf]; p++) {
    *q++ = *p;
  }
  *q = '\0';
  return q; /* points to trailing NUL */
}

static inline size_t
print_uint16_hex(char *dst, uint16_t v)
{
  static const char hexa[] = "0123456789abcdef";
  char *p = dst;
  int i;

  for (i = 0; i < 3; i++, v <<= 4) {
    uint8_t d;

    d = v >> 12;
    if (0 != d || p != dst)
      *p++ = hexa[d];
  }
  *p++ = hexa[v >> 12];

  return p - dst;
}

/**
 * @returns NULL in case of failure; pointer to the trailing NUL otherwise
 */
char *
print_uint16(char *dst, size_t size, uint16_t v)
{
  char buf[UINT16_DEC_BUFLEN], *q;
  unsigned i;
  
  RUNTIME_ASSERT(size <= INT_MAX);  
  if (size < 1)
    return dst;

  for (i = 0; /* NOTHING */; v /= 10) {
    static const char deca[] = "0123456789";

    buf[i++] = deca[v % 10];
    if (v < 10)
      break;
  }

  if (i >= size)
    i = size - 1;

  q = dst;
  while (i > 0)
    *q++ = buf[--i];

  *q = '\0';
  return q; /* points to trailing NUL */
}

/**
 * @returns NULL in case of failure; pointer to the trailing NUL otherwise
 */
char *
print_uint32(char *dst, size_t size, uint32_t v)
{
  char buf[UINT32_DEC_BUFLEN], *q;
  unsigned i;
  
  RUNTIME_ASSERT(size <= INT_MAX);  
  if (size < 1)
    return dst;

  for (i = 0; /* NOTHING */; v /= 10) {
    static const char deca[] = "0123456789";

    buf[i++] = deca[v % 10];
    if (v < 10)
      break;
  }

  if (i >= size)
    i = size - 1;

  q = dst;
  while (i > 0)
    *q++ = buf[--i];

  *q = '\0';
  return q; /* points to trailing NUL */
}


/* Returns: NULL in case of failure; pointer to the trailing NUL otherwise */

char *
print_uint64(char *dst, size_t size, uint64_t v)
{
  char buf[UINT64_DEC_BUFLEN];
  char *p, *q;
  
  RUNTIME_ASSERT(size <= INT_MAX);  
  if (size < 1)
    return dst;

  if (v <= (uint32_t) -1)
    return print_uint32(dst, size, (uint32_t) v);
  
#ifdef __TenDRA__
  /* XXX: TenDRA causes a SIGFPE when using / or % with variables of
   *	  type uint64_t (on 32-bit platforms?).
   */

  p = dst;
  snprintf(p, size, "%" PRIu64, v);
  q = strchr(p, '\0');

#else /* !__TenDRA__ */
  
  p = &buf[sizeof buf - 1];
  do {
    static const char deca[] = "0123456789";
    
    *p = deca[v % 10];
    if (v < 10)
      break;
    v /= 10;
  } while (--p != buf);

  for (q = dst; --size > 0 && p != &buf[sizeof buf]; p++) {
    *q++ = *p;
  }
  *q = '\0';

#endif /* __TenDRA__ */
  
  return q; /* points to trailing NUL */
}

/**
 * @return ``ipv4_addr'' converted to a string pointing to the trailing
 * NUL-character.
 */
char *
print_ipv4_addr(char *dst, size_t size, in_addr_t ipv4_addr)
{
  const uint8_t *addr = (uint8_t *) &ipv4_addr;
  char *p;
  int i;

  RUNTIME_ASSERT(size <= INT_MAX);  
  if (size < IPV4_ADDR_BUFLEN)
    return NULL;

  p = dst;
  for (i = 0; i < 4; i++) {
    static const char deca[] = "0123456789";
    uint8_t v = addr[i];

    if (v >= 10) {
      div_t r;
        
      if (v >= 100) {
        r = div(v, 100);
        *p++ = deca[r.quot];
        v = r.rem;
      }

      r = div(v, 10);
      *p++ = deca[r.quot];
      v = r.rem;
    }
    *p++ = deca[v];
    if (i < 3)
      *p++ = '.';
  }
  *p = '\0';

  RUNTIME_ASSERT(p < &dst[size]);
  return p;
}

/**
 * Prints the IPv6 address ``ipv6_addr'' to ``dst''. The string written
 * to ``dst'' is always NUL-terminated unless ``size'' is zero. If ``size''
 * is too small, the string will be truncated.
 *
 * @param dst the destination buffer.
 * @param ipv6_addr the IPv6 address; must point to a buffer of 16 bytes.
 * @param size the size of ``dst'' in bytes.
 *
 * @return a pointer to the trailing NUL written to ``dst''; or ``dst'' 
 *         if ``size'' is zero.
 */
char *
print_ipv6_addr(char *dst, size_t size, const uint8_t *ipv6_addr)
{
  char *p, buf[IPV6_ADDR_BUFLEN];
  const char *q;
  int zero_len = 2, zero_start = -1;
  int cur_len = 0, cur_start = 0;
  int i = 0;

  if (size < 1)
    return dst;

  /*
   * Use a temporary buffer if ``size'' is not "safe" so that we
   * don't need any boundary checks.
   */
  q = p = size < sizeof buf ? buf : dst;

  /*
   * The zero compression "::" is allowed exactly once. Thus, determine
   * the longest run of zeros first.
   */

  for (i = 0; i < 16; /* NOTHING */) {
    uint16_t v;
   
    v = peek_be16(&ipv6_addr[i]);

    /* We want "::1" and "::" but "::192.0.20.3" */
    if (0 == v && (12 != i || 0 == cur_len || 0 == ipv6_addr[12]))
      cur_len += 2;

    i += 2;
    if (0 != v || 16 == i) {
      if (cur_len > zero_len) {
        zero_start = cur_start;
        zero_len = cur_len;
      }
      cur_start = i;
      cur_len = 0;
    }
    
  }

  for (i = 0; i < 16; /* NOTHING */) {
    uint16_t v = peek_be16(&ipv6_addr[i]);

    if (i != zero_start) {
      p += print_uint16_hex(p, v);
      i += 2;

      if (i < 16 && i != zero_start)
        *p++ = ':';
    } else if (zero_len > 0) {
      /* Compress the longest string of contiguous zeros with "::" */
      i += zero_len;
      *p++ = ':';
      *p++ = ':';
    }

    /*
     * Use IPv4 representation for the special addresses
     */
    if (12 == i &&
      (
        (0xffff == v && 10 == zero_len) ||
        (0x0000 == v && 12 == zero_len)
      )
    ) {
      size_t n;
      in_addr_t ip;

      n = sizeof buf - (p - q);
      memcpy(&ip, &ipv6_addr[12], 4);
      p = print_ipv4_addr(p, n, ip);
      break;
    }

  }

  /* Now copy the result to ``dst'' if we used the temporary buffer. */
  if (dst != q) {
    size_t n = size - 1;

    n = MIN(n, (size_t) (p - q));
    memcpy(dst, q, n);
    dst[n] = '\0';
    return &dst[n];
  }
  
  *p = '\0';
  return p;
}

char *
print_net_addr(char *dst, size_t size, const net_addr_t addr)
{
  return net_addr_is_ipv4_mapped(addr)
    ? print_ipv4_addr(dst, size, net_addr_ipv4(addr))
    : print_ipv6_addr(dst, size, net_addr_ipv6(&addr));
}

char *
print_net_addr_port(char *dst, size_t size,
    const net_addr_t addr, uint16_t port)
{
  char addr_buf[NET_ADDR_BUFLEN], *p = dst;
  bool ipv4;
  
  ipv4 = net_addr_is_ipv4_mapped(addr);

  if (!ipv4)
    p = append_string(p, &size, "[");
  
  print_net_addr(addr_buf, sizeof addr_buf, addr);
  p = append_string(p, &size, addr_buf);

  if (!ipv4)
    p = append_string(p, &size, "]");
    
  p = append_string(p, &size, ":");
  p = append_uint(p, &size, port);
  return p;
}

const char *
net_addr_to_string(const net_addr_t addr)
{
  static char addr_buf[NET_ADDR_BUFLEN];
  
  print_net_addr(addr_buf, sizeof addr_buf, addr);
  return addr_buf;
}

const char *
net_addr_port_to_string(const net_addr_t addr, const in_port_t port)
{
  static char addr_buf[NET_ADDR_PORT_BUFLEN];
  size_t avail = sizeof addr_buf;
  char *p = addr_buf;

 if (net_addr_is_ipv4_mapped(addr)) {
    char *q;
    
    q = print_ipv4_addr(p, avail, net_addr_ipv4(addr));
    avail -= (q - p);
    p = q;
  } else {
    p = append_char(p, &avail, '[');
    {
      char *q;

      q = print_ipv6_addr(p, avail, net_addr_ipv6(&addr));
      avail -= (q - p);
      p = q;
    }
    p = append_char(p, &avail, ']');
  }
  p = append_char(p, &avail, ':');
  p = append_uint16(p, &avail, port);
    
  return addr_buf;
}

size_t
off_t_to_string_buf(off_t v, char *dst, size_t size)
{
  char buf[OFF_T_DEC_BUFLEN];
  char *end = &buf[sizeof buf - 1], *p = end;
  bool neg = v < 0;

  RUNTIME_ASSERT(0 == size || NULL != dst);

  *p = '\0';
  do {
    int d = v % 10;

    v /= 10;
    *--p = dec_digit(neg ? -d : d);
  } while (0 != v);
  if (neg) {
    *--p = '-';
  }
  append_string(dst, &size, p);
  return end - p;
}

const char *
off_t_to_string(off_t v)
{
  static char buf[OFF_T_DEC_BUFLEN];
  off_t_to_string_buf(v, buf, sizeof buf);
  return buf;
}

const char *
sha1_to_base32_string(const struct sha1 *sha1)
{
  static char buf[33];
  
  RUNTIME_ASSERT(sha1);
  base32_encode(buf, sizeof buf, sha1->data, sizeof sha1->data);
  buf[ARRAY_LEN(buf) - 1] = '\0';
  return buf;
}

struct sha1_base32
sha1_base32_string(const struct sha1 *sha1)
{
  struct sha1_base32 buf;
  
  RUNTIME_ASSERT(sha1);
  base32_encode(buf.str, sizeof buf.str, sha1->data, sizeof sha1->data);
  buf.str[ARRAY_LEN(buf.str) - 1] = '\0';
  return buf;
}


/**
 * Parses an unsigned 64-bit integer from an ASCII string.
 *
 * @param src
 *    The string to parse.
 * @param endptr
 *    May be NULL. Otherwise, it will be set to address of the first invalid
 *    character.
 * @param base
 *    The base system to be assumed e.g., 10 for decimal numbers 16 for
 *    hexadecimal numbers. The value MUST be 2..36.
 * @param errorptr
 *    Indicates a parse error if not zero. EINVAL means there was no
 *    number with respect to the used base at all. ERANGE means the
 *    number would exceed (2^64)-1. On success it's set to zero.
 *
 * @return
 *    The parsed value or zero in case of an error. If zero is returned
 *    error must be checked to determine whether there was an error
 *    or whether the parsed value was zero.
 */
uint64_t
parse_uint64(const char *src, char **endptr, int base, int *errorptr)
{
  const char *p;
  uint64_t v = 0, ov;
  int error = 0, c;

  RUNTIME_ASSERT(src != NULL);
  RUNTIME_ASSERT(errorptr != NULL);
  RUNTIME_ASSERT(base >= 2 && base <= 36);

  if (base < 2 || base > 36) {
    *errorptr = EINVAL;
    return 0;
  }

  /*
   * Below this value, no overflow can happen. Thus, we can save a
   * possibly costly division check per digit.
   */
  ov = ((uint64_t) -1) / base;

  for (p = src; (c = (unsigned char) *p) != '\0'; ++p) {
    uint64_t d, w;
    
    if (!isascii(c)) {
      break;
    }
    if (isdigit(c)) {
      d = c - '0';
    } else if (base > 10 && isalpha(c)) {
      c = tolower(c);
      d = c - 'a' + 10;
    } else {
      break;
    }
    if (d >= (unsigned) base) {
      break;
    }
    
    w = v * base;
    if (v >= ov && w / base != v) {
      error = ERANGE;
      break;
    }
    v = w + d; 
    if (v < w) {
      error = ERANGE;
      break;
    }
  }
  
  if (NULL != endptr) {
    *endptr = (char *) p;
  }
  if (!error && p == src) {
    error = EINVAL;
  }
  if (error) {
    v = 0;
  }
  *errorptr = error;
  return v;
}

/**
 * Parses an unsigned 32-bit integer from an ASCII string.
 *
 * @param src
 *    The string to parse.
 * @param endptr
 *    May be NULL. Otherwise, it will be set to address of the first invalid
 *    character.
 * @param base
 *    The base system to be assumed e.g., 10 for decimal numbers 16 for
 *    hexadecimal numbers. The value MUST be 2..36.
 * @param errorptr
 *    Indicates a parse error if not zero. EINVAL means there was no
 *    number with respect to the used base at all. ERANGE means the
 *    number would exceed (2^32)-1.
 *
 * @return
 *    The parsed value or zero in case of an error. If zero is returned
 *    error must be checked to determine whether there was an error
 *    or whether the parsed value was zero. On success it's set to zero.
 */
uint32_t
parse_uint32(const char *src, char **endptr, int base, int *errorptr)
{
  const char *p;
  uint32_t v = 0;
  int error = 0, c;

  RUNTIME_ASSERT(src != NULL);
  RUNTIME_ASSERT(errorptr != NULL);
  RUNTIME_ASSERT(base >= 2 && base <= 36);

  if (base < 2 || base > 36) {
    *errorptr = EINVAL;
    return 0;
  }
      
  for (p = src; (c = (unsigned char) *p) != '\0'; ++p) {
    uint32_t d, w;
    
    if (!isascii(c)) {
      break;
    }
    if (isdigit(c)) {
      d = c - '0';
    } else if (base > 10 && isalpha(c)) {
      c = tolower(c);
      d = c - 'a' + 10;
    } else {
      break;
    }
    if (d >= (unsigned) base) {
      break;
    }
    
    w = v * base;
    if (w / base != v) {
      error = ERANGE;
      break;
    }
    v = w + d; 
    if (v < w) {
      error = ERANGE;
      break;
    }
  }
  
  if (NULL != endptr) {
    *endptr = (char *) p;
  }
  if (!error && p == src) {
    error = EINVAL;
  }
  if (error) {
    v = 0;
  }
  *errorptr = error;
  return v;
}

/**
 * Parses an unsigned 16-bit integer from an ASCII string.
 *
 * @param src
 *    The string to parse.
 * @param endptr
 *    May be NULL. Otherwise, it will be set to address of the first invalid
 *    character.
 * @param base
 *    The base system to be assumed e.g., 10 for decimal numbers 16 for
 *    hexadecimal numbers. The value MUST be 2..36.
 * @param errorptr
 *    Indicates a parse error if not zero. EINVAL means there was no
 *    number with respect to the used base at all. ERANGE means the
 *    number would exceed (2^16)-1.
 *
 * @return
 *    The parsed value or zero in case of an error. If zero is returned
 *    error must be checked to determine whether there was an error
 *    or whether the parsed value was zero. On success it's set to zero.
 */
uint16_t
parse_uint16(const char *src, char **endptr, int base, int *errorptr)
{
  const char *p;
  uint16_t v = 0;
  int error = 0, c;

  RUNTIME_ASSERT(src != NULL);
  RUNTIME_ASSERT(errorptr != NULL);
  RUNTIME_ASSERT(base >= 2 && base <= 36);

  if (base < 2 || base > 36) {
    *errorptr = EINVAL;
    return 0;
  }
      
  for (p = src; (c = (unsigned char) *p) != '\0'; ++p) {
    uint32_t d, w;
    
    if (!isascii(c)) {
      break;
    }
    if (isdigit(c)) {
      d = c - '0';
    } else if (base > 10 && isalpha(c)) {
      c = tolower(c);
      d = c - 'a' + 10;
    } else {
      break;
    }
    if (d >= (unsigned) base) {
      break;
    }
    
    w = v * base;
    if (w / base != v) {
      error = ERANGE;
      break;
    }
    v = w + d; 
    if (v < w) {
      error = ERANGE;
      break;
    }
  }
  
  if (NULL != endptr) {
    *endptr = (char *) p;
  }
  if (!error && p == src) {
    error = EINVAL;
  }
  if (error) {
    v = 0;
  }
  *errorptr = error;
  return v;
}

bool
parse_ipv4_addr(const char *s, in_addr_t *addr, char **endptr)
{
  const char *p = s;
  uint8_t buf[sizeof *addr];
  uint8_t *a = addr ? (uint8_t *) addr : buf;
  bool is_valid = true;
  int i, j, v;

  for (i = 0; i < 4; i++) {
    v = 0;
    for (j = 0; j < 3; j++) {
      if (*p < '0' || *p > '9') {
        is_valid = j > 0;
        break;
      }
      v *= 10;
      v += *p++ - '0';
    }
    if (!is_valid)
      break;
    if (i < 3) {
      if (*p != '.') {
        is_valid = false;
        break; /* failure */
      }
      p++;
    }
    *a++ = (uint8_t) v;
  }

  if (endptr)
    *endptr = deconstify_char_ptr(p);

  if (!is_valid) {
    if (addr)
      *addr = 0;
    return false;
  }
  return true;
}


/**
 * Parses an IPv6 address.
 *
 * @param s the string to parse.
 * @param dst will hold the IPv6 address on success; must
 *        point to 16 or more bytes .
 * @param endptr if not NULL, it will point to the next character after
 *        the parsed address on success. On failure it will point to the
 *        character which caused the failure.
 * @returns false if ``s'' is not a valid IPv6 address; true on success.
 */
bool
parse_ipv6_addr(const char *s, uint8_t *dst, char **endptr)
{
  uint8_t buf[16];
  unsigned char c = 0, last;
  int dc_start = -1;
  int error;
  int i;
  
  RUNTIME_ASSERT(s);

  for (i = 0; i < 16; /* NOTHING */) {
    char *ep;
    uint32_t v;

    last = c;
    c = *s;

    if (':' == c) {
      if (':' == last) {
        if (dc_start >= 0) {
          /* Second double colon */
          s--; /* Rewind to the really bad colon */
          break;
        }
        dc_start = i;
      }
      s++;
      continue;
    }

    if (!isascii(c) || !isxdigit(c)) {
      /* "Expected hexdigit" */
      break;
    }

    v = parse_uint32(s, &ep, 16, &error);
    if (error || v > 0xffff) {
      /* parse_uint32() failed */
      break;
    }

    if (*ep == '.' && i <= 12) {
      in_addr_t ip;

      if (parse_ipv4_addr(s, &ip, &ep)) {
        s = ep;
        memcpy(&buf[i], &ip, 4);
        i += 4;
      }
      /* IPv4 found */
      break;
    }

    buf[i++] = v >> 8;
    buf[i++] = v & 0xff;

    s = ep;

    if ('\0' == *s) {
      /* NUL reached */
      break;
    }

    last = 0;
  }

  if (endptr)
    *endptr = deconstify_char_ptr(s);

  if (dc_start >= 0) {
    int z, n, j;

    z = 16 - i;
    n = i - dc_start;

    for (j = 1; j <= n; j++)
      buf[16 - j] = buf[dc_start + n - j];

    memset(&buf[dc_start], 0, z);
    i += z;
  }

  if (16 != i)
    return false;

  if (dst)
    memcpy(dst, buf, sizeof buf);

  return true;
}

bool
parse_net_addr(const char *s, net_addr_t *addr, char **endptr)
{
  in_addr_t ip;
  uint8_t ipv6[16];
  
  RUNTIME_ASSERT(s);

  if ('[' == *s) {
    char *ep = NULL;
    bool ok;
    
    ok = parse_ipv6_addr(&s[1], ipv6, &ep) && ']' == *ep;
    if (addr)
      *addr = net_addr_peek_ipv6(ipv6);
    if (endptr)
      *endptr = ok ? ++ep : ep;

    return ok;
  } else if (parse_ipv4_addr(s, &ip, endptr)) {
    if (addr)
      *addr = net_addr_set_ipv4(ip);
    return true;
  } else if (parse_ipv6_addr(s, ipv6, endptr)) {
    if (addr)
      *addr = net_addr_peek_ipv6(ipv6);
    return true;
  }

  return false;
}

bool
parse_port_number(const char *s, uint16_t *port, char **endptr)
{
  const char *p = s;
  unsigned int v = 0;
  bool is_valid = false;
  int c;

  /* Disallow zero and zero(s) as prefix */
  if ('0' != *s) {
    
    for (;;) {
      int d;
      
      c = *p;
      switch (c) {
      case '0': d = 0; break;
      case '1': d = 1; break;
      case '2': d = 2; break;
      case '3': d = 3; break;
      case '4': d = 4; break;
      case '5': d = 5; break;
      case '6': d = 6; break;
      case '7': d = 7; break;
      case '8': d = 8; break;
      case '9': d = 9; break;
      default:
	d = -1;
      }
      if (d == -1) {
	is_valid = p != s && v > 0;
	break;
      }
      v = (v * 10) + d;
      if (v > 65535) {
	is_valid = false;
#if 0
	/* failure */
#endif
	break;
      }
      p++;
    }
    
  }
  
  if (endptr)
    *endptr = deconstify_char_ptr(p);
  if (port)
    *port = is_valid ? (uint16_t) v : 0;
  return is_valid;
}

char *
print_iso8601_date(char *dst, size_t size, time_t t)
{
  struct tm *tms;
  char *p = dst;

  RUNTIME_ASSERT(dst);

  tms = gmtime(&t);
  RUNTIME_ASSERT(tms->tm_wday >= 0 && tms->tm_wday <= 6);
  RUNTIME_ASSERT(tms->tm_mon >= 0 && tms->tm_mon <= 12);

  p = append_uint(p, &size, tms->tm_year + 1900);
  p = append_string(p, &size, "-");
  
  p = append_uint(p, &size, (tms->tm_mon + 1) / 10);
  p = append_uint(p, &size, (tms->tm_mon + 1) % 10);
  p = append_string(p, &size, "-");

  p = append_uint(p, &size, tms->tm_mday / 10);
  p = append_uint(p, &size, tms->tm_mday % 10);
  p = append_string(p, &size, "T");

  p = append_uint(p, &size, tms->tm_hour / 10);
  p = append_uint(p, &size, tms->tm_hour % 10);
  p = append_string(p, &size, ":");

  p = append_uint(p, &size, tms->tm_min / 10);
  p = append_uint(p, &size, tms->tm_min % 10);
  p = append_string(p, &size, ":");
  
  p = append_uint(p, &size, tms->tm_sec / 10);
  p = append_uint(p, &size, tms->tm_sec % 10);
  
  return p;
}


char *
print_rfc1123_date(char *dst, size_t size, time_t t)
{
  static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
  static const char days[] = "SunMonTueWedThuFriSat";
  static const char gmt[] = "GMT";
  struct tm *tms;
  char *p = dst;

  if (size < RFC1123_DATE_BUFLEN) {
    /* buffer is too small */
    if (size > 0)
      dst[0] = '\0';
    return NULL;
  }

  tms = gmtime(&t);
  RUNTIME_ASSERT(tms->tm_wday >= 0 && tms->tm_wday <= 6);
  RUNTIME_ASSERT(tms->tm_mon >= 0 && tms->tm_mon <= 12);
  memcpy(p, days + tms->tm_wday * 3, 3);
  p += 3;
  *p++ = ',';
  *p++ = ' ';
  *p++ = tms->tm_mday / 10 + '0';
  *p++ = tms->tm_mday % 10 + '0';
  *p++ = ' ';
  memcpy(p, months + tms->tm_mon * 3, 3);
  p += 3;
  *p++ = ' ';
  p = print_uint(p, size - (p - dst), tms->tm_year + 1900);
  *p++ = ' ';
  *p++ = tms->tm_hour / 10 + '0';
  *p++ = tms->tm_hour % 10 + '0';
  *p++ = ':';
  *p++ = tms->tm_min / 10 + '0';
  *p++ = tms->tm_min % 10 + '0';
  *p++ = ':';
  *p++ = tms->tm_sec / 10 + '0';
  *p++ = tms->tm_sec % 10 + '0';
  *p++ = ' ';
  memcpy(p, gmt, sizeof gmt); /* includes trailing NUL */
  p += sizeof gmt - 1;
  RUNTIME_ASSERT(&dst[RFC1123_DATE_BUFLEN - 1] == p && *p == '\0');
  return p;
}

char *
print_ncsa_date(char *dst, size_t size, time_t t)
{
  static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
  static const char gmt[] = " +0000";
  struct tm *tms;
  char *p = dst;

  if (size < NCSA_DATE_BUFLEN) {
    /* buffer is too small */
    if (size > 0)
      dst[0] = '\0';
    return NULL;
  }

  tms = gmtime(&t);
  RUNTIME_ASSERT(tms->tm_wday >= 0 && tms->tm_wday <= 6);
  RUNTIME_ASSERT(tms->tm_mon >= 0 && tms->tm_mon <= 12);

  /* Day of month */
  *p++ = tms->tm_mday / 10 + '0';
  *p++ = tms->tm_mday % 10 + '0';
  *p++ = '/';
  
  /* Month (abbrevated name) */
  memcpy(p, months + tms->tm_mon * 3, 3);
  p += 3;
  *p++ = '/';
  
  /* Year (4 digits) */
  p = print_uint(p, size - (p - dst), tms->tm_year + 1900);
  *p++ = ':';
  
  /* Time */
  *p++ = tms->tm_hour / 10 + '0';
  *p++ = tms->tm_hour % 10 + '0';
  *p++ = ':';
  *p++ = tms->tm_min / 10 + '0';
  *p++ = tms->tm_min % 10 + '0';
  *p++ = ':';
  *p++ = tms->tm_sec / 10 + '0';
  *p++ = tms->tm_sec % 10 + '0';

  /* Time zone */
  memcpy(p, gmt, sizeof gmt); /* Includes NUL */
  p += sizeof gmt - 1;
  
  RUNTIME_ASSERT(&dst[NCSA_DATE_BUFLEN - 1] == p && '\0' == *p);
  return p;
}


/**
 * Parses a time in HH:MM:SS format whereas a single leading zero is
 * optional for element e.g., H:MM:S is also considered OK. Leading
 * whitespace characters or more than 2 digits are NOT allowed. If ``tm''
 * is not NULL, the values of tm_hour, tm_min, tm_sec will be set to the
 * parsed values * but no other members are touched.
 *
 * @param tm a ``struct tm'' which is set to the parsed values, may be NULL.
 * @param endptr on success, it will set to the first character after the
 *        parsed time.
 * @return 0 on success, non-zero on failure. 
 */
static int
parse_time(const char *s, struct tm *tm, char **endptr)
{
  char *ep;
  uint32_t u;
  int error;

  if (endptr)
    *endptr = NULL;

  /* Allow only one optional leading zero */
  if (
    '0' == *s &&
    isdigit((unsigned char) s[1]) &&
    isdigit((unsigned char) s[2])
  ) {
    /* Expected at most 2 digits */
    return -1;
  }
  
  u = parse_uint32(s, &ep, 10, &error);
  if (error || u > 23) {
    /* Expected hour */  
    return -1;
  }
  
  s = ep; 
  if (':' != *s) {
    /* Expected colon after hour */
    return -1;
  }
  s++;
  
  if (tm)
    tm->tm_hour = u;
  
  /* Allow only one optional leading zero */
  if (
    '0' == *s &&
    isdigit((unsigned char) s[1]) &&
    isdigit((unsigned char) s[2])
  ) {
    /* Expected at most 2 digits */
    return -1;
  }
   
  u = parse_uint32(s, &ep, 10, &error);
  if (error || u > 59) {
    /* Expected minutes */  
    return -1;
  }
 
  s = ep; 
  if (':' != *s) {
    /* Expected colon after minutes */
    return -1;
  }
  s++;
  
  if (tm)
    tm->tm_min = u;
  
  /* Allow only one optional leading zero */
  if (
    '0' == *s &&
    isdigit((unsigned char) s[1]) &&
    isdigit((unsigned char) s[2])
  ) {
    /* Expected at most 2 digits */
    return -1;
  }

  /* Second */
  u = parse_uint32(s, &ep, 10, &error);
  if (error || u > 61) {
    /* Expected seconds */  
    return -1;
  }
  
  if (tm)
    tm->tm_sec = u;

  if (endptr)
    *endptr = ep;

  return 0;
}

/**
 * Parses a date as specified by ISO 8601.
 *
 * @param s a NUL-terminated string presumed to contain a ISO 8601 date.
 * @param endptr if not NULL, it will br initialized to NULL on failure and
 *        point to the end of original string ``s'' on success.
 * @param tm if not NULL and parsing succeeds the ``struct tm'' will be
 *        initialized to parsed date.
 * @return 0 on success, non-zero on failure.
 */
int
parse_iso8601_date(const char *s, char **endptr, struct tm *tmptr)
{
  static const struct tm zero_tm;
  struct tm tm;
  int error;
  uint16_t u;
  char *ep;

  if (endptr) {
    *endptr = NULL;
  }

  tm = zero_tm;
  tm.tm_isdst = -1;
  s = skip_spaces(s);

  u = parse_uint16(s, &ep, 10, &error);
  if (error || u < 1900 || u > 3000 || '-' != *ep) {
    /* Expected year */  
    return -1;
  }
  tm.tm_year = u - 1900;
  s = ep;

  u = parse_uint16(s, &ep, 10, &error);
  if (error || u < 1 || u > 12 || '-' != *ep) {
    /* Expected month */  
    return -1;
  }
  tm.tm_mon = u;
  s = ep;

  u = parse_uint16(s, &ep, 10, &error);
  if (error || u < 1 || u > 31) {
    /* Expected day of week */  
    return -1;
  }
  tm.tm_mday = u;
 
  if ('T' == *ep || (' ' == *ep && isdigit((unsigned char) ep[1]))) {
    s = &ep[1];
    if (0 != parse_time(s, &tm, &ep)) {
      /* Expected time */
      return -1;
    }
  } else if ('\0' != *ep) {
    return -1;
  }

  if ('Z' == *ep) {
    ep++;
  }

#if 0
  DBUG("%04d-%02d-%02d %02d:%02d:%02d",
      tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
      tm.tm_hour, tm.tm_min, tm.tm_sec);
#endif

  if (endptr)
    *endptr = ep;

  if (tmptr)
    *tmptr = tm;

  return 0;
}


/**
 * Parses a date as specified by RFC 1123.
 *
 * @param s a NUL-terminated string presumed to contain a RFC 1123 date.
 * @param endptr if not NULL, it will br initialized to NULL on failure and
 *        point to the end of original string ``s'' on success.
 * @param tm if not NULL and parsing succeeds the ``struct tm'' will be
 *        initialized to parsed date.
 * @return 0 on success, non-zero on failure.
 */
int
parse_rfc1123_date(const char *s, char **endptr, struct tm *tmptr)
{
  static const char months[][4] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
  };
  static const char days[][4] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
  };
  static const struct tm zero_tm;
  struct tm tm;
  int error;
  uint32_t u;
  unsigned int i;
  char *ep;

  STATIC_ASSERT(12 == ARRAY_LEN(months));
  STATIC_ASSERT(7 == ARRAY_LEN(days));
  STATIC_ASSERT(4 == ARRAY_LEN(months[0]));
  STATIC_ASSERT(4 == ARRAY_LEN(days[0]));
  
  if (endptr)
    *endptr = NULL;

  tm = zero_tm;
  tm.tm_isdst = -1;
  s = skip_spaces(s);

  for (i = 0; i < ARRAY_LEN(days); i++) {
    if (NULL != (ep = skip_prefix(s, days[i]))) {
      break;
    }
  }

  if (!ep) {
    /* Expected day of week */  
    return -1;
  }

  tm.tm_wday = i;
  s = ep;

  if (',' != *s) {
    /* Expected comma */  
    return -1;
  }
  
  s = skip_spaces(++s);
  
  /* Allow only one optional leading zero */
  if (
    '0' == *s &&
    isdigit((unsigned char) s[1]) &&
    isdigit((unsigned char) s[2])
  ) {
    /* Expected at most 2 digits */
    return -1;
  }

  u = parse_uint32(s, &ep, 10, &error);
  if (error || u < 1 || u > 31) {
    /* Expected day of month */  
    return -1;
  }

  tm.tm_mday = u;
  s = skip_spaces(ep);
  
  for (i = 0; i < ARRAY_LEN(months); i++) {
    if (NULL != (ep = skip_prefix(s, months[i]))) {
      break;
    }
  }

  if (!ep) {
    /* Expected month */  
    return -1;
  }

  tm.tm_mon = i;
  s = skip_spaces(ep);
  
  /* Allow only one optional leading zero */
  if (
    '0' == *s &&
    isdigit((unsigned char) s[1]) &&
    isdigit((unsigned char) s[2])
  ) {
    /* Expected at most 2 digits */
    return -1;
  }

  /* Year */
  u = parse_uint32(s, &ep, 10, &error);
  if (error || u < 1970 || u > 3000) {
    /* Expected year */  
    return -1;
  }

  tm.tm_year = u - 1900;

  s = skip_spaces(ep);
  if (0 != parse_time(s, &tm, &ep)) {
    /* Expected time */
    return -1;
  }
  
  s = skip_spaces(ep);
  ep = skip_prefix(s, "GMT");
  if (!ep) {
    /* Expected "GMT" */
    return -1;
  }

#if 0
  DBUG("%04d-%02d-%02d %02d:%02d:%02d",
      tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
      tm.tm_hour, tm.tm_min, tm.tm_sec);
#endif

  if (endptr)
    *endptr = ep;

  if (tmptr)
    *tmptr = tm;

  return 0;
}

/**
 * Parses a date as specified by RFC 850.
 *
 * @param s a NUL-terminated string presumed to contain a RFC 850 date.
 * @param endptr if not NULL, it will br initialized to NULL on failure and
 *        point to the end of original string ``s'' on success.
 * @param tm if not NULL and parsing succeeds the ``struct tm'' will be
 *        initialized to parsed date.
 * @return 0 on success, non-zero on failure.
 */
int
parse_rfc850_date(const char *s, char **endptr, struct tm *tmptr)
{
  static const char months[][4] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
  };
  static const char days[][10] = {
    "Sunday", "Monday", "Tuesday", "Wednesday",
    "Thursday", "Friday", "Saturday"
  };
  static const struct tm zero_tm;
  struct tm tm;
  int error;
  uint32_t u;
  unsigned int i;
  char *ep;

  STATIC_ASSERT(12 == ARRAY_LEN(months));
  STATIC_ASSERT(7 == ARRAY_LEN(days));
  STATIC_ASSERT(4 == ARRAY_LEN(months[0]));
  STATIC_ASSERT(10 == ARRAY_LEN(days[0]));
  
  if (endptr)
    *endptr = NULL;

  tm = zero_tm;
  tm.tm_isdst = -1;
  s = skip_spaces(s);

  for (i = 0; i < ARRAY_LEN(days); i++) {
    if (NULL != (ep = skip_prefix(s, days[i]))) {
      break;
    }
  }

  if (!ep) {
    /* Expected day of week */  
    return -1;
  }

  tm.tm_wday = i;
  s = ep;

  if (',' != *s) {
    /* Expected comma */  
    return -1;
  }
  
  s = skip_spaces(++s);
  
  /* Allow only one optional leading zero */
  if (
    '0' == *s &&
    isdigit((unsigned char) s[1]) &&
    isdigit((unsigned char) s[2])
  ) {
    /* Expected at most 2 digits */
    return -1;
  }

  u = parse_uint32(s, &ep, 10, &error);
  if (error || u < 1 || u > 31) {
    /* Expected day of month */  
    return -1;
  }

  tm.tm_mday = u;
  
  if ('-' != *ep) {
    /* Expected hyphen after day */
    return -1;
  }
  s = ++ep;
   
  for (i = 0; i < ARRAY_LEN(months); i++) {
    if (NULL != (ep = skip_prefix(s, months[i]))) {
      break;
    }
  }

  if (!ep) {
    /* Expected month */  
    return -1;
  }

  tm.tm_mon = i;
  s = ep;
  
  if ('-' != *ep) {
    /* Expected hyphen after month */
    return -1;
  }
  s = ++ep;
  
  /* Year */

  /* Allow only one optional leading zero */
  if (
    '0' == *s &&
    isdigit((unsigned char) s[1]) &&
    isdigit((unsigned char) s[2])
  ) {
    /* Expected at most 2 digits */
    return -1;
  }

  u = parse_uint32(s, &ep, 10, &error);
  if (error || u > 3000 || (u > 99 && u < 1970)) {
    /* Expected year */  
    return -1;
  }

  /* Fixup a 2 digit Y2K-unsafe date */
  if (u < 70) {
    u += 2000;
  } else if (u < 100) {
    u += 1900;
  }

  tm.tm_year = u - 1900;
  s = skip_spaces(ep);
  
  if (0 != parse_time(s, &tm, &ep)) {
    /* Expected time */
    return -1;
  }
  
  s = skip_spaces(ep);

  /* Other timezones are possible but we accept only GMT and UTC */
  ep = skip_prefix(s, "GMT");
  if (!ep)
    ep = skip_prefix(s, "UTC");
  if (!ep) {
    /* Expected "GMT" or "UTC" */
    return -1;
  }

  if (endptr)
    *endptr = ep;

  if (tmptr)
    *tmptr = tm;

  return 0;
}

/**
 * Parses a date as printed by asctime().
 *
 * @param s a NUL-terminated string presumed to contain an asctime() date.
 * @param endptr if not NULL, it will br initialized to NULL on failure and
 *        point to the end of original string ``s'' on success.
 * @param tm if not NULL and parsing succeeds the ``struct tm'' will be
 *        initialized to parsed date.
 * @return 0 on success, non-zero on failure.
 */
int
parse_asctime_date(const char *s, char **endptr, struct tm *tmptr)
{
  static const char months[][4] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
  };
  static const char days[][4] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
  };
  static const struct tm zero_tm;
  struct tm tm;
  int error;
  uint32_t u;
  unsigned int i;
  char *ep;

  STATIC_ASSERT(12 == ARRAY_LEN(months));
  STATIC_ASSERT(7 == ARRAY_LEN(days));
  STATIC_ASSERT(4 == ARRAY_LEN(months[0]));
  STATIC_ASSERT(4 == ARRAY_LEN(days[0]));
  
  if (endptr)
    *endptr = NULL;

  tm = zero_tm;
  tm.tm_isdst = -1;
  s = skip_spaces(s);

  for (i = 0; i < ARRAY_LEN(days); i++) {
    if (NULL != (ep = skip_prefix(s, days[i]))) {
      break;
    }
  }

  if (!ep) {
    /* Expected day of week */  
    return -1;
  }

  tm.tm_wday = i;
  s = skip_spaces(ep);

  for (i = 0; i < ARRAY_LEN(months); i++) {
    if (NULL != (ep = skip_prefix(s, months[i]))) {
      break;
    }
  }

  if (!ep) {
    /* Expected month */  
    return -1;
  }

  tm.tm_mon = i;
  s = skip_spaces(ep);
  
  /* Allow only one optional leading zero */
  if (
    '0' == *s &&
    isdigit((unsigned char) s[1]) &&
    isdigit((unsigned char) s[2])
  ) {
    /* Expected at most 2 digits */
    return -1;
  }

  u = parse_uint32(s, &ep, 10, &error);
  if (error || u < 1 || u > 31) {
    /* Expected day of month */  
    return -1;
  }

  tm.tm_mday = u;
  s = skip_spaces(ep);
  
  if (0 != parse_time(s, &tm, &ep)) {
    /* Expected time */
    return -1;
  }

  s = skip_spaces(ep);
  
  /* Allow only one optional leading zero */
  if (
    '0' == *s &&
    isdigit((unsigned char) s[1]) &&
    isdigit((unsigned char) s[2])
  ) {
    /* Expected at most 2 digits */
    return -1;
  }

  /* Year */
  u = parse_uint32(s, &ep, 10, &error);
  if (error || u < 1970 || u > 3000) {
    /* Expected year */  
    return -1;
  }

  tm.tm_year = u - 1900;
  
  if (endptr)
    *endptr = ep;

  if (tmptr)
    *tmptr = tm;

  return 0;
}


/**
 * Compares two ``struct tm'' ignoring the timezone and daylight savings.
 * All values are assumed to be within their valid ranges.
 *
 * @param a the first initialized ``struct tm''.
 * @param a the second initialized ``struct tm''.
 * @return  1 if a is newer than b.
 *         -1 if a is older than b.
 *          0 if a and b are equal.
 */
int
tm_cmp(const struct tm *a, const struct tm *b)
{
  int s;
  
  RUNTIME_ASSERT(a);
  RUNTIME_ASSERT(b);

  if (0 == (s = SIGN_CMP(a->tm_year, b->tm_year))) 
    if (0 == (s = SIGN_CMP(a->tm_mon, b->tm_mon)))
      if (0 == (s = SIGN_CMP(a->tm_mday, b->tm_mday)))
        if (0 == (s = SIGN_CMP(a->tm_hour, b->tm_hour)))
          if (0 == (s = SIGN_CMP(a->tm_min, b->tm_min)))
            s = SIGN_CMP(a->tm_sec, b->tm_sec);
  
  return s;
}

/**
 *  @return NULL if it fails, returns a pointer to the end of the
 *  decoded string otherwise.
 *  NB: ``dst'' and ``src'' MAY point to the same buffer.
 */
char *
url_decode(char *dst, const char *src, ssize_t size)
{
  const char *p = src;
  char *q = dst;
  unsigned int i, ch, c;

  if (size-- < 1) {
    /* destination buffer is too small */
    return NULL;
  }

  while ((c = (unsigned char) *p++) != '\0' && (q - dst) < size) {
    if (!isascii(c) || isspace(c) || iscntrl(c) || c < 32 || c > 126) {
      /* Illegal character in URL */
      return NULL;
    }

    switch (c) {
    case '+':
      *q++ = ' ';
      break;
      
    case '%':
      ch = 0;
      for (i = 0; i < 2; i++) {
        ch *= 16;
        c = (unsigned char) *p++;
        if (c >= '0' && c <= '9')
          ch += c - '0';
        else if (c >= 'a' && c <= 'f')
          ch += c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
          ch += c - 'A' + 10;
        else {
          /* invalid encoded character */
          return NULL;
        }
      }

      if (ch == '\0') {
        /* encoded NUL-character in URL; rejected */
        return NULL;
      }

      *q++ = (char) ch;
      break;
      
    default:
      *q++ = c;
    }
  }

  *q = '\0';
  return q;
}

int
url_split(const char *url, char *host, size_t host_size,
    uint16_t *port_ptr, const char **path_ptr)
{
  const char *dummy_path;
  uint16_t dummy_port;
  const char *p, *host_start, *host_end;

  RUNTIME_ASSERT(url);
  RUNTIME_ASSERT(0 == host_size || host != NULL);
 
  if (!path_ptr) {
    path_ptr = &dummy_path; 
  }
  if (!port_ptr) {
    port_ptr = &dummy_port;
  }
  if (host && host_size > 0) {
    *host = '\0';
  }
  *port_ptr = 0;
  *path_ptr = NULL;

  if (NULL == (host_start = skip_prefix(url, "http://"))) {
    return -1;
  }

  host_end = NULL;
  *port_ptr = 80; /* HTTP_DEFAULT_PORT */

  for (p = host_start; '\0' != p; p++) {
    if (':' == *p) {
      char *endptr;

      host_end = p;
      p++;
      if (!parse_port_number(p, port_ptr, &endptr)) {
        return -1;
      }
      if ('\0' == *endptr) {
        *path_ptr = endptr;
        break;
      }
      if ('/' != *endptr) {
        return -1;
      }
      p = endptr;
    }
    if ('/' == *p) {
      if (!host_end)
        host_end = p;

      while ('/' == p[1]) {
        p++;
      }
      *path_ptr = p;
      break;
    }
  }

  if (!host_end || host_end == host_start)
    return -1;

  if (host && host_size > 0) {
    size_t host_len = host_end - host_start;
    char *endptr;
   
    if (host_len >= host_size)
      return -1;
  
    host_size--; 
    endptr = append_chars(host, &host_size, host_start, host_len);
    *endptr = '\0';
  }

#if 0 
  DBUG("%s: host=\"%s\", port=%u, URI=\"%s\"", __func__,
      host, (unsigned) *port, *uri);
#endif

  return 0;
}

const char *
humanize_value(uint64_t v, uint64_t *integer, uint64_t *fraction)
{
  static const char *s[] = { "", "k", "M", "G", "T", "P", "E" };
  const char *suffix = s[0];
  size_t j;
  uint64_t i, f;
  
  i = v;
  f = 0;
  for (j = 1; v >= 1024 && j < ARRAY_LEN(s); j++) {
    suffix = s[j];
    i = (v / 1024);
    f = ((v - i * 1024) * 10) / 1024;
    v /= 1024;
  }

  *integer = i;
  *fraction = f;
  return suffix;
}

/**
 * Creates the canonical representation of a path.
 *
 * ``dst'' and ``src'' may be identical but must not overlap otherwise.
 *
 * @param dst the destination, must be sufficiently long.
 * @param path a NUL-terminated string representing the input path.
 * @return zero on sucess, non-zero on failure.
 */
int
uri_canonize_path(char *dst, const char *path)
{
  const char *p;
  char *q;
  int c;
  
  RUNTIME_ASSERT(dst);
  RUNTIME_ASSERT(path);
  /** FIXME: Add overlap check. */
  
  /* Scan path */
  for (p = path, q = dst; '\0' != (c = (unsigned char) *p); q++, p++) {
 
    /* Handle relative paths i.e., /. and /.. */
    if (c != '/') {
      *q = c;
      continue;
    }

    /* Special handling for '/' follows */

    do {
        
      *q = '/';

      while (p[1] == '/') {
        p++;
      }

      if (0 == strcmp(p, "/.")) {
        p++;
        /* Ignoring trailing "/." in URI */
      } else if (0 == strcmp(p, "/..")) {
        return -1;
      } else if (NULL != skip_prefix(p, "/./")) {
        p += 2;
        /* Ignoring unnecessary "/./" in URI */
      } else if (NULL != skip_prefix(p, "/../")) {
        p += 3;
        
        /* Ascending one component in URI */
        do {
          if (q == dst)
            return -1; /* beyond root */
        } while (*--q != '/');
          
      } else {
        break;
      }

    } while (*p == '/' && (p[1] == '/' || p[1] == '.'));
    
  }

  *q = '\0';
  return 0;
}

char *
create_pathname(const char *path, const char *filename)
{
  size_t size;
  char *pathname;

  RUNTIME_ASSERT(path);
  RUNTIME_ASSERT(filename);
  RUNTIME_ASSERT('\0' != *path);

  size = 2 + strlen(path) + strlen(filename);
  if (NULL != (pathname = malloc(size))) {
    bool has_slash;
    char *p;
   
    p = pathname;
    p = append_string(p, &size, path);
    has_slash = '/' == *(p - 1);
    if (has_slash) {
      while ('/' == filename[0])
        filename++;
    } else if ('/' != filename[0]) {
      p = append_string(p, &size, "/");
    }
    p = append_string(p, &size, filename);
  }
  return pathname;
}

int
tokenline(FILE *f, char *buf, size_t size)
{
  char *p = buf;
  bool token = false;
  int count = 0;
  int c;

  RUNTIME_ASSERT((ssize_t) size > 0);
  RUNTIME_ASSERT(p);

  *p = '\0';
  c = fgetc(f);
  if (c == EOF || feof(f)) {
    return -1;
  }
  
  while (c != EOF && c != '\n' && !feof(f)) {
    
    if (p - buf >= (ssize_t) size) {
      while (c != EOF && c != '\n' && !feof(f)) {
        /* Discard everything until EOF or EOL */
        c = fgetc(f);
      }
      
      break;
    }

    if (isspace(c) || iscntrl(c) || c == '\0') {
      if (token) {
        *p++ = '\0';
        token = false;
      }
    } else {
      *p++ = c;
      if (!token) {
        count++;
        token = true;
      }
    }
    c = fgetc(f);
  }
  *p = '\0';

  return count;
}

static inline FILE *FAILURE(int e) { errno = e; return NULL; }

/* Opens only regular files i.e., doesn't follow sym-links.
 * If used by root, the file must be root-owned and at most root-writeable.
 * The file must not be world-writable.
 */
FILE *
safer_fopen(const char *pathname, safer_fopen_mode_t m)
{
  FILE *f = NULL;
  int fd = -1;
  int flags;
  const char *fmode = NULL;
  struct stat sb1, sb2;
  bool is_new = false;

  RUNTIME_ASSERT(pathname);
  RUNTIME_ASSERT(m);
 
  switch (m) {
  case SAFER_FOPEN_RD:
    flags = O_RDONLY;
    fmode = "r";
    break;
  case SAFER_FOPEN_WR:
    flags = O_WRONLY | O_TRUNC | O_CREAT;
    fmode = "w";
    break;
  case SAFER_FOPEN_RDWR:
    flags = O_RDWR;
    fmode = "w+";
    break;
  case SAFER_FOPEN_APPEND:
    flags = O_WRONLY | O_APPEND | O_CREAT;
    fmode = "a";
    break;
  default:
    flags = 0;
    RUNTIME_ASSERT(0);
  }
 
#ifdef O_NOFOLLOW
  flags |= O_NOFOLLOW;
#endif
  
  flags |= O_NOCTTY | O_NONBLOCK;
  
  errno = 0;
  if (lstat(pathname, &sb1)) {
    is_new = true;
   
    if (errno != ENOENT)
      return FAILURE(errno);

    if (!(m & SAFER_FOPEN_WR))
      return FAILURE(errno ? errno : EACCES);
  } else {
  
    /* root-owned or owned by real user */
    if (0 != sb1.st_uid && 0 == getuid()) {
      return FAILURE(EACCES);
    }
  
    /* world-writable? */
    if (S_IWOTH & sb1.st_mode) {
      return FAILURE(EACCES);
    }
  
    if ((sb1.st_mode & S_IFMT) != S_IFREG) {
      return FAILURE(EACCES);
    }
  }
  
  fd = open(pathname, flags, S_IWUSR | S_IRUSR | S_IRGRP);
  if (fd < 0) {
    return FAILURE(errno);
  }

  /* Check the file again because the world may have changed in the meantime */
  if (fstat(fd, &sb2)) {
    close(fd);
    return FAILURE(EACCES);
  }

  /* root-owned or owned by real user */
  if (0 != sb2.st_uid && 0 == getuid()) {
    close(fd);
    return FAILURE(EACCES);
  }
  
  /* world-writable? */
  if (S_IWOTH & sb2.st_mode) {
    close(fd);
    return FAILURE(EACCES);
  }
  
  if (!is_new && (
	0 != memcmp(&sb1.st_dev, &sb2.st_dev, sizeof sb1.st_dev) ||
	0 != memcmp(&sb1.st_ino, &sb2.st_ino, sizeof sb1.st_ino)
      )
  ) {
    close(fd);
    return FAILURE(EACCES);
  }
  
  f = fdopen(fd, fmode);
  if (!f) {
    close(fd);
  }
  return f;
}

#define BITS 32
#define SETBIT(x, b) do { ((x)[(b) / BITS] |= 1 << ((b) % BITS)); } while(0)
#define CHECKBIT(x, b) (1 & ((x)[(b) / BITS] >> ((b) % BITS)))

uint32_t
prime_up(uint32_t n)
{
  uint32_t *b;
  uint32_t i, j, k = 0, m;
  size_t size;

  m = MIN(n, 89);
  size = m / 8 + 1;
  b = calloc(1, size);
  if (!b)
    return 0;

  do {
    for (i = 2; i < size; i++)
      if (!CHECKBIT(b, i)) {
        for (j = i << 1; j < m; j += i)
          if (!CHECKBIT(b, j))
            SETBIT(b, j);

        if (!CHECKBIT(b, i) && i >= n) {
          k = i;
          break;
        }
      }

    if (!k) {
      uint32_t *nb;
      size_t os = size;
      
      m <<= 1;
      size = m / 8 + 1;  
      nb = realloc(b, m / 8 + 1);
      if (!nb)
        break;
      b = nb;
      memset(&((char *) b)[os], 0, size - os);
    }
  } while (!k);

  DO_FREE(b);
  return k;  
}

#if 0
#include "common.h"

int
main(void)
{
  static const char * const tab[] = {
    "0.0.0.0",
    "1.0.0.0",
    "1.2.3.4",
    "10.0.100.0",
    "202.104.20.0",
    "255.255.255.255",
  };
  static const struct {
    const char *str;
    int base;
    size_t len;
    uint64_t res;
    int error;
  } val[] = {
    { "",   10, 0, 0, EINVAL  },
    { "1",  10, 1, 1, 0  },
    { "a",  16, 1, 10, 0 },
    { "F",  16, 1, 15, 0 },
    { "68719476736", 10, 11, 68719476736ULL, 0 },
    { "ffffffffffffffff", 16, 16, 0xffffffffffffffffULL, 0 },
    { "zZZzzZzZZzZzzZZ", 36, 12, 0, ERANGE },
    { "zzz", 36, 3, 46655, 0 },
    { "=", 2, 0, 0, EINVAL },
    { "1", 2, 1, 1, 0 },
    { "-1", 10, 0, 0, EINVAL },
    { "+1", 10, 0, 0, EINVAL },
    { "0x4", 16, 1, 0, 0 },
  };
  unsigned int i;
  
  for (i = 0; i < ARRAY_LEN(tab); ++i) {
    char buf[16];
    bool ret;
    in_addr_t addr;
    const char *endptr;
    const char *s;
    
    s = tab[i];
    printf("\"%s\"\n", s);
    ret = parse_ipv4_addr(s, &addr, &endptr);
    RUNTIME_ASSERT(ret && *endptr == '\0');
    print_ipv4_addr(buf, sizeof buf, addr);
    ret = !strcmp(buf, s);
    RUNTIME_ASSERT(ret);
  }

  for (i = 0; i < ARRAY_LEN(val); ++i) {
    int error;
    uint64_t v;
    char *endptr;
    const char *s;
    
    endptr = NULL;
    error = EIO;
    s = val[i].str;
    printf("\"%s\"\n", s);
    v = parse_uint64(s, &endptr, val[i].base, &error);
    RUNTIME_ASSERT(v == val[i].res);
    RUNTIME_ASSERT((size_t)(endptr - s) == val[i].len);
    if (0 == v) {
      RUNTIME_ASSERT(error == val[i].error);
    } else if (10 == val[i].base) {
      char buf[32];
     
      print_uint64(buf, sizeof buf, v);
      error = strcmp(buf, s);
      RUNTIME_ASSERT(0 == error);
    }
  }
  
  return 0;
}
#endif /* 0 */

/* vi: set et sts=2 sw=2 cindent: */
