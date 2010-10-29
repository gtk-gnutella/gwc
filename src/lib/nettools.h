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

#ifndef NETTOOLS_HEADER_FILE
#define NETTOOLS_HEADER_FILE

#include "common.h"
#include "net_addr.h"

typedef uint32_t hash_t;

#define IPV4_ADDR_BUFLEN (sizeof "AAA.BBB.CCC.DDD")
#define IPV6_ADDR_BUFLEN \
  (sizeof "0001:0203:0405:0607:0809:1011:255.255.255.255")
#define NET_ADDR_BUFLEN IPV6_ADDR_BUFLEN
#define NET_ADDR_PORT_BUFLEN (NET_ADDR_BUFLEN + sizeof ":[65535]")

#define UINT8_DEC_BUFLEN (sizeof "255")
#define UINT16_DEC_BUFLEN (sizeof "65535")
#define UINT32_DEC_BUFLEN (sizeof "4294967295")
#define UINT64_DEC_BUFLEN (sizeof "18446744073709551615")
#define RFC1123_DATE_BUFLEN (sizeof "Thu, 01 Jan 1970 01:00:00 GMT")
#define NCSA_DATE_BUFLEN (sizeof "01/Jan/1970:01:00:00 +0000")
#define OFF_T_DEC_BUFLEN (sizeof(off_t) * CHAR_BIT) /* very roughly */

typedef enum {
  SAFER_FOPEN_RD = 1,
  SAFER_FOPEN_WR = 2,
  SAFER_FOPEN_RDWR = SAFER_FOPEN_RD | SAFER_FOPEN_WR,
  SAFER_FOPEN_APPEND = SAFER_FOPEN_WR | 4
} safer_fopen_mode_t;

static inline char *
skip_prefix(const char *s, const char *prefix)
{
  char c;
  
  RUNTIME_ASSERT(NULL != s);
  RUNTIME_ASSERT(NULL != prefix);
  
  for (/* NOTHING*/; '\0' != (c = *prefix++); s++) {
    if (c != *s)
      return NULL; 
  }

  return deconstify_char_ptr(s);
}

static inline char *
skip_ci_prefix(const char *s, const char *prefix)
{
  char c;
  
  RUNTIME_ASSERT(NULL != s);
  RUNTIME_ASSERT(NULL != prefix);
  
  for (/* NOTHING*/; '\0' != (c = *prefix++); s++) {
    if (tolower((unsigned char) c) != tolower((unsigned char) *s))
      return NULL; 
  }

  return deconstify_char_ptr(s);
}

static inline char *
skip_spaces(const char *s)
{
  int c;
  
  for (/* NOTHING*/; (c = (unsigned char) *s) != '\0'; s++)
    if (!isspace(c))
      break;

  return (char *) s; /* override const */
}

static inline char *
skip_non_spaces(const char *s)
{
  int c;
  
  for (/* NOTHING*/; (c = (unsigned char) *s) != '\0'; s++)
    if (isspace(c))
      break;

  return (char *) s; /* override const */
}

char *print_uint(char *dst, size_t size, unsigned int v);
char *print_uint16(char *dst, size_t size, uint16_t v);
char *print_uint32(char *dst, size_t size, uint32_t v);
char *print_uint64(char *dst, size_t size, uint64_t v);
uint16_t parse_uint16(const char *src, char **endptr, int base, int *errorptr);
uint32_t parse_uint32(const char *src, char **endptr, int base, int *errorptr);
uint64_t parse_uint64(const char *src, char **endptr, int base, int *errorptr);
char *print_ipv4_addr(char *dst, size_t size, in_addr_t ipv4_addr);
char *print_ipv6_addr(char *dst, size_t size, const uint8_t *ipv6_addr);
char *print_net_addr(char *dst, size_t size, const net_addr_t addr);
char *print_net_addr_port(char *dst, size_t size,
    const net_addr_t addr, uint16_t port);
char *print_iso8601_date(char *dst, size_t size, time_t t);
char *print_rfc1123_date(char *dst, size_t size, time_t t);
char *print_ncsa_date(char *dst, size_t size, time_t t);
bool ipv4_is_private(in_addr_t addr);
bool parse_ipv4_addr(const char *s, in_addr_t *addr, char **endptr);
bool parse_ipv6_addr(const char *s, uint8_t *addr, char **endptr);
bool parse_net_addr(const char *s, net_addr_t *addr, char **endptr);
bool parse_port_number(const char *s, uint16_t *port, char **endptr);
char *url_decode(char *dst, const char *src, ssize_t size);
int url_split(const char *url, char *host, size_t host_size,
      uint16_t *port, const char **uri);
int parse_iso8601_date(const char *s, char **endptr, struct tm *);
int parse_rfc1123_date(const char *s, char **endptr, struct tm *);
int parse_rfc850_date(const char *s, char **endptr, struct tm *);
int parse_asctime_date(const char *s, char **endptr, struct tm *);
hash_t hash_str(const char *src);
bool cmp_str(const char *a, const char *b);
int uri_canonize_path(char *dst, const char *path);
const char *humanize_value(uint64_t v, uint64_t *i, uint64_t *f);
int tokenline(FILE *f, char *buf, size_t size);
char *create_pathname(const char *path, const char *filename);
FILE *safer_fopen(const char *pathname, safer_fopen_mode_t m);
uint32_t prime_up(uint32_t n);
int tm_cmp(const struct tm *a, const struct tm *b);

const char *net_addr_to_string(const net_addr_t addr);
const char *net_addr_port_to_string(const net_addr_t addr,
    const in_port_t port);
size_t off_t_to_string_buf(off_t v, char *dst, size_t size);
const char *off_t_to_string(off_t v);

struct sha1 {
  unsigned char data[20];
};

struct sha1_base32 {
  char str[33];
};

const char *sha1_to_base32_string(const struct sha1 *sha1);
struct sha1_base32 sha1_base32_string(const struct sha1 *sha1);

/* vi: set sts=2 sw=2 cindent: */
#endif /* NETTOOLS_HEADER_FILE */
