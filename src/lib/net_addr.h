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
 *    without specific prior written permission.
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

#ifndef NET_ADDR_HEADER_FILE
#define NET_ADDR_HEADER_FILE

#include "common.h"

typedef union net_addr {
  uint8_t ipv6[16];
  uint32_t u32[4];
  uint64_t u64[2];
} net_addr_t;

static const net_addr_t net_addr_ipv4_mapped = {
  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0 }
};

static const net_addr_t net_addr_unspecified = {
  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

static const net_addr_t net_addr_multicast = {
  { 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

static const net_addr_t net_addr_link_local = {
  { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

static const net_addr_t net_addr_site_local = {
  { 0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

static inline bool
net_addr_matches(const net_addr_t a, const net_addr_t b, uint8_t prefixlen)
{
  uint8_t bits, i, s;

  for (bits = MIN(prefixlen, 128), i = 0; bits >= 8; bits -= 8, i++) {
    if (a.ipv6[i] != b.ipv6[i])
      return false;
  }

  s = (8 - bits);
  return 0 == bits ? true : (a.ipv6[i] >> s) == (b.ipv6[i] >> s);
}


static inline bool
net_addr_is_ipv4_mapped(const net_addr_t addr)
{
  return net_addr_matches(addr, net_addr_ipv4_mapped, 96); 
}

static inline bool
net_addr_is_multicast(const net_addr_t addr)
{
  return net_addr_matches(addr, net_addr_multicast, 8); 
}

static inline bool
net_addr_is_link_local(const net_addr_t addr)
{
  return net_addr_matches(addr, net_addr_link_local, 10);
}

static inline bool
net_addr_is_site_local(const net_addr_t addr)
{
  return net_addr_matches(addr, net_addr_site_local, 10);
}

static inline in_addr_t
net_addr_ipv4(const net_addr_t addr)
{
  in_addr_t ip;

  memcpy(&ip, &addr.ipv6[12], 4);
  return ip;
}

static inline net_addr_t
net_addr_set_ipv4(const in_addr_t ip)
{
  net_addr_t addr;

  memcpy(&addr.ipv6[0], net_addr_ipv4_mapped.ipv6, 12);
  memcpy(&addr.ipv6[12], &ip, 4);
  return addr;
}

static inline net_addr_t
net_addr_peek_ipv4(const void *addr_ptr)
{
  net_addr_t addr;

  memcpy(&addr.ipv6[0], net_addr_ipv4_mapped.ipv6, 12);
  memcpy(&addr.ipv6[12], addr_ptr, 4);
  return addr;
}

static inline void
net_addr_poke_ipv4(const net_addr_t addr, char data[4])
{
  memcpy(data, &addr.ipv6[12], 4);
}

static inline const uint8_t *
net_addr_ipv6(const net_addr_t *addr)
{
  return addr->ipv6;
}

static inline net_addr_t 
net_addr_peek_ipv6(const uint8_t *ipv6_addr)
{
  net_addr_t addr;
  
  memcpy(addr.ipv6, ipv6_addr, 16);
  return addr;
}

static inline bool
net_addr_equal(const net_addr_t a, const net_addr_t b)
{
  return a.u64[1] == b.u64[1] && a.u64[0] == b.u64[0];
}

static inline bool
net_addr_equal_ptr(const net_addr_t *a, const net_addr_t *b)
{
  return a->u64[1] == b->u64[1] && a->u64[0] == b->u64[0];
}

static inline uint32_t
net_addr_hash(const net_addr_t addr)
{
  int i;
  uint32_t h = addr.ipv6[15];
  
  for (i = 0; i < 16; i++)
    h ^= addr.ipv6[i] << (i << 2);

  return h;
}

static inline bool
ipv4_is_private(in_addr_t addr)
{
  const uint8_t *a = (const uint8_t *) &addr;

  return (
    (a[0] == 0) ||
    (a[0] == 10) ||
    (a[0] == 127) ||
    (a[0] == 169 && a[1] == 254) ||
    (a[0] == 172 && (a[1] & 0xf0) == 16) ||
    (a[0] == 192 && a[1] == 0 && a[2] == 2) ||
    (a[0] == 192 && a[1] == 168) ||
    ((a[0] & 0xc0) == 224)
  );
}

static inline int
net_addr_family(const net_addr_t addr)
{
  return net_addr_is_ipv4_mapped(addr)
	    ? AF_INET
#ifdef HAVE_IPV6_SUPPORT
	    : AF_INET6;
#else
	    : AF_UNSPEC;
#endif /* HAVE_IPV6_SUPPORT */
}


static inline bool
net_addr_is_ipv4_private(const net_addr_t addr)
{
  return net_addr_is_ipv4_mapped(addr) && ipv4_is_private(net_addr_ipv4(addr));
}

static inline bool
net_addr_is_private(const net_addr_t addr)
{
  return net_addr_is_site_local(addr) || 
    net_addr_is_link_local(addr) || 
    net_addr_is_ipv4_private(addr);
}

static inline socklen_t
net_addr_sockaddr_ipv6(const net_addr_t addr, in_port_t port,
    const struct sockaddr **sock_addr)
{
#ifdef HAVE_IPV6_SUPPORT
  static const struct sockaddr_in6 zero_sin6;
  static struct sockaddr_in6 sin6;

  sin6 = zero_sin6;
  memcpy(&sin6.sin6_addr, net_addr_ipv6(&addr), sizeof sin6.sin6_addr);
  sin6.sin6_port = htons(port);
  sin6.sin6_family = AF_INET6;
  *sock_addr = cast_to_void_ptr(&sin6);
  return sizeof sin6;
#else
  (void) addr;
  (void) port;
  *sock_addr = NULL;
  return 0;
#endif /* HAVE_IPV6_SUPPORT */
}

static inline socklen_t
net_addr_sockaddr_ipv4(const net_addr_t addr, in_port_t port,
    const struct sockaddr **sock_addr)
{
  static const struct sockaddr_in zero_sin4;
  static struct sockaddr_in sin4;

  sin4 = zero_sin4;
  sin4.sin_addr.s_addr = net_addr_ipv4(addr);
  sin4.sin_port = htons(port);
  sin4.sin_family = AF_INET;
  *sock_addr = cast_to_void_ptr(&sin4);
  return sizeof sin4;
}

static inline socklen_t
net_addr_sockaddr(const net_addr_t addr, in_port_t port,
    const struct sockaddr **sock_addr)
{
  return net_addr_is_ipv4_mapped(addr)
    ? net_addr_sockaddr_ipv4(addr, port, sock_addr)
    : net_addr_sockaddr_ipv6(addr, port, sock_addr);
}

static inline int
sockaddr_to_net_addr(const struct sockaddr *sock_addr,
  net_addr_t *addr_ptr, in_port_t *port_ptr)
{
  switch (sock_addr->sa_family) {
  case AF_INET:
    {
      const struct sockaddr_in *sin4;

      sin4 = cast_to_const_void_ptr(sock_addr);
      if (port_ptr) {
	*port_ptr = htons(sin4->sin_port);
      }
      if (addr_ptr) {
	*addr_ptr = net_addr_peek_ipv4(
		      cast_to_const_void_ptr(&sin4->sin_addr.s_addr));
      }
      return 0;
    }
  case AF_INET6:
    {
      const struct sockaddr_in6 *sin6;

      sin6 = cast_to_const_void_ptr(sock_addr);
      if (port_ptr) {
	*port_ptr = htons(sin6->sin6_port);
      }
      if (addr_ptr) {
	*addr_ptr = net_addr_peek_ipv6(sin6->sin6_addr.s6_addr);
      }
      return 0;
    }
  }

  return -1;
}


/* vi: set sts=2 sw=2 cindent: */
#endif /* NET_ADDR_HEADER_FILE */
