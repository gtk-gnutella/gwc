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

#include "connection.h"

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "nettools.h"
#include "mem.h"
#include "oop.h"

#ifdef HAVE_SOCKER_GET
#include <socker.h>
#endif /* HAVE_SOCKER_GET */

typedef enum connection_magic {
  CONNECTION_MAGIC = 0x7d794ad3
} connection_magic_t;

struct connection {
  connection_magic_t  magic;
  int                 ref_count;

  void                *context;
  ev_source_t         *source;
  connection_event_cb event_cb;
  net_addr_t          addr;
  uint16_t            port;
  bool                listening;
};

#define GETTER(type, attr) \
type \
connection_get_ ## attr (connection_t *c) \
{ \
  connection_check(c); \
  return (c->attr); \
}

#define SETTER(type, attr) \
void \
connection_set_ ## attr (connection_t *c, type val) \
{ \
  connection_check(c); \
  (c->attr) = (val); \
}

GETTER(net_addr_t, addr)
GETTER(uint16_t, port)
GETTER(bool, listening)
GETTER(ev_source_t *, source)
GETTER(void *, context)

SETTER(connection_event_cb, event_cb)
SETTER(void *, context)

void
connection_check(connection_t *c)
{
  RUNTIME_ASSERT(c);
  RUNTIME_ASSERT(CONNECTION_MAGIC == c->magic);
  RUNTIME_ASSERT(c->ref_count > 0);
}

char *
connection_get_addrstr(connection_t *c, char *dst, size_t size)
{
  connection_check(c);
  print_net_addr(dst, size, c->addr);
  return dst;
}

int
connection_get_fd(connection_t *c)
{
  connection_check(c);
  return c->source ? ev_source_get_fd(c->source) : -1;
}

bool
connection_is_closed(connection_t *c)
{
  connection_check(c);
  return !c->source || ev_source_is_closed(c->source);
}

void
connection_close(connection_t *c)
{
  connection_check(c);

  if (c->source) {
    int fd;

    ev_source_check(c->source);
    fd = ev_source_get_fd(c->source);
    if (fd >= 0) {
      if (close(fd)) {
        CRIT("close(%d) failed: %s", fd, compat_strerror(errno));
      }
      ev_source_close(c->source);
    }
    ev_source_set_context(c->source, NULL);
    ev_source_set_event_cb(c->source, NULL);
    ev_source_unref(c->source);
    c->source = NULL;
  }
}

static connection_t *
connection_alloc(void)
{
  connection_t *c;

  c = mem_chunk_alloc(sizeof *c);
  return c;
}

static void
connection_free(connection_t *c)
{
  if (c) {
    c->magic = 0;
    c->context = NULL;
    c->source = NULL;
    c->event_cb = NULL;
    mem_chunk_free(c, sizeof *c);
  }
}

void
connection_ref(connection_t *c)
{
  connection_check(c);
  RUNTIME_ASSERT(c->ref_count > 0);
  RUNTIME_ASSERT(c->ref_count < INT_MAX);
  c->ref_count++;
}

void
connection_unref(connection_t *c)
{
  connection_check(c);
  RUNTIME_ASSERT(c->ref_count > 0);
  c->ref_count--;
  if (0 == c->ref_count) {
    connection_free(c);
  }
}


static int
connection_set_sockopt(connection_t *c, int level, int opt, int optval,
    const char *optname)
{
  socklen_t optlen = sizeof optval;
  int fd, ret;
  
  connection_check(c);

  fd = connection_get_fd(c);
  ret = setsockopt(fd, level, opt, &optval, optlen);
  if (ret) {
    WARN("setsockopt(%d, ..., %s, ...) failed: %s\n",
        fd, optname, compat_strerror(errno));
  }
  return ret;
}

static void
connection_event_callback(ev_source_t *evs, ev_type_t ev)
{
  connection_t *c;

  ev_source_check(evs);

  c = ev_source_get_context(evs);
  connection_check(c);

  RUNTIME_ASSERT(c->event_cb);
  c->event_cb(c, ev);
}

void
connection_set_source(connection_t *c, ev_source_t *evs)
{
  connection_check(c);
  ev_source_check(evs);
  
  c->source = evs;
  ev_source_set_context(c->source, c);
  ev_source_set_event_cb(c->source, connection_event_callback);
}

int
connection_set_rcvbuf(connection_t *c, int optval)
{
  connection_check(c);
  return connection_set_sockopt(c, SOL_SOCKET, SO_RCVBUF, optval, "SO_RCVBUF");
}

int
connection_set_sndbuf(connection_t *c, int optval)
{
  connection_check(c);
  return connection_set_sockopt(c, SOL_SOCKET, SO_SNDBUF, optval, "SO_SNDBUF");
}

/**
 * Enables or disables the TCP_NODELAY socket option (Nagle algorithm) on
 * the connection socket.
 *
 * @param value if true, TCP_NODELAY is enabled, otherwise it's disabled.
 * @return -1 on failure (see errno) and zero on success.
 */
int
connection_set_nodelay(connection_t *c, bool value)
{
  connection_check(c);
  return connection_set_sockopt(c, IPPROTO_TCP, TCP_NODELAY,
          value ? 1 : 0, "TCP_NODELAY");
}

int
connection_set_tos_lowdelay(connection_t *c)
{
  connection_check(c);
  return connection_set_sockopt(c, IPPROTO_IP, IP_TOS, IPTOS_LOWDELAY,
            "IPTOS_LOWDELAY");
}

int
connection_set_tos_throughput(connection_t *c)
{
  connection_check(c);
  return connection_set_sockopt(c, IPPROTO_IP, IP_TOS, IPTOS_THROUGHPUT,
            "IPTOS_THROUGHPUT");
}

int
connection_set_tos_reliability(connection_t *c)
{
  connection_check(c);
  return connection_set_sockopt(c, IPPROTO_IP, IP_TOS, IPTOS_RELIABILITY,
            "IPTOS_RELIABILITY");
}

int
connection_set_rcvlowat(connection_t *c, unsigned int lowat)
{
  connection_check(c);
  
#ifdef SO_RCVLOWAT
  return connection_set_sockopt(c, SOL_SOCKET, SO_RCVLOWAT, lowat,
          "SO_RCVLOWAT");
#else   /* !SO_RCVLOWAT */
  (void) lowat;
#endif  /* SO_RCVLOWAT */

  return 0;
}

int
connection_set_blocking(connection_t *c, bool block)
{
  int flags, fd;

  connection_check(c);

  fd = connection_get_fd(c);
  flags = fcntl(fd, F_GETFL);
  if (-1 == flags) {
    CRIT("fcntl(%d, F_GETFL) failed: %s", fd, compat_strerror(errno));
    return -1;
  }

  if (block) {
    if (0 == (flags & O_NONBLOCK))
      return 0;
    flags &= ~O_NONBLOCK;
  } else {
    if (0 != (flags & O_NONBLOCK))
      return 0;
    flags |= O_NONBLOCK;
  }
  
  if (-1 == fcntl(fd, F_SETFL, flags)) {
    CRIT("fcntl(%d, F_SETFL) failed: %s", fd, compat_strerror(errno));
    return -1;
  }
  return 0;
}

/**
 * @return -1 on failure (see errno) and zero on success.
 */
int
connection_accept_http_filter(connection_t *c)
#if defined(SO_ACCEPTFILTER)
{
  static const struct accept_filter_arg zero_arg;
  struct accept_filter_arg arg;
  static const char name[] = "httpready";
  int fd;
  
  connection_check(c);

  arg = zero_arg;
  STATIC_ASSERT(sizeof arg.af_name >= STATIC_STRLEN(name));
  strncpy(arg.af_name, name, sizeof arg.af_name);
  
  fd = connection_get_fd(c);
  if (setsockopt(fd, SOL_SOCKET, SO_ACCEPTFILTER, &arg, sizeof arg)) {
    WARN("Cannot set SO_ACCEPTFILTER (%s): %s", name, compat_strerror(errno));
    return -1;
  }
  return 0;
}
#else /* !SO_ACCEPTFILTER */
{
  (void) c;
  errno = ENOTSUP;
  return -1;
}
#endif /* SO_ACCEPTFILTER */

/**
 * @return -1 on failure (see errno) and zero on success.
 */
int
connection_set_defer_accept(connection_t *c, int seconds)
#if defined(TCP_DEFER_ACCEPT)
{
  connection_check(c);
  return connection_set_sockopt(c, IPPROTO_TCP, TCP_DEFER_ACCEPT, seconds,
            "TCP_DEFER_ACCEPT");
}
#else /* !TCP_DEFER_ACCEPT */
{
  connection_check(c);
  (void) seconds;
  errno = ENOTSUP;
  return -1;
}
#endif /* TCP_DEFER_ACCEPT */

/**
 * @return -1 on failure (see errno) and zero on success.
 */
int
connection_set_quick_ack(connection_t *c, bool value)
#if defined(TCP_QUICKACK)
{
  connection_check(c);
  return connection_set_sockopt(c, IPPROTO_TCP, TCP_QUICKACK, value ? 1 : 0,
            "TCP_QUICKACK");
}
#else /* !TCP_QUICKACK */
{
  connection_check(c);
  (void) value;
  errno = ENOTSUP;
  return -1;
}
#endif /* TCP_QUICKACK */

/**
 * @return -1 on failure (see errno) and zero on success.
 */
int
connection_set_nopush(connection_t *c, bool value)
#if defined(TCP_NOPUSH)
{
  connection_check(c);
  return connection_set_sockopt(c, IPPROTO_TCP, TCP_NOPUSH, value ? 1 : 0,
            "TCP_NOPUSH");
}
#else /* !TCP_NOPUSH */
{
  connection_check(c);
  (void) value;
  errno = ENOTSUP;
  return -1;
}
#endif /* TCP_NOPUSH */

int
connection_socker_get(const net_addr_t addr, uint16_t port, int type)
#ifdef HAVE_SOCKER_GET
{
  char addr_buf[NET_ADDR_BUFLEN];
  int fd;

  print_net_addr(addr_buf, sizeof addr_buf, addr);
  fd = socker_get(net_addr_family(addr), type, 0, addr_buf, port);
  if (-1 == fd) {
    CRIT("socker_get() failed");
  }
  return fd;
}
#else /* HAVE_SOCKER_GET */
{
  (void) addr;
  (void) port;
  (void) type;
  errno = ENOTSUP;
  return -1;
}
#endif

int
connection_bind_socket(const net_addr_t addr, uint16_t port, int type,
  bool reuse_addr)
{
  bool used_socker = false;
  int fd;

  fd = socket(net_addr_family(addr), type, 0);
  if (fd < 0) {
    int saved_errno = errno;
    
    fd = connection_socker_get(addr, port, type);
    if (fd < 0) {
      if (ENOTSUP == errno) {
        errno = saved_errno;
        CRIT("socket() failed: %s", compat_strerror(errno));
      }
      return -1;
    }

    used_socker = true;
  }

  if (reuse_addr) {
    static const int enable = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof enable)) {
      CRIT("setsockopt() failed: %s", compat_strerror(errno));
      close(fd);
      return -1;
    }
  }

  if (!used_socker) {
    const struct sockaddr *sa;
    socklen_t len;

    /* Always enable IPv6-only for IPv6 sockets so that the socket()
     * does not accept IPv4 connections. Some implementations
     * do not support this anyway. */
#if defined(IPV6_V6ONLY) && defined(HAVE_IPV6_SUPPORT)
    if (AF_INET6 == net_addr_family(addr)) {
      static const int enable = 1;

      if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &enable, sizeof enable)) {
        WARN("setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, ...)");
      }
    }
#endif /* IPV6_V6ONLY */

    len = net_addr_sockaddr(addr, port, &sa);
    if (0 != bind(fd, sa, len)) {
      int saved_errno = errno;

      close(fd);
      fd = connection_socker_get(addr, port, type);
      if (fd < 0) {
        if (ENOTSUP == errno) {
          errno = saved_errno;
          CRIT("bind() failed: %s", compat_strerror(errno));
        }
        return -1;
      }
    }
  }

  return fd;
}

connection_t * 
connection_listen(const net_addr_t addr, uint16_t port, int backlog)
{
  connection_t *c;
  int fd;

  fd = connection_bind_socket(addr, port, SOCK_STREAM, true);
  if (-1 == fd) {
    return NULL;
  }

  if (listen(fd, backlog)) {
    CRIT("listen() failed: %s", compat_strerror(errno));
    close(fd);
    return NULL;
  }

  c = connection_new(addr, port);
  if (c) {
    c->listening = true;
    connection_set_source(c, ev_source_new(fd));
  } else {
    close(fd);
  }
  return c;
}

connection_t * 
connection_udp(const net_addr_t addr, uint16_t port)
{
  connection_t *c;
  int fd;

  fd = connection_bind_socket(addr, port, SOCK_DGRAM, false);
  if (-1 == fd) {
    return NULL;
  }
  
  c = connection_new(addr, port);
  if (c) {
    connection_set_source(c, ev_source_new(fd));
  } else {
    close(fd);
  }
  return c;
}

connection_t *
connection_accept(connection_t *server)
{
  static bool inherits = false;
#ifdef HAVE_IPV6_SUPPORT
  struct sockaddr_storage sa;
#else
  struct sockaddr sa;
#endif
  socklen_t len = sizeof sa;
  net_addr_t addr;
  int fd, s_fd;
  uint16_t port;

  s_fd = connection_get_fd(server);
  fd = accept(s_fd, cast_to_void_ptr(&sa), &len);
  if (-1 == fd)
    return NULL;

#ifdef HAVE_IPV6_SUPPORT
  switch (sa.ss_family) {
  case PF_INET6:
    {
      const struct sockaddr_in6 *sin6 = cast_to_void_ptr(&sa);
      
      addr = net_addr_peek_ipv6(cast_to_const_void_ptr(&sin6->sin6_addr));
      port = peek_be16(&sin6->sin6_port);
    }
    break;
#else
  switch (sa.sa_family) {
#endif

  case PF_INET:
    {
      const struct sockaddr_in *sin4 = cast_to_void_ptr(&sa);
      struct sockaddr_in sin4_copy;

      memcpy(&sin4_copy, sin4, sizeof *sin4);
      addr = net_addr_set_ipv4(sin4_copy.sin_addr.s_addr);
      port = peek_be16(&sin4_copy.sin_port);
    }
    break;

  default:
    {
      unsigned u =
#ifdef HAVE_IPV6_SUPPORT
        sa.ss_family;
#else
        sa.sa_family;
#endif

      WARN("accept()ed connection of unknown protocol (%u), closing", u);
    }
    close(fd);
    return NULL;
  }

  if (!inherits) {
    static bool checked = false;
    int c_flags, s_flags;
    
    c_flags = fcntl(fd, F_GETFL);
    if (c_flags == -1) {
      CRIT("fcntl(fd, F_GETFL) failed: %s", compat_strerror(errno));
      c_flags = 0;
    }
    
    s_flags = fcntl(s_fd, F_GETFL);
    if (s_flags == -1) {
      CRIT("fcntl(fd, F_GETFL) failed: %s", compat_strerror(errno));
    }

    if (-1 != s_flags && !checked) {
      checked = true;     
      inherits = (s_flags & O_NONBLOCK) == (c_flags & O_NONBLOCK);
      DBUG("client socket %s O_NONBLOCK from server",
        inherits ? "inherits" : "does NOT inherit");
    }

    c_flags = (c_flags & ~O_NONBLOCK) | (s_flags & O_NONBLOCK);
    if (-1 == fcntl(fd, F_SETFL, c_flags)) {
      CRIT("fcntl(fd, F_SETFL) failed: %s", compat_strerror(errno));
    }
  }
 
  {
    connection_t *c = connection_new(addr, port);
    if (c) {
      connection_set_source(c, ev_source_new(fd));
      return c;
    }
  }
  
  CRIT("connection_new() failed");
  close(fd);
  return NULL;
}

connection_t *
connection_new(const net_addr_t addr, uint16_t port)
{
  connection_t *c;
  
  c = connection_alloc();
  if (c) {
    c->magic = CONNECTION_MAGIC;
    c->ref_count = 1;
    c->addr = addr;
    c->port = port;
    c->context = NULL;
    c->source = NULL;
    c->listening = false;
  }
  return c;
}

/* vi: set ai et sts=2 sw=2 cindent: */
