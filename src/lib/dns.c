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

#include "dns.h"

#if defined(HAVE_GETHOSTBYNAME) && \
	(defined(HAVE_HERROR) || defined(HAVE_HSTRERROR))
#define USE_GETHOSTBYNAME
#endif

#if defined(HAVE_GETADDRINFO) && \
	defined(HAVE_GAI_STRERROR) && defined(HAVE_FREEADDRINFO)
#define USE_GETADDRINFO
#undef USE_GETHOSTBYNAME
#endif


#if !defined(USE_GETHOSTBYNAME) && !defined(USE_GETADDRINFO)
#error Either gethostname() or getaddrinfo() is necessary!
#endif


#if defined(USE_GETADDRINFO)
struct dnslookup_ctx {
  struct addrinfo *ai0, *ai;
};

int
dnslookup(dnslookup_ctx_t *ctx, const char *host, int *error)
{
  static const struct addrinfo zero_hints;
  struct addrinfo hints;
  int ret;
  
  RUNTIME_ASSERT(ctx != NULL);
  RUNTIME_ASSERT(host != NULL);
  RUNTIME_ASSERT(error != NULL);

  *error = 0;
  hints = zero_hints;
  hints.ai_family = PF_UNSPEC;

  ret = getaddrinfo(host, NULL, &hints, &ctx->ai0);
  if (ret) {
    *error = EADDRNOTAVAIL;
    ctx->ai = ctx->ai0 = NULL;
    return -1;
  }
  ctx->ai = ctx->ai0;
  return 0;
}

bool
dnslookup_next(dnslookup_ctx_t *ctx, net_addr_t *addr)
{
  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(addr);

  *addr = net_addr_unspecified;
  while (ctx->ai) {
    const void *sa = ctx->ai->ai_addr;
    int family = ctx->ai->ai_family;
    
    ctx->ai = ctx->ai->ai_next;
    switch (family) {
    case PF_INET:
      {
        const struct sockaddr_in *sin4 = sa;
        *addr = net_addr_set_ipv4(sin4->sin_addr.s_addr);
      }
      return true;
      
#ifdef HAVE_IPV6_SUPPORT
    case PF_INET6:
      {
        const struct sockaddr_in6 *sin6 = sa;
        *addr = net_addr_peek_ipv6(sin6->sin6_addr.s6_addr);
      }
      return true;
#endif
       
    default:
      ;
    }
  }
  
  return false;
}

void
dnslookup_ctx_reset(dnslookup_ctx_t *ctx)
{
  RUNTIME_ASSERT(ctx);
  if (ctx->ai0) {
    freeaddrinfo(ctx->ai0);
    ctx->ai0 = NULL;
  }
  memset(ctx, 0, sizeof *ctx);
}

#else /* USE_GETHOSTBYNAME */

struct dnslookup_ctx {
  struct hostent *he;
  size_t i;
};

int
dnslookup(dnslookup_ctx_t *ctx, const char *host, int *error)
{
  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(host);
  RUNTIME_ASSERT(error);
  
  ctx->i = 0;
  ctx->he = gethostbyname(host);
  if (!ctx->he) {
    *error = h_errno;
  }
  return (ctx->he && ctx->he->h_addrtype == AF_INET) ? 0 : -1;
}

bool
dnslookup_next(dnslookup_ctx_t *ctx, uint32_t *addr)
{
  const void *p;
  RUNTIME_ASSERT(ctx);
  RUNTIME_ASSERT(addr);

  *addr = 0; /* Just in case */
  p = ctx->he->h_addr_list[ctx->i];
  if (p) {
    memcpy(addr, p, sizeof *addr);
    ctx->i++;
    return true;
  }
  return false;
}

void
dnslookup_ctx_reset(dnslookup_ctx_t *ctx)
{
  RUNTIME_ASSERT(ctx);
  memset(ctx, 0, sizeof *ctx);
}

#endif /* USE_GETHOSTBYNAME */

void
dnslookup_ctx_free(dnslookup_ctx_t *ctx)
{
  RUNTIME_ASSERT(ctx);
  dnslookup_ctx_reset(ctx);
  DO_FREE(ctx);
}

dnslookup_ctx_t *
dnslookup_ctx_new(void)
{
  dnslookup_ctx_t *ctx;

  ctx = calloc(1, sizeof *ctx);
  return ctx;
}

/* vi: set ai et sts=2 sw=2 cindent: */
