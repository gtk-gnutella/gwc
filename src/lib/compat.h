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

#ifndef COMPAT_HEADER_FILE
#define COMPAT_HEADER_FILE

#include "common.h"

char * compat_strdup(const char *s);
int compat_strncasecmp(const char *s1, const char *s2, size_t len);
void (*set_signal(int signo, void (*handler)(int)))(int);
const char *compat_strerror(int error);
size_t compat_getpagesize(void);
void * compat_protect_memdup(const void *p, size_t size);
void * compat_protect_strdup(const char *s);
void * compat_page_align(size_t size);
void compat_page_free(void *p, size_t size);
time_t compat_mono_time(struct timeval *tv);
int compat_chroot(const char *dir);
int compat_disable_fork(void);
int compat_disable_coredumps(void);
int compat_daemonize(const char *directory);
int compat_close_std_streams(void);
void compat_setproctitle(const char *title);
void *compat_memmem(const void *data, size_t size,
      const void *pattern, size_t pattern_size);

static inline bool
is_temporary_error(int error)
{
  switch (error) {
  case EAGAIN:
#if defined(EWOULDBLOCK) && EAGAIN != EWOULDBLOCK
  case EWOULDBLOCK:
#endif /* EWOULDBLOCK != EAGAIN */
  case EINTR:
    return true;
  default:
    return false;
  }
}

static inline struct iovec
iov_from_string(const char *s)
{
  struct iovec iov;
  
  iov.iov_base = (char *) s;
  iov.iov_len = s ? strlen(s) : 0;
  return iov;
}
 
/**
 * Rounds ``n'' up so that it matches the given alignment ``align''.
 */
static inline size_t
round_size(size_t align, size_t n)
{
	size_t m = n % align;
	return m ? n + (align - m) : MAX(n, align);
}

#define le_compose(v, byte, i) ((v) | ((byte) << ((i) << 3)))
#define be_compose(v, byte, i) (((v) << 8) | (byte)) 

#define PEEK(bits, endian)        \
static inline uint ## bits ## _t          \
peek_ ## endian ## bits(const void *p)    \
{                                         \
  const uint8_t *q = (const uint8_t *) p; \
  uint ## bits ## _t v;                   \
  int i;                                  \
                                          \
  v = q[0];                               \
  for (i = 1; i < (bits >> 3); i++)       \
    v = endian ## _compose(v, (uint ## bits ## _t) q[i], i);   \
                                          \
  return v;                               \
}

PEEK(16, le)
PEEK(32, le)
PEEK(64, le)

PEEK(16, be)
PEEK(32, be)
PEEK(64, be)
#undef PEEK

#define POKE_LE(bits)                                   \
static inline void                                      \
poke_le ## bits(void *p, uint ## bits ## _t v)          \
{                                                       \
  unsigned int i;                                       \
  uint8_t *q = (uint8_t *) p;                           \
                                                        \
  for (i = 0; i < (bits >> 3); i++) {                   \
    q[i] = v;                                           \
    v >>= 8;                                            \
  }                                                     \
}

POKE_LE(16)
POKE_LE(32)
POKE_LE(64)
#undef POKE_LE

#define POKE_BE(bits)                                   \
static inline void                                      \
poke_be ## bits(void *p, uint ## bits ## _t v)          \
{                                                       \
  int i;                                                \
  uint8_t *q = (uint8_t *) p;                           \
                                                        \
  for (i = (bits >> 3); i-- > 0; /* NOTHING */) {       \
    q[i] = v;                                           \
    v >>= 8;                                            \
  }                                                     \
}

POKE_BE(16)
POKE_BE(32)
POKE_BE(64)
#undef POKE_BE

#define PEEK_U(bits) \
static inline uint ## bits ## _t \
peek_u ## bits(const void *p) \
{ \
  union { \
    uint ## bits ## _t v; \
    uint8_t u8[bits / 8]; \
  } buf; \
  const uint8_t *src = p; \
  unsigned i; \
\
  for (i = 0; i < (bits / 8); i++) { \
    buf.u8[i] = src[i]; \
  } \
  return buf.v; \
}

PEEK_U(16)
PEEK_U(32)
PEEK_U(64)
#undef PEEK_U

/*
 * NZERO is used for setpriority() and getpriority(). To
 * protect against a missing definition, use
 * COMPAT_{MIN,MAX}_PRIORITY instead of -NZERO and NZERO-1.
 * However, the real value is returned by sysconf(_SC_NZERO);
 */
#ifdef NZERO
/* NZERO should be defined in <limits.h> */
#define COMPAT_MIN_PRIORITY (-NZERO)
#define COMPAT_MAX_PRIORITY (NZERO - 1)
#else
/* Just make something up */
#define COMPAT_MIN_PRIORITY INT_MIN
#define COMPAT_MAX_PRIORITY INT_MAX
#endif

/* vi: set ai et sts=2 sw=2 cindent: */
#endif /* COMPAT_HEADER_FILE */
