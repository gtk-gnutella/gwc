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

#ifndef COMMON_HEADER_FILE
#define COMMON_HEADER_FILE

/***
 *** Portability hooks
 ***/

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif

#ifdef HAVE_PTHREAD_SUPPORT

#ifndef _REENTRANT
#define _REENTRANT
#endif

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#endif /* HAVE_PTHREAD_SUPPORT */

#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef HAVE_SYS_EVENT_H
#include <sys/event.h>
#endif

#ifdef HAVE_KQUEUE
/*
 * Some kqueue() implementations have a "struct kevent" with "udata"
 * being of type (void *) while others have "udata" of type "intptr_t".
 * To prevent incorrect casts and compiler warnings the two macros below
 * should be used to access this struct member.
 */
#ifdef HAVE_KEVENT_INT_UDATA
#define KEVENT_UDATA_TO_PTR(x) UINT2PTR(x)
#define PTR_TO_KEVENT_UDATA(x) PTR2UINT(x)
#else
#define KEVENT_UDATA_TO_PTR(x) (x)
#define PTR_TO_KEVENT_UDATA(x) (x)
#endif /* HAVE_KEVENT_INT_UDATA */
#endif /* HAVE_KQUEUE */

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/uio.h>

#ifdef HAVE_UNAME
#include <sys/utsname.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_FEATURES_H
#include <features.h>
#endif /* HAVE_FEATURES_H */

#if defined(__GLIBC__) && !defined(__GNUC__)
#define __gnuc_va_list va_list
#endif

#include <ctype.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif /* HAVE_ZLIB_H */

#ifdef DMALLOC
#include <dmalloc.h>
#endif

/**
 * A few compilers don't like "do { ... } while(0)" ``trick'' or don't
 * optimize it away. Thus use MACRO_BEGIN and MACRO_END, so that it
 * can be customized if desired.
 */
#define MACRO_BEGIN do {
#define MACRO_END } while (0)

#define STATIC_ASSERT_PLAIN(x) sizeof(char[((x) ? 1 : -23)])
#define STATIC_ASSERT(x) \
  MACRO_BEGIN { switch (0) { case 0: case ((x) ? 1 : 0): break; } } MACRO_END

   
#ifndef HAVE_UINT8_T
#if 8 == (SIZEOF_CHAR * CHAR_BIT)
typedef unsigned char uint8_t;
#elif 8 == (SIZEOF_SHORT * CHAR_BIT)
typedef unsigned short uint8_t;
#else
#error Missing type uint8_t!
#endif
#endif /* HAVE_UINT8_T */

#ifndef HAVE_INT8_T
#if 8 == (SIZEOF_CHAR * CHAR_BIT)
typedef char int8_t;
#elif 8 == (SIZEOF_SHORT * CHAR_BIT)
typedef short int8_t;
#else
#error Missing type int8_t!
#endif
#endif /* HAVE_INT8_T */

#ifndef HAVE_UINT16_T
#if 16 == (SIZEOF_SHORT * CHAR_BIT)
typedef unsigned short uint16_t;
#elif 16 == (SIZEOF_INT * CHAR_BIT)
typedef unsigned int uint16_t;
#else
#error Missing type uint16_t!
#endif
#endif /* HAVE_UINT16_T */

#ifndef HAVE_INT16_T
#if 16 == (SIZEOF_SHORT * CHAR_BIT)
typedef short int16_t;
#elif 16 == (SIZEOF_INT * CHAR_BIT)
typedef int int16_t;
#else
#error Missing type int16_t!
#endif
#endif /* HAVE_INT16_T */

#ifndef HAVE_UINT32_T
#if 32 == (SIZEOF_INT * CHAR_BIT)
typedef unsigned int uint32_t;
#elif 32 == (SIZEOF_LONG * CHAR_BIT)
typedef unsigned long uint32_t;
#else
#error Missing type uint32_t!
#endif
#endif /* HAVE_UINT32_T */

#ifndef HAVE_INT32_T
#if 32 == (SIZEOF_INT * CHAR_BIT)
typedef int int32_t;
#elif 32 == (SIZEOF_LONG * CHAR_BIT)
typedef long int32_t;
#else
#error Missing type int32_t!
#endif
#endif /* HAVE_INT32_T */

#ifndef HAVE_UINT64_T
#if 64 == (SIZEOF_LONG * CHAR_BIT)
typedef unsigned long uint64_t;
#elif 64 == (SIZEOF_LONG_LONG * CHAR_BIT)
typedef unsigned long long uint64_t;
#else
#error Missing type uint64_t!
#endif
#endif /* HAVE_UINT64_T */

#ifndef HAVE_INT64_T
#if 64 == (SIZEOF_LONG * CHAR_BIT)
typedef long int64_t;
#elif 64 == (SIZEOF_LONG_LONG * CHAR_BIT)
typedef long long int64_t;
#else
#error Missing type int64_t!
#endif
#endif /* HAVE_INT64_T */

/* NOTE: It's not necessarily a good idea to use these, as printf() etc.
 * might not be handle them. Better use uint64_to_string() etc. */
#ifndef PRId64
#if SIZEOF_LONG == 8
#define PRId64 "ld"
#elif SIZEOF_LONG_LONG == 8
#define PRId64 "lld"
#else
/* #error Missing definition of PRId64! */
#endif
#endif /* PRId64 */

#ifndef PRIu64
#if SIZEOF_LONG == 8
#define PRIu64 "lu"
#elif SIZEOF_LONG_LONG == 8
#define PRIu64 "llu"
#else
/* #error Missing definition of PRIu64! */
#endif
#endif /* PRIu64 */

#ifndef PRIx64
#if SIZEOF_LONG == 8
#define PRIx64 "lx"
#elif SIZEOF_LONG_LONG == 8
#define PRIx64 "llx"
#else
/* #error Missing definition of PRIx64! */
#endif
#endif /* PRIx64 */


#ifndef __bool_true_false_are_defined
#define true 1
#define false 0
#endif /* __bool_true_false_are_defined */

#ifndef SIZEOF_BOOL
typedef int bool;
#define SIZEOF_BOOL SIZEOF_INT
#endif /* SIZEOF_BOOL */

#ifndef HAVE_SOCKLEN_T
typedef unsigned int socklen_t;
#endif /* HAVE_SOCKLEN_T */

#ifndef HAVE_IN_ADDR_T
typedef uint32_t in_addr_t;
#endif /* HAVE_IN_ADDR_T */

#ifndef HAVE_IN_PORT_T
typedef uint16_t in_port_t;
#endif /* HAVE_IN_PORT_T */

#ifndef HAVE_INTPTR_T
#if SIZEOF_VOID_PTR == 4
typedef int32_t intptr_t;
#elif SIZEOF_VOID_PTR == 8 
typedef int64_t intptr_t;
#else
#error Missing definition of intptr_t!
#endif
#endif /* HAVE_INTPTR_T */

#ifndef HAVE_UINTPTR_T
#if SIZEOF_VOID_PTR == 4
typedef uint32_t uintptr_t;
#elif SIZEOF_VOID_PTR == 8 
typedef uint64_t uintptr_t;
#else
#error Missing definition of uintptr_t!
#endif
#endif /* HAVE_UINTPTR_T */

#define INT2PTR(x) ((void *)((intptr_t) (x)))
#define UINT2PTR(x) ((void *)((uintptr_t) (x)))
#define PTR2INT(x) ((intptr_t)(x)) 
#define PTR2UINT(x) ((uintptr_t)(x)) 

#ifndef HAVE_C99_inline
#ifdef HAVE___inline
#define inline __inline
#else   /* !HAVE___inline */
#define inline
#endif  /* HAVE___inline */
#endif  /* HAVE_C99_inline */

#include "casts.h"

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif /* MAX */

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif /* MIN */

/* returns (-1, 0, 1) if a is (smaller, equal, greater) b respectively */
#define SIGN_CMP(a, b) ((a) > (b) ? 1 : ((a) < (b) ? -1 : 0)) 

#ifdef __GNUC__
#define HAVE_GCC(a,b) \
  ((__GNUC__ > (a)) || (__GNUC__ == (a) && __GNUC_MINOR__ >= (b)))
#else
#define HAVE_GCC(a,b) 0
#endif /* __GNUC__ */

#if HAVE_GCC(3,3)
#define NON_NULL __attribute__((__nonnull__))
#else
#define NON_NULL
#endif /* HAVE_GCC(3,3) */

#if HAVE_GCC(3,3)
#define CHECK_FMT(fmt, arg) __attribute__ ((format (__printf__, fmt, arg)))
#else
#define CHECK_FMT(fmt, arg)
#endif /* HAVE_GCC(3,3) */

#if HAVE_GCC(3,0) && defined(__x86__)
#define REGPARM(n) __attribute__((__regparm__(n)))
#else
#define REGPARM(n)
#endif /* HAVE_GCC(3,0) */

#if HAVE_GCC(3,0)
#define NO_RETURN __attribute__((__noreturn__))
#else
#define NO_RETURN
#endif /* HAVE_GCC(3,0) */

#ifndef HAVE_C99_func
/* __FUNCTION__ is something else!
 * __func__ must not be used like printf("blah" __func__ "blubb")! */
#define __func__ "function"
#endif
  
#include "debug.h"
#include "compat.h"

enum {
#ifndef HAVE_SHUT_RD
	SHUT_RD = 0,
#define SHUT_RD SHUT_RD
#endif /* HAVE_SHUT_RD */

#ifndef HAVE_SHUT_WR
	SHUT_WR = 1,
#define SHUT_WR SHUT_WR
#endif /* HAVE_SHUT_WR */

#ifndef HAVE_SHUT_RDWR
	SHUT_RDWR = 2,
#define SHUT_RDWR SHUT_RDWR
#endif /* SHUT_RDWR */
	SHUT_THE_FUCK_UP
};

/***
 *** Convenience macros
 ***/

#define ARRAY_LEN(a) (sizeof (a) / sizeof((a)[0]))
#define STATIC_STRLEN(x) (ARRAY_LEN(x) - 1)

#define DEV_NULL "/dev/null"

#define BUFFERSIZE 4096
#define MAX_URL_SIZE BUFFERSIZE

#define DO_FREE(x) MACRO_BEGIN {         \
  void *hidden_copy__ = (x);  \
  if (hidden_copy__) {         \
    free(hidden_copy__);       \
    x = NULL;      \
  }                             \
} MACRO_END

#define XSTRINGIFY(x) #x
#define STRINGIFY(x) XSTRINGIFY(x)

#define DIFFTIMEVAL(a, b) \
  (difftime((a)->tv_sec, (b)->tv_sec) * 1000000 + (a)->tv_usec - (b)->tv_usec)

/* Determines the maximum value of the given integer type "t". This
 * works for signed as well as unsigned types. However, it's assumed
 * the type consists of exactly sizeof (type) * CHAR_BIT bits. */
#define MAX_INT_VAL(t) \
	(((t) 1 << (CHAR_BIT * sizeof(t) - 1 - ((t) -1 < 0))) \
   	- 1 + ((t) 1 << (CHAR_BIT * sizeof(t) - 1 - ((t) -1 < 0))))

#ifndef TIME_T_MAX
/* This assumes time_t is an integer, not a float */
#define TIME_T_MAX MAX_INT_VAL(time_t)
#endif /* TIME_T_MAX */

#ifndef OFF_T_MAX
#define OFF_T_MAX MAX_INT_VAL(off_t)
#endif /* OFF_T_MAX */

#if defined(NDEBUG)
#define RUNTIME_ASSERT_FULL(expr, file, line, func)
#define RUNTIME_ASSERT(expr)
#else /* !NDEBUG */
#define RUNTIME_ASSERT_FULL(expr, file, line, func) \
  MACRO_BEGIN { \
    if (!(expr)) { \
      static const struct assert_point ap_ = { #expr, file, line, func }; \
      debug_assert(&ap_); \
    } \
  } MACRO_END
#define RUNTIME_ASSERT(expr) \
  RUNTIME_ASSERT_FULL((expr), __FILE__, STRINGIFY(__LINE__), __func__)
#endif  /* NDEBUG */

/* Memory allocation logging */
  
#if 0
static void *
my_alloc(size_t n, size_t m,
    const char *file, const char *function, unsigned line)
{
  void *p;
  static size_t all;
  
  p = calloc(n, m);
  if (p)
    all += n*m;
  fprintf(stderr, "%s::%s(%u): alloc(%u)=%p (all=%lu)\n",
      file, function, line,
      (unsigned) n * m, p, (unsigned long) all);
  return p;
}
#define calloc(n,m) my_alloc((n),(m),(__FILE__),(__func__),(__LINE__))
#define malloc(m) calloc(1, (m))

#endif /* 0 */

typedef struct {
  /* This is not as paranoid as it seems. It prevents that config.h is
   * out-of-sync with the compiler resp. compiler flags. */

  int x[
    STATIC_ASSERT_PLAIN(SIZEOF_CHAR  == sizeof(signed char)) ^
    STATIC_ASSERT_PLAIN(SIZEOF_SHORT == sizeof(signed short)) ^
    STATIC_ASSERT_PLAIN(SIZEOF_INT   == sizeof(signed int)) ^
    STATIC_ASSERT_PLAIN(SIZEOF_LONG  == sizeof(signed long)) ^

    STATIC_ASSERT_PLAIN(SIZEOF_CHAR  == sizeof(unsigned char)) ^
    STATIC_ASSERT_PLAIN(SIZEOF_SHORT == sizeof(unsigned short)) ^
    STATIC_ASSERT_PLAIN(SIZEOF_INT   == sizeof(unsigned int)) ^
    STATIC_ASSERT_PLAIN(SIZEOF_LONG  == sizeof(unsigned long)) ^

    STATIC_ASSERT_PLAIN(SIZEOF_BOOL  == sizeof(bool)) ^

    STATIC_ASSERT_PLAIN(1 == sizeof(int8_t)) ^
    STATIC_ASSERT_PLAIN(2 == sizeof(int16_t)) ^ 
    STATIC_ASSERT_PLAIN(4 == sizeof(int32_t)) ^ 
    STATIC_ASSERT_PLAIN(8 == sizeof(int64_t)) ^

    STATIC_ASSERT_PLAIN(1 == sizeof(uint8_t)) ^
    STATIC_ASSERT_PLAIN(2 == sizeof(uint16_t)) ^
    STATIC_ASSERT_PLAIN(4 == sizeof(uint32_t)) ^
    STATIC_ASSERT_PLAIN(8 == sizeof(uint64_t)) ^
    
    STATIC_ASSERT_PLAIN((uint8_t) -1 == 0xffU) ^
    STATIC_ASSERT_PLAIN((uint8_t) -1 > 0) ^

    STATIC_ASSERT_PLAIN((uint16_t) -1 == 0xffffU) ^
    STATIC_ASSERT_PLAIN((uint16_t) -1 > 0) ^

    STATIC_ASSERT_PLAIN((in_port_t) -1 == 0xffffU) ^
    STATIC_ASSERT_PLAIN((in_port_t) -1 > 0) ^

    STATIC_ASSERT_PLAIN((uint32_t) -1 == 0xffffffffUL) ^
    STATIC_ASSERT_PLAIN((uint32_t) -1 > 0) ^

    STATIC_ASSERT_PLAIN((in_addr_t) -1 == 0xffffffffUL) ^
    STATIC_ASSERT_PLAIN((in_addr_t) -1 > 0) ^

    STATIC_ASSERT_PLAIN((uint64_t) -1 >> 32 == 0xffffffffUL) ^
    STATIC_ASSERT_PLAIN((uint64_t) -1 > 0) ^
    
    STATIC_ASSERT_PLAIN(sizeof(intptr_t) == sizeof(void *)) ^
    STATIC_ASSERT_PLAIN(sizeof(uintptr_t) == sizeof(void *)) ^

#if 0
    STATIC_ASSERT_PLAIN((uintptr_t)(void *)(intptr_t) -1 == (uintptr_t) -1) ^
    STATIC_ASSERT_PLAIN((uintptr_t)(void *) 0 == 0) ^
    STATIC_ASSERT_PLAIN((intptr_t)(void *) INT_MAX == INT_MAX) ^
    STATIC_ASSERT_PLAIN((uintptr_t)(void *) INT_MAX == INT_MAX) ^
#endif
    
    STATIC_ASSERT_PLAIN(sizeof(void *) >= sizeof(int)) ^

    STATIC_ASSERT_PLAIN( 2 == MAX(1, 2)) ^
    STATIC_ASSERT_PLAIN( 1 == MAX(-1, 1)) ^
    STATIC_ASSERT_PLAIN( 0 == MIN(0, 2)) ^
    STATIC_ASSERT_PLAIN(-1 == MIN(-1, 1))
  ];
} config_h_consistency_check;

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
#endif /* COMMON_HEADER_FILE */
