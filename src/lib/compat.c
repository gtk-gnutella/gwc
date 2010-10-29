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

#include "compat.h"
#include "append.h"

#include <signal.h>

static CHECK_FMT(1, 2) void
debug_msg(const char *fmt, ...)
{
  va_list ap;
  int saved_errno = errno;
  char msg[4096];

  va_start(ap, fmt);
  vsnprintf(msg, sizeof msg, fmt, ap);
  fputs(msg, stderr);
  fputc('\n', stderr);
  va_end(ap);
  errno = saved_errno;
}

static CHECK_FMT(1, 2) void
debug_error(const char *fmt, ...)
{
  va_list ap;
  int saved_errno = errno;
  char msg[4096];

  va_start(ap, fmt);
  vsnprintf(msg, sizeof msg, fmt, ap);
  fputs(msg, stderr);
  fputs(": ", stderr);
  fputs(strerror(saved_errno), stderr);
  fputc('\n', stderr);
  va_end(ap);
  errno = saved_errno;
}

char *
compat_strdup(const char *s)
{
  size_t size;
  char *p;

  RUNTIME_ASSERT(s);
  size = strlen(s) + 1;
  RUNTIME_ASSERT(size > 0 && size <= INT_MAX);
  p = (char *) malloc(size);
  if (p) {
    memcpy(p, s, size);
  }
  return p;
}

int
compat_strncasecmp(const char *s1, const char *s2, size_t len)
{
  int c1, c2;

  RUNTIME_ASSERT(s1);
  RUNTIME_ASSERT(s2);
 
  c1 = c2 = '\0';
  do {
    if (!len--)
      break;
    
    c1 = tolower((unsigned char) *s1);
    c2 = tolower((unsigned char) *s2);
    s1++;
    s2++;
  } while (c1 != '\0' && c1 == c2);
  
  return c1 - c2;
}

void (*
set_signal(int signo, void (*handler)(int)))(int)
{
  struct sigaction sa, osa;

  memset(&sa, 0, sizeof sa);
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = signo != SIGALRM ? SA_RESTART
#ifdef HAVE_SA_INTERRUPT
    : SA_INTERRUPT;
#else
    : 0;
#endif
  return sigaction(signo, &sa, &osa) ? SIG_ERR : osa.sa_handler;
}

const char *
compat_strerror(int error)
{
  return strerror(error);
}

size_t
compat_getpagesize(void)
{
  static size_t pagesize;
  
  if (!pagesize) {
    long ret;
#if defined(_SC_PAGESIZE)
    int name = _SC_PAGESIZE;
#else
#if defined(_SC_PAGE_SIZE)
    int name = _SC_PAGESIZE;
#endif
#endif

    errno = 0;
    ret = sysconf(name);
    if ((long) -1L == ret) {
      if (errno != 0) {
#ifdef DBUG
        DBUG("sysconf(_SC_PAGESIZE) failed: %s", compat_strerror(errno));
#endif /* DBUG */
      }
  
#if defined(HAVE_GETPAGESIZE)
      ret = (long) getpagesize();
#endif /* HAVE_GETPAGESIZE */
        
    }
    
    if (ret < 0) {
      /* Assuming 64 KB pagesize */
      pagesize = 64 * 1024;
    } else {
      pagesize = ret;
    }
  }

  RUNTIME_ASSERT(pagesize > 0);
  return pagesize;
}

void *
compat_valloc(size_t size)
{
#ifdef HAVE_VALLOC
  return valloc(size);
#endif
  
  size_t psize = compat_getpagesize(), cut = 0;
  char *p = NULL;
  int i;
  
  for (i = 0; i < 2; i++) {
    char *q;
   
    q = realloc(p, size);
    if (!q) {
      DO_FREE(p);
      return NULL;
    }
    p = q;
    cut = (unsigned long) p % psize;
    if (!cut)
      break;
    
    if (i == 1) {
      p = &p[psize - cut];
      break;
    }
    size += psize;
  }
  
  RUNTIME_ASSERT((unsigned long) p % psize == 0);
  return p;
}

void *
compat_protect_memdup(const void *p, size_t size)
{
  size_t len, psize;
  void *q;

  psize = compat_getpagesize();
  RUNTIME_ASSERT(psize > 0);
  len = (size / psize + (size % psize ? 1 : 0)) * psize;
  RUNTIME_ASSERT(len >= size);
  RUNTIME_ASSERT(len >= psize);
  
  q = compat_valloc(len);
  if (q) {
    memcpy(q, p, size);
    if (mprotect(q, len, PROT_READ)) {
#ifdef DBUG
      WARN("mprotect(%p, %lu, PROT_READ) failed: %s",
          q, (unsigned long) len, compat_strerror(errno));
#endif /* DBUG */
      return NULL;
    }
  }
  return q;
}

void *
compat_protect_strdup(const char *s)
{
  size_t size;

  size = strlen(s) + 1;
  RUNTIME_ASSERT(size > 0 && size <= INT_MAX);
  return compat_protect_memdup(s, size);
}

time_t
compat_mono_time_gettimeofday(struct timeval *tv)
{
  static bool initialized;
  static struct timeval past;
  struct timeval now;
  int64_t d;

  gettimeofday(&now, NULL);
  if (!initialized) {
    initialized = true;
    past = now;
  }

  d = DIFFTIMEVAL(&now, &past);
  if (d >= 0) {
    past = now;
  } else {
#ifdef DBUG
    if (d < -100000) {
      DBUG("Clock jumped %luus backwards", (unsigned long) -d);
    }
#endif /* DBUG*/

    now = past; /* freeze time to restore space-time continuum */
    if (d < -60000000) {
#ifdef DBUG
      DBUG("Your clock is way too screwed, let's crash");
#endif /* DBUG*/
      abort();
    }
  }

  if (tv) {
    *tv = now;
  }  
  return now.tv_sec;
}

time_t
compat_mono_time_clock_gettime(struct timeval *tv)
{
#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
  static bool initialized;
  static struct timespec now, prev;
  struct timespec cur;
  long nd;

  if (!initialized) {
    initialized = true;
    if (
      -1 == clock_gettime(CLOCK_REALTIME, &now) || 
      -1 == clock_gettime(CLOCK_MONOTONIC, &prev)
    ) {
      return (time_t) -1;
    }
  }

  clock_gettime(CLOCK_MONOTONIC, &cur);
  now.tv_sec += cur.tv_sec - prev.tv_sec;
  nd = cur.tv_nsec - prev.tv_nsec; 
  if (nd > LONG_MAX - now.tv_nsec) {
    nd -= LONG_MAX - now.tv_nsec;
    now.tv_sec++;
  }
  now.tv_nsec += nd;
  prev = cur;

  if (tv) {
    tv->tv_sec = now.tv_sec;
    tv->tv_usec = now.tv_nsec / 1000;
  }
  return now.tv_sec;
#else /* !(HAVE_CLOCK_GETTIME && CLOCK_MONOTONIC) */
  (void) tv;
  errno = ENOSYS;
  return (time_t) -1;
#endif  /* HAVE_CLOCK_GETTIME && CLOCK_MONOTONIC */
}

time_t
compat_mono_time(struct timeval *tv)
{
  static bool initialized, use_gettimeofday;

  if (!initialized) {
    initialized = true;
    use_gettimeofday = (time_t) -1 == compat_mono_time_clock_gettime(NULL);
  }
  if (use_gettimeofday) {
    return compat_mono_time_gettimeofday(tv);
  } else {
    return compat_mono_time_clock_gettime(tv);
  }
}

int
compat_chroot(const char *dir)
{
  int fd = -1;
  struct stat st;

  RUNTIME_ASSERT(dir);
  RUNTIME_ASSERT(dir[0] == '/');

  if (!dir || '/' != dir[0]) {
    debug_msg("Invalid directory %s%s%s",
        dir ? "\"" : "",
        dir ? dir : "NULL",
        dir ? "\"" : "");
    return -1;
  }
  
  fd = open(dir, O_RDONLY | O_NOCTTY, 0);
  if (fd < 0) {
    debug_error("Cannot access directory \"%s\"", dir);
    return -1;
  }
  if (fstat(fd, &st)) {
    debug_error("Cannot fstat() directory \"%s\"", dir);
    return -1;
  }
  if (!(S_IFDIR & st.st_mode)) {
    debug_msg("This is not a directory \"%s\"", dir);
    return -1;
  }
  if (S_IWOTH & st.st_mode) {
    debug_msg("Directory \"%s\" is world-writeable!", dir);
    return -1;
  }
#ifdef HAVE_FCHROOT
  if (fchroot(fd)) {
    debug_error("fchroot(\"%s\") failed", dir);
    return -1;
  }
#else /* !HAVE_FCHROOT */
  if (fchdir(fd)) {
    debug_error("fchdir(\"%s\") failed\n", dir);
    return -1;
  }
  if (chroot(dir)) {
    debug_error("chroot(\"%s\") failed", dir);
    return -1;
  } else {
    struct stat st2;

    if (fstat(fd, &st2)) {
      debug_error("Cannot fstat() directory \"%s\"", dir);
      return -1;
    }
    if (0 != memcmp(&st.st_dev, &st2.st_dev, sizeof st.st_dev) ||
        0 != memcmp(&st.st_ino, &st2.st_ino, sizeof st.st_ino)
    ) {
      debug_msg("Directories don't match after chroot()!");
      return -1;
    }
  }
#endif /* HAVE_FCHROOT */
  if (close(fd)) {
    debug_error("close() failed");
    return -1;
  }
  
  return 0;
}

#ifdef RLIMIT_NPROC
int
compat_disable_fork(void)
{
  struct rlimit lim;
  pid_t pid;

  lim.rlim_cur = 0;
  lim.rlim_max = 0;
  if (setrlimit(RLIMIT_NPROC, &lim)) {
    debug_error("setrlimit() failed for RLIMIT_NPROC");
    return -1;
  }
  if (getrlimit(RLIMIT_NPROC, &lim)) {
    debug_error("getrlimit() failed for RLIMIT_NPROC");
    return -1;
  }
#if 0
  DBUG("RLIMIT_NPROC: current=%ld, max=%ld",
      (long) lim.rlim_cur, (long) lim.rlim_max);
#endif
  
  /* Check whether the limit can be raised */
  lim.rlim_cur = 1;
  lim.rlim_max = 1;
  if (setrlimit(RLIMIT_NPROC, &lim)) {
#if 0
    DBUG("setrlimit() failed for RLIMIT_NPROC: %s", compat_strerror(errno));
#endif
  } else {
#ifdef DBUG
    DBUG("setrlimit() allowed to raise the limit for RLIMIT_NPROC!");
#endif /* DBUG */
    /* The returned value might be wrong. Thus, use fork() to check
     * whether the limit is effective or not. */
  }
  
  /* Check whether the limit is effective */
  fflush(NULL);
  pid = fork();
  switch (pid) {
  case (pid_t) -1:
    /* Good, fork() failed as expected */
#if 0
    DBUG("fork() failed: %s", compat_strerror(errno));
#endif
    break;
  case 0:
    /* Whoops, fork succeeded?! */
    _exit(EXIT_FAILURE);
    break;
  default:
    /* This doesn't look like Kansas anymore... */
    debug_msg("fork() did still succeed!");
    return -1;
  }

  return 0;
}
#else
int
compat_disable_fork(void)
{
  /* Your system does not support disabling fork(). */
  return 0;
}
#endif /* RLIMIT_NPROC  */

int
compat_disable_coredumps(void)
{
  struct rlimit lim;

  lim.rlim_cur = 0;
  lim.rlim_max = 0;
  if (setrlimit(RLIMIT_CORE, &lim)) {
    debug_error("setrlimit() failed for RLIMIT_CORE");
    return -1;
  }
  if (getrlimit(RLIMIT_CORE, &lim)) {
    debug_error("getrlimit() failed for RLIMIT_CORE");
    return -1;
  }
#if 0
  DBUG("RLIMIT_CORE: current=%ld, max=%ld",
      (long) lim.rlim_cur, (long) lim.rlim_max);
#endif
  
  /* Check whether the limit can be raised */
  lim.rlim_cur = 1;
  lim.rlim_max = 1;
  setrlimit(RLIMIT_CORE, &lim);

  if (getrlimit(RLIMIT_CORE, &lim)) {
    debug_error("getrlimit() failed for RLIMIT_CORE");
  } else if (lim.rlim_cur > 0 || lim.rlim_max > 0) {
    debug_msg("setrlimit() allowed to raise the limit for RLIMIT_CORE!");
    return -1;
  }
  
  return 0;
}

int
compat_close_std_streams(void)
{
  if (!freopen(DEV_NULL, "r", stdin)) {
    debug_error("freopen() failed for stdin");
    return -1;
  }
  if (!freopen(DEV_NULL, "w", stdout)) {
    debug_error("freopen() failed for stdout");
    return -1;
  }
  if (!freopen(DEV_NULL, "w", stderr)) {
    debug_error("freopen() failed for stderr");
    return -1;
  }
  return 0;
}

/**
 * Daemonizes the current process.
 *
 * @param directory We will chdir() to this directory. A value of NULL
 *                  implies the root directory.
 */
int
compat_daemonize(const char *directory)
{
  pid_t pid;
  int i;

  if (!directory) {
    directory = "/";
  }

  for (i = 0; i < 2; i++) {
    if (SIG_ERR == set_signal(SIGCHLD, SIG_IGN)) {
      debug_error("set_signal(SIGCHLD, SIG_IGN) failed");
      return -1;
    }

    fflush(NULL);
    pid = fork();
    if ((pid_t) -1 == pid) {
      debug_error("fork() failed");
      return -1;
    }

    if (pid) {
      _exit(0);
      /* NOTREACHED */
      return -1;
    }
   
    /* Create a new session after the first fork() */
    if (0 == i && (pid_t) -1 == setsid()) {
      debug_error("setsid() failed");
      return -1;
    }

  }
   
  pid = getpid();
  if (setpgid(0, pid)) {
    debug_error("setpgid(0, %lu) failed", (unsigned long) pid);
    return -1;
  }
  
  if (chdir(directory)) {
    debug_error("chdir(\"%s\") failed", directory);
    return -1;
  }

  /* Make sure we don't create any files with an s- or x-bit set or
   * a world-writeable file */
  umask(umask(0) | S_IWOTH | S_IXUSR | S_IXGRP | S_IXOTH | S_ISUID | S_ISGID);

  if (compat_close_std_streams()) {
    return -1;
  }

  return 0;
}

/**
 * Allocates a page-aligned memory chunk.
 *
 * @param size The size in bytes to allocate; will be rounded to the pagesize.
 */
void *
compat_page_align(size_t size)
{
  size_t align = compat_getpagesize();
  void *p;

  size = round_size(align, size);

#if 0 && defined(HAVE_POSIX_MEMALIGN)
  if (posix_memalign(&p, align, size)) {
    debug_error("posix_memalign() failed");
    return NULL;
  }
#elif 0 && defined(HAVE_MEMALIGN)
  p = memalign(align, size);
  if (!p) {
    debug_error("memalign() failed");
    return NULL;
  }
#else
  {
    static int fd = -1, flags;

#if defined(MAP_ANON)
    flags = MAP_ANON;
#elif defined (MAP_ANONYMOUS)
    flags = MAP_ANONYMOUS
#else /* Neither MAP_ANON nor MAP_ANONYMOUS */
    flags = MAP_PRIVATE;
    if (-1 == fd) {
      fd = open("/dev/zero", O_RDWR, 0);
      if (-1 == fd) {
        debug_error("compat_page_align(): open() failed for /dev/zero");
        return NULL;
      }
    }
#endif	/* MAP_ANON */

    flags |= MAP_PRIVATE;
    p = mmap(0, size, PROT_READ | PROT_WRITE, flags, fd, 0);
    if (MAP_FAILED == p) {
      debug_error("mmap() failed");
      return NULL;
    }
  }
#endif	/* HAVE_POSIX_MEMALIGN || HAVE_MEMALIGN */

  if (0 != PTR2UINT(p) % align) {
    debug_msg("Aligned memory required");
    return NULL;
  }

  return p;
}

void
compat_page_free(void *p, size_t size)
{
  size_t align = compat_getpagesize();

  RUNTIME_ASSERT(0 == PTR2UINT(p) % align);

#if 0 && (defined(HAVE_POSIX_MEMALIGN) || defined(HAVE_MEMALIGN))
  (void) size;
  free(p);
#else
  munmap(p, size);
#endif	/* HAVE_POSIX_MEMALIGN || HAVE_MEMALIGN */
}

void
compat_setproctitle(const char *title)
#ifdef HAVE_LINUX_SETPROCTITLE
{
  /* The BSD version uses printf-style arguments, the Linux one accepts
   * only a string as argument. */
  setproctitle(buf);
}
#elif HAVE_SETPROCTITLE
{
  setproctitle("%s", title);
}
#else /* !HAVE_SETPROCTITLE */
{
    (void) title;
}
#endif /* HAVE_SET_PROCTITLE */

void *
compat_memmem(const void *data, size_t size,
  const void *pattern, size_t pattern_size)
{
  const char *p, *end;
  char pat0;
  size_t n;

  p = data;
  if (pattern_size > 0) {
    end = &p[size];
    pat0 = *(const char *) pattern;

    for (;;) {
      n = end - p;
      p = n < pattern_size ? NULL : memchr(p, n, pat0);
      if (!p || 0 == memcmp(p, pattern, pattern_size)) {
        break;
      }
      p++;
    }
  }
  return (void *) p;
}

/* vi: set ai et sts=2 sw=2 cindent: */
