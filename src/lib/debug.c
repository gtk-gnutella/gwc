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

#include "debug.h"

static void
vnote(const char *file, int line, note_level_t level, const char *fmt,
    va_list ap)
{
  int saved_errno = errno;
 
  note_prefix(file, line, level);
  vfprintf(stderr, fmt, ap);
  fputs("\n", stderr);
#if 0
  fflush(stderr);
#endif
  if (level == NOTE_FATAL) {
    fatality("FATALITY");
  }
  
  errno = saved_errno;
}

void
printerr(const char *fmt, ...)
{
  va_list ap;
  int saved_errno = errno;

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputs("\n", stderr);
#if 0
  fflush(stderr);
#endif
  errno = saved_errno;
}

#define PRINTERR(suffix, level)             \
void                                        \
printerr_ ## suffix (const char *fmt, ...)  \
{                                           \
  va_list ap;                               \
  int saved_errno = errno;                  \
                                            \
  va_start(ap, fmt);                        \
  vnote(NULL, 0, level, fmt, ap);           \
  va_end(ap);                               \
  errno = saved_errno;                      \
}

PRINTERR(crit, NOTE_CRIT)
PRINTERR(warn, NOTE_WARN)
PRINTERR(info, NOTE_INFO)
PRINTERR(verb, NOTE_VERB)
PRINTERR(dbug, NOTE_DBUG)
  
void
fatality(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputs("\n", stderr);
  fflush(stderr);
  exit(EXIT_FAILURE);
}

void
note_prefix(const char *file, int line, note_level_t level)
{
  char prefix[] = "X ";

  prefix[0] = (char) level;
  if (file)
    fprintf(stderr, "%s%s(%d): ", prefix, file, line);
  else
    fputs(prefix, stderr);
}

void
note(const char *file, int line, note_level_t level, const char *fmt, ...)
{
  va_list ap;
  int saved_errno = errno;

  va_start(ap, fmt);
  vnote(file, line, level, fmt, ap);
  va_end(ap);
  
  errno = saved_errno;
}

void NO_RETURN NON_NULL REGPARM(1)
debug_assert(const struct assert_point *ap)
{
  const char *sv[] = {
    "\nAssertion failure at ",
    ap->file, ":",
    ap->line, " (",
    ap->func, "): ",
    ap->expr, "\n"
  };
  struct iovec iov[ARRAY_LEN(sv)], *iov_ptr = iov;
  unsigned i;

  for (i = 0; i < ARRAY_LEN(iov); i++) {
    *iov_ptr++ = iov_from_string(sv[i]);
  }

  (void) writev(STDERR_FILENO, iov, ARRAY_LEN(iov));
  abort();
}

/* vi: set ai et sts=2 sw=2 cindent: */
