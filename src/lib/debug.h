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

#ifndef DEBUG_HEADER_FILE
#define DEBUG_HEADER_FILE

#include "common.h"

typedef enum {
  NOTE_FATAL  = 'F',
  NOTE_CRIT   = 'C',
  NOTE_WARN   = 'W',
  NOTE_INFO   = 'I',
  NOTE_VERB   = 'V',
  NOTE_DBUG   = 'D',

  NOTE_NUM
} note_level_t;


void note(const char *file, int line, note_level_t l, const char *fmt, ...)
  CHECK_FMT(4, 5);
void fatality(const char *fmt, ...) CHECK_FMT(1, 2);
void printerr_crit(const char *fmt, ...) CHECK_FMT(1, 2);
void printerr_warn(const char *fmt, ...) CHECK_FMT(1, 2);
void printerr_info(const char *fmt, ...) CHECK_FMT(1, 2);
void printerr_verb(const char *fmt, ...) CHECK_FMT(1, 2);
void printerr_dbug(const char *fmt, ...) CHECK_FMT(1, 2);
void note_prefix(const char *file, int line, note_level_t level);

#if defined(HAVE_C99_VARIADIC_MACROS)
#define FATAL(...) note(__FILE__, __LINE__, NOTE_FATAL, ## __VA_ARGS__)
#define CRIT(...)  note(__FILE__, __LINE__, NOTE_CRIT, ## __VA_ARGS__)
#define WARN(...)  note(__FILE__, __LINE__, NOTE_WARN, ## __VA_ARGS__)
#define INFO(...)  note(__FILE__, __LINE__, NOTE_INFO, ## __VA_ARGS__)
#define VERB(...)  note(__FILE__, __LINE__, NOTE_VERB, ## __VA_ARGS__)
#define DBUG(...)  note(__FILE__, __LINE__, NOTE_DBUG, ## __VA_ARGS__)
#else
#define FATAL fatality
#define CRIT  printerr_crit
#define WARN  printerr_warn
#define INFO  printerr_info
#define VERB  printerr_verb
#define DBUG  printerr_dbug
#endif

struct assert_point {
  const char * const expr;
  const char * const file;
  const char * const line;
  const char * const func;
};

void debug_assert(const struct assert_point *ap) NO_RETURN NON_NULL REGPARM(1);

/* vi: set ai et sts=2 sw=2 cindent: */
#endif /* DEBUG_HEADER_FILE */
