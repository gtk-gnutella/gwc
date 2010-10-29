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

#include "acclog.h"

#include "append.h"
#include "oop.h"

typedef enum {
  ACCLOG_MAGIC = 0x18fac81a
} acclog_magic_t;

typedef struct {
  struct acclog vtable;
  acclog_magic_t magic;
  FILE *stream;
  time_t stamp;
  net_addr_t addr;
  int code;
  size_t size;
  char user_agent[1024];
  char referer[1024];
  char request[1024];
} acclog_private_t;

typedef union {
  acclog_t pub;
  acclog_private_t priv;
} acclog_union;

#define PRIV(obj) (&((acclog_union *)(obj))->priv)

ATTRIBUTE_GET(acclog, FILE *, stream)
  
ATTRIBUTE_SET(acclog, int, code)
ATTRIBUTE_SET(acclog, const net_addr_t, addr)
ATTRIBUTE_SET(acclog, time_t, stamp)
ATTRIBUTE_SET(acclog, size_t, size)

#define ACCLOG_STRING(name) \
static void \
acclog_set_ ## name (acclog_t *l, const char * name) \
{ \
  size_t size = sizeof PRIV(l)->name; \
  \
  RUNTIME_ASSERT(l != NULL); \
  RUNTIME_ASSERT(name != NULL); \
  (void) append_escaped_string(PRIV(l)->name, &size, name); \
}

ACCLOG_STRING(referer)
ACCLOG_STRING(request)
ACCLOG_STRING(user_agent)

static void
acclog_reset(acclog_t *la)
{
  acclog_private_t *l = PRIV(la);
  
  RUNTIME_ASSERT(l != NULL);

  l->code = 0;
  l->stamp = 0;
  l->addr = net_addr_unspecified;
  l->size = 0;
  l->referer[0] = '\0';
  l->user_agent[0] = '\0';
  l->request[0] = '\0';
}

static void
acclog_flush(acclog_t *la)
{
  acclog_private_t *l = PRIV(la);
  
  RUNTIME_ASSERT(l != NULL);
  RUNTIME_ASSERT(l->stream != NULL);

  fflush(l->stream);
}

static void
acclog_commit(acclog_t *la)
{
  char addr_buf[NET_ADDR_BUFLEN];
  char date_buf[NCSA_DATE_BUFLEN];
  char code[32];
  size_t size = sizeof code;
  acclog_private_t *l = PRIV(la);
  
  RUNTIME_ASSERT(l != NULL);
  RUNTIME_ASSERT(l->stream != NULL);

  if (l->code != 0) {
    char *p = code;
    
    p = append_uint(p, &size, l->code);
    RUNTIME_ASSERT(size > 0);
    *p = '\0';
  } else {
    append_string(code, &size, "-");
  }
  
  print_net_addr(addr_buf, sizeof addr_buf, l->addr);
  print_ncsa_date(date_buf, sizeof date_buf, l->stamp);
  fprintf(l->stream, "%s - - [%s] \"%s\" %s %lu %s%s%s %s%s%s\n",
      addr_buf,
      date_buf,
      l->request,
      code,
      (unsigned long) l->size,
      l->referer[0] != '\0' ? "\"" : "-",
      l->referer,
      l->referer[0] != '\0' ? "\"" : "",
      l->user_agent[0] != '\0' ? "\"" : "-",
      l->user_agent,
      l->user_agent[0] != '\0' ? "\"" : "");
  la->reset(la);
}

static void
acclog_destruct(acclog_t *la)
{
  acclog_private_t *l = PRIV(la);
  
  RUNTIME_ASSERT(l != NULL);
  memset(l, 0, sizeof *l);
  DO_FREE(l);
}

static const struct acclog acclog_vtable = {
  &acclog_commit,
  &acclog_flush,
  &acclog_reset,
  &acclog_get_stream,
  &acclog_set_code,
  &acclog_set_addr,
  &acclog_set_referer,
  &acclog_set_request,
  &acclog_set_size,
  &acclog_set_stamp,
  &acclog_set_user_agent,
  &acclog_destruct
};

acclog_t *
acclog_new(FILE *f)
{
  acclog_private_t *al;

  RUNTIME_ASSERT(f != NULL);
  al = calloc(1, sizeof *al);
  if (al) {
    al->vtable = acclog_vtable;
    al->magic = ACCLOG_MAGIC;
    al->stream = f; 
  }
  return (acclog_t *) al;
}

/* vi: set ai et sts=2 sw=2 cindent: */
