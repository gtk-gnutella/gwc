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

#ifndef ACCLOG_HEADER_FILE
#define ACCLOG_HEADER_FILE

#include "common.h"
#include "net_addr.h"

#define ACCLOG_SET(al, name, x) \
do { \
  acclog_t *al_ = (al); \
  if (al_) { \
    al_->set_ ## name (al_, x); \
  } \
} while (0)

#define ACCLOG_OP(al, op) \
do { \
  acclog_t *al_ = (al); \
  if (al_) { \
    al_-> op (al_); \
  } \
} while (0)

#define ACCLOG_COMMIT(al) ACCLOG_OP(al, commit)
#define ACCLOG_FLUSH(al) ACCLOG_OP(al, flush)
#define ACCLOG_RESET(al) ACCLOG_OP(al, reset)

typedef struct acclog acclog_t;

acclog_t * acclog_new(FILE *f);

struct acclog {
  void    (* commit) (acclog_t *) NON_NULL;
  void    (* flush) (acclog_t *) NON_NULL;
  void    (* reset) (acclog_t *) NON_NULL;
  FILE *  (* get_stream) (acclog_t *) NON_NULL;
  void    (* set_code) (acclog_t *, int) NON_NULL;
  void    (* set_addr) (acclog_t *, const net_addr_t) NON_NULL;
  void    (* set_referer) (acclog_t *, const char *) NON_NULL;
  void    (* set_request) (acclog_t *, const char *) NON_NULL;
  void    (* set_size) (acclog_t *, size_t) NON_NULL;
  void    (* set_stamp) (acclog_t *, time_t) NON_NULL;
  void    (* set_user_agent) (acclog_t *, const char *) NON_NULL;
  void    (* set_destruct) (acclog_t *) NON_NULL;
};


/* vi: set ai et sts=2 sw=2 cindent: */
#endif /* ACCLOG_HEADER_FILE */
