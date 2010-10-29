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

#ifndef GGEP_H_HEADERFILE
#define GGEP_H_HEADERFILE

#include "common.h"

#define GGEP_F_COBS     0x40
#define GGEP_F_DEFLATE  0x20

#define GGEP_ID_BUFLEN  16  /* Maximum necessary buffersize to hold a GGEP ID */

typedef enum {
  GGEP_ID_INVALID = 0, /* Not a valid ID, used for errors */
  
  GGEP_ID_LIME_XML, /* "<" */
  GGEP_ID_ALT,
  GGEP_ID_AUTH,
  GGEP_ID_BH,
  GGEP_ID_CT,
  GGEP_ID_DU,
  GGEP_ID_GTKG_IPP6,
  GGEP_ID_GTKG_IPV6,
  GGEP_ID_GTKG_TLS,
  GGEP_ID_GUE,
  GGEP_ID_H,
  GGEP_ID_HNAME,
  GGEP_ID_IP,
  GGEP_ID_IPP,
  GGEP_ID_LOC,
  GGEP_ID_M,
  GGEP_ID_MCAST,
  GGEP_ID_NP,
  GGEP_ID_PHC,
  GGEP_ID_PUSH,
  GGEP_ID_QK,
  GGEP_ID_SCP,
  GGEP_ID_SWAP_q,
  GGEP_ID_UDPHC,
  GGEP_ID_UDPNFW,
  GGEP_ID_UP,
  GGEP_ID_VC,

  NUM_GGEP_ID
} ggep_id_t;

typedef enum {
  GGEP_T_MAGIC = 0x0e983373
} ggep_magic_t;

struct ggep {
  ggep_magic_t magic;
  char *data;    /* Raw memory chunk for decoding or encoding */
  char *last;    /* Start position of the previous extension block */
  char *p_data_len;  /* Position of the GGEP length field */
  char *p;       /* Current position in ``data'' */
  char *open;    /* Position in ``data'' when ggep_open() was used */
  size_t size;      /* Size of the memory chunk data points to */
  size_t data_len;  /* Payload length of the current extension block */
};

typedef struct ggep ggep_t;

ggep_t * ggep_init(ggep_t *gtx, char *data, size_t size);
size_t ggep_data_min_left(ggep_t *gtx, ggep_id_t id);
int ggep_pack(ggep_t *gtx, ggep_id_t id, int flags, const char *data,
    size_t data_len);
char * ggep_open(ggep_t *gtx, ggep_id_t id, int flags, size_t data_len);
void ggep_write(ggep_t *gtx, const char *data, size_t data_len);
void ggep_close(ggep_t *gtx);
size_t ggep_end(ggep_t *gtx);
ggep_id_t ggep_map_id_name(const char *name, size_t *len);
ggep_t * ggep_decode(ggep_t *gtx, const char *data, size_t len);
int ggep_next(ggep_t *gtx, char *id);
size_t ggep_data(ggep_t *gtx, char **data_ptr, char *buf, size_t bufsize);

#endif /* GGEP_H_HEADERFILE */
/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
