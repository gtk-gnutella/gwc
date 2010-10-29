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

#include "ggep.h"
#include "cobs.h"

#include "append.h"

#define GGEP_MAGIC   ((unsigned char) 0xC3)

#define GGEP_F_LAST     ((unsigned char) 0x80)
#define GGEP_F_RESERVED ((unsigned char) 0x10)

#define GGEP_LEN_MASK   ((unsigned char) 0xC0)
#define GGEP_LEN_MORE   ((unsigned char) 0x80)
#define GGEP_LEN_LAST   ((unsigned char) 0x40)

/* Maximum payload size of a single GGEP block */ 
#define GGEP_LEN_MAX    ((1U << 18) - 1)

/* Minimum size of a complete GGEP packet */ 
#define GGEP_SIZE_MIN   5

/* Minimum payload length at which deflate is attempted.
 * The overhead of deflate is 12 bytes + 0.1% of the payload size */ 
#define GGEP_DEFLATE_THRESHOLD  20

/**
 * @return the amount of bytes left in the data buffer of the GGEP context.
 */
static inline size_t
ggep_consumed(const ggep_t *gtx)
{
  return (size_t) (gtx->p - gtx->data);
}

static inline bool
ggep_is_magic(const char *p)
{
  return GGEP_MAGIC == *(const unsigned char *) p;
}

static char *
ggep_encode_length(char *dst, size_t *size, size_t len)
{
  char *p = dst;
  uint8_t q[3];
  int i;
  
  RUNTIME_ASSERT(dst != NULL);
  RUNTIME_ASSERT(size != NULL);
  RUNTIME_ASSERT(*size <= INT_MAX);
  RUNTIME_ASSERT(*size >= 3);
  RUNTIME_ASSERT(len <= INT_MAX);
  RUNTIME_ASSERT(len < (1 << 18));

  for (i = 0; i < 3; i++) {
    q[i] = len & 0x3f;
    len >>= 6;
    if (0 == len)
      break;
  }
  RUNTIME_ASSERT(i < 3);
  
  do {
    *p++ = q[i] | (i == 0 ? GGEP_LEN_LAST : GGEP_LEN_MORE);
  } while (0 != i--);

  *size -= p - dst;
  RUNTIME_ASSERT(*size <= INT_MAX);
  return p;
}

/**
 * Sets or changes the length of the current GGEP block and adjusts
 * gtx->open. If the newly encoded length field is longer than the old one
 * and there was already valid payload, the payload has to be rewritten or
 * corrected.
 */
static void
ggep_set_data_length(ggep_t *gtx, size_t data_len)
{
  size_t left;
  
  RUNTIME_ASSERT(gtx);
  RUNTIME_ASSERT(GGEP_T_MAGIC == gtx->magic);
  RUNTIME_ASSERT(data_len <= INT_MAX);
  RUNTIME_ASSERT(data_len <= GGEP_LEN_MAX);
  RUNTIME_ASSERT(gtx->p_data_len != NULL);
  
  left = gtx->size - (gtx->p_data_len - gtx->data);
  RUNTIME_ASSERT(data_len <= left);
  
  gtx->p = ggep_encode_length(gtx->p_data_len, &left, data_len);
  gtx->open = gtx->p;
  gtx->data_len = data_len;
}

/**
 * Initializes a GGEP context to decode the GGEP packet. Must be called
 * before ggep_next() can be used with the context.
 *
 * @param gtx   NULL or an allocated GGEP context.
 * @param data  a GGEP packet. If the first byte is not a GGEP magic, NULL
 *              is returned.
 * @param len   The length of ``data'' buffer. If len is smaller than the
 *              minimum size of a GGEP packet, NULL is returned.
 * @return      On success the a newly allocated GGEP context is returned if
 *              ``gtx'' was NULL or ``gtx'' if it was not NULL. On failure,
 *              NULL is returned.
 */
ggep_t *
ggep_decode(ggep_t *gtx, const char *data, size_t len)
{
  RUNTIME_ASSERT(data != NULL);
  if (len < GGEP_SIZE_MIN) {
    /* Too small for GGEP */
    return NULL;
  }
  
  gtx = ggep_init(gtx, (char *) data, len); /* override const */
  if (gtx) {
    if (!ggep_is_magic(gtx->data)) {
      /* No GGEP magic */
      return NULL;
    }
    gtx->last = NULL;
    gtx->p = &gtx->data[1];
  }
  return gtx;
}

/**
 * Jumps to next available GGEP block.
 *
 * @param   gtx a GGEP context initialized by ggep_decode().
 * @param   id must point to a buffer of 16 or more bytes. On success, the
 *          buffer contains the GGEP ID as an NUL-terminated string.
 *
 * @return  -1 on failure, don't call ggep_next() again after this.
 *          0 if the end of the GGEP packet was reached.
 *          1 if a GGEP block is ready to read.
 */
int
ggep_next(ggep_t *gtx, char *id)
{
  size_t i, id_len, left;
  uint8_t flags, ch;
 
  RUNTIME_ASSERT(gtx != NULL);
  RUNTIME_ASSERT(id != NULL);
  RUNTIME_ASSERT(gtx->magic == GGEP_T_MAGIC);
  RUNTIME_ASSERT(gtx->size >= GGEP_SIZE_MIN && gtx->size <= INT_MAX);
  RUNTIME_ASSERT(gtx->data != NULL);
  RUNTIME_ASSERT(gtx->p != NULL);
  RUNTIME_ASSERT(gtx->p != gtx->data);
  RUNTIME_ASSERT(gtx->data_len <= GGEP_LEN_MAX);

  *id = '\0';
    
  if (gtx->last && 0 != (*gtx->last & GGEP_F_LAST)) {
    if (ggep_consumed(gtx) < gtx->size && ggep_is_magic(gtx->p)) {
      gtx->p++;
      /* Found another GGEP block after the last */
    } else {
      gtx->p = NULL;  /* Mark GGEP block as done */
      return 0;
    }
  }

  RUNTIME_ASSERT(gtx->size >= ggep_consumed(gtx));
  left = gtx->size - ggep_consumed(gtx);
  RUNTIME_ASSERT(left < gtx->size);
  
  if (left < 3) {
    if (ggep_consumed(gtx) && left != 0) {
      /* Too short for GGEP */
    }
    gtx->p = NULL;  /* Mark GGEP block as done */
    return -1;
  }

  gtx->last = gtx->p++;
  flags = *gtx->last;
  RUNTIME_ASSERT(left >= 1);
  left--;
  
  id_len = flags & 0x0f;
  if (0 == id_len) {
    /* GGEP ID Len is zero */
    gtx->p = NULL;  /* Mark GGEP block as done */
    return -1;
  }
  
  if (left < id_len + 1) {
    /* Too short for GGEP ID Len */
    gtx->p = NULL;  /* Mark GGEP block as done */
    return -1;
  }
  RUNTIME_ASSERT(left >= id_len);
  left -= id_len;
  
  for (i = 0; i < id_len; i++) {
    ch = *gtx->p++;

    if (ch == '\0') {
      /* GGEP ID contains NUL */
      gtx->p = NULL;  /* Mark GGEP block as done */
      return -1;
    }

    id[i] = ch;
  }
  id[i] = '\0';
#if 0
  DBUG("GGEP ID: \"%s\"", id);
#endif

  gtx->data_len = 0;
  i = 0;
  ch = 0;
  RUNTIME_ASSERT(left > 0);
  while (left-- > 0) {
    int h;

    ch = *gtx->p++;
    h = ch & GGEP_LEN_MASK;
    gtx->data_len = (gtx->data_len << 6) | (ch & 0x3f);
    switch (h) {
    case 0x00:
    case GGEP_LEN_MASK:
      /* Invalid length encoding */
      gtx->p = NULL;  /* Mark GGEP block as done */
      return -1;
    }
    if (h == GGEP_LEN_LAST)
      break;
    if (++i == 3)
      break;
  }
  RUNTIME_ASSERT(left <= GGEP_LEN_MAX);

  if ((ch & GGEP_LEN_MASK) != GGEP_LEN_LAST) {
    /* GGEP length truncated */
    gtx->p = NULL;  /* Mark GGEP block as done */
    return -1;
  }
#if 0
  DBUG("GGEP block length: %d", gtx->data_len);
#endif
  if (flags & GGEP_F_COBS) {
    /* COBS encoded */
  }
  if (flags & GGEP_F_RESERVED) {
    /* reserved bit is set(?!) */
  } 
  if (flags & GGEP_F_LAST) {
#if 0
    /* Last extension */
#endif
  } else if (0 == left) {
    /* GGEP_F_LAST not set but end-of-packet reached */
  }
  if (left < gtx->data_len) {
    /* GGEP payload truncated */
    gtx->p = NULL;  /* Mark GGEP block as done */
    return -1;
  }
 
  gtx->open = gtx->p;
  gtx->p = &gtx->open[gtx->data_len];
  return 1;
}

/**
 * Retrieves the payload from a GGEP block. Must only be called after an
 * successful ggep_next().
 *
 * @param gtx   a GGEP context initialized with ggep_decode() after ggep_next()
 *              returned 1.
 * @param data_ptr  On success, the pointer will be initialized to point to the
 *              payload of the GGEP block. It will either point directly to
 *              the data in the GGEP block or to the supplied ``buf'' which
 *              holds the decompressed data.
 *              The payload is inflated if it was deflate compressed. COBS
 *              encoded data is not supported.
 * @param buf   A buffer to hold the decompressed payload of the GGEP block.
 * @param buf_size The size in bytes of ``buf''.
 *
 * @return      -1 on failure, otherwise the payload length of the current
 *              GGEP block. Note that a payload of 0 bytes is completely valid.
 */
size_t
ggep_data(ggep_t *gtx, char **data_ptr, char *buf, size_t buf_size)
{
  char *dummy_ptr;
  size_t src_len;

  RUNTIME_ASSERT(gtx != NULL);
  RUNTIME_ASSERT(buf != NULL);
  RUNTIME_ASSERT(buf_size > 0 && buf_size <= INT_MAX);
  RUNTIME_ASSERT(gtx->magic == GGEP_T_MAGIC);
  RUNTIME_ASSERT(gtx->size >= GGEP_SIZE_MIN && gtx->size <= INT_MAX);
  RUNTIME_ASSERT(gtx->data != NULL);
  RUNTIME_ASSERT(gtx->last != NULL);
  RUNTIME_ASSERT(gtx->p != NULL);
  RUNTIME_ASSERT(gtx->p != gtx->data);
  RUNTIME_ASSERT(gtx->open != NULL);
  RUNTIME_ASSERT(gtx->data_len <= GGEP_LEN_MAX);
  RUNTIME_ASSERT(gtx->size >= ggep_consumed(gtx));

  if (!data_ptr) {
    data_ptr = &dummy_ptr;
  }

  if (GGEP_F_COBS & *gtx->last) {
    src_len = cobs_decode(gtx->open, gtx->open, gtx->data_len);
    RUNTIME_ASSERT(src_len <= gtx->data_len);
    *data_ptr = gtx->open;
  } else {
    src_len = gtx->data_len;
  }
  
  if (GGEP_F_DEFLATE & *gtx->last) {
#ifndef HAVE_ZLIB_SUPPORT
    *data_ptr = NULL;
    return -1;
#else
    static z_stream zs_inflate;
    static z_streamp zsp_inflate;
    size_t dlen;
    int ret;

    zs_inflate.next_in = (void *) gtx->open;
    zs_inflate.avail_in = src_len;
    zs_inflate.next_out = (void *) buf;
    zs_inflate.avail_out = buf_size;
    if (!zsp_inflate) {
      zs_inflate.zalloc = NULL;
      zs_inflate.zfree = NULL;
      zs_inflate.opaque = NULL;
      zsp_inflate = &zs_inflate;
      ret = inflateInit(zsp_inflate);
    } else {
      ret = inflateReset(zsp_inflate);
    }
    switch (ret) {
    case Z_OK:
      break;
    case Z_MEM_ERROR:
    case Z_VERSION_ERROR:
    default:
#if 0
      WARN("inflateInit() failed: %s", 
        zs_inflate.msg ? zs_inflate.msg : "Unknown error");
#endif
      *data_ptr = NULL;
      return -1;
    }
         
    do {
      ret = inflate(zsp_inflate, Z_FINISH);
      if (Z_OK == ret && 0 == zs_inflate.avail_out) {
          ret = Z_BUF_ERROR;
          break;
      }
    } while (Z_OK == ret);
      
    switch (ret) {
    case Z_STREAM_END:
      dlen = zs_inflate.total_out;
      break;
    case Z_OK:
      RUNTIME_ASSERT(0);
    case Z_BUF_ERROR:
    case Z_DATA_ERROR:
    case Z_MEM_ERROR:
    case Z_NEED_DICT:
    case Z_STREAM_ERROR:
    default:
#if 0
      WARN("inflate() failed: %s", 
        zs_inflate.msg ? zs_inflate.msg : "Unknown error");
#endif
      dlen = (size_t) -1;
    }
  
    ret = inflateReset(zsp_inflate);
    switch (ret) {
    case Z_OK:
      break;
    case Z_STREAM_ERROR:
    default:
#if 0
      WARN("inflateReset() failed: %s", 
        zs_inflate.msg ? zs_inflate.msg : "Unknown error");
#endif
      ;
    }

    *data_ptr = buf;
    return dlen;
#endif /* !HAVE_ZLIB_SUPPORT */
  } else {
    *data_ptr = gtx->open;
    return src_len;
  }
}

ggep_t *
ggep_init(ggep_t *gtx, char *data, size_t size)
{
  RUNTIME_ASSERT(data != NULL);
  RUNTIME_ASSERT(size >= GGEP_SIZE_MIN && size <= INT_MAX);
  
  if (!gtx) {
    gtx = calloc(1, sizeof *gtx);
  }

  if (gtx) {
    gtx->magic = GGEP_T_MAGIC;
    gtx->data = data;
    gtx->p = gtx->data;
    gtx->last = NULL;
    gtx->open = NULL;
    gtx->size = size;
    gtx->data_len = 0;
  }

  return gtx;
}

static const struct {
  const char *name;
  uint8_t id;
  uint8_t len;
} ggep_ids[] = {
#define GGEP_ID_(name, id) { name, id, ARRAY_LEN(name) - 1 }
#define GGEP_ID(x) GGEP_ID_(#x, GGEP_ID_ ## x)
#define GGEP_VENDOR_ID(v, x) GGEP_ID_(#v "." #x, GGEP_ID_ ## v ## _ ## x)
  
  { "",  GGEP_ID_INVALID,  1 },  /* GGEP_ID_INVALID */
  { "<", GGEP_ID_LIME_XML, 1 },  /* GGEP_ID_LIME_XML */
  GGEP_ID(ALT),
  GGEP_ID(AUTH),
  GGEP_ID(BH),
  GGEP_ID(CT),
  GGEP_ID(DU),
  GGEP_VENDOR_ID(GTKG, IPP6),
  GGEP_VENDOR_ID(GTKG, IPV6),
  GGEP_VENDOR_ID(GTKG, TLS),
  GGEP_ID(GUE),
  GGEP_ID(H),
  GGEP_ID(HNAME),
  GGEP_ID(IP),
  GGEP_ID(IPP),
  GGEP_ID(LOC),
  GGEP_ID(M),
  GGEP_ID(MCAST),
  GGEP_ID(NP),
  GGEP_ID(PHC),
  GGEP_ID(PUSH),
  GGEP_ID(QK),
  GGEP_ID(SCP),
  GGEP_VENDOR_ID(SWAP, q),
  GGEP_ID(UDPHC),
  GGEP_ID(UDPNFW),
  GGEP_ID(UP),
  GGEP_ID(VC),
  
#undef GGEP_ID
};

ggep_id_t
ggep_map_id_name(const char *name, size_t *len)
{
  size_t i;

  STATIC_ASSERT(ARRAY_LEN(ggep_ids) == NUM_GGEP_ID);
  
  for (i = 0; i < ARRAY_LEN(ggep_ids); i++) {
    RUNTIME_ASSERT(i == ggep_ids[i].id);
    if (!strcmp(name, ggep_ids[i].name)) {
      if (len)
        *len = ggep_ids[i].len;
      return i;
    }
  }

  if (len)
    *len = 0;
  return GGEP_ID_INVALID;
}

const char *
ggep_id_name(ggep_id_t id)
{
  RUNTIME_ASSERT((int) id >= 0);
  RUNTIME_ASSERT(id < NUM_GGEP_ID);
  return ggep_ids[id].name;
}

size_t
ggep_id_len(ggep_id_t id)
{
  size_t len;
  
  RUNTIME_ASSERT((int) id >= 0);
  RUNTIME_ASSERT(id < NUM_GGEP_ID);
  len = ggep_ids[id].len;
  RUNTIME_ASSERT(len > 0 && len < GGEP_ID_BUFLEN);
  return len;
}

int
ggep_pack(ggep_t *gtx, ggep_id_t id, int flags,
    const char *data, size_t data_len)
{
  char *p;
  
  RUNTIME_ASSERT(gtx != NULL);
  RUNTIME_ASSERT(flags == (flags & (GGEP_F_DEFLATE | GGEP_F_COBS)));
  RUNTIME_ASSERT(gtx->magic == GGEP_T_MAGIC);
  RUNTIME_ASSERT((data != NULL) ^ (0 == data_len));

  p = ggep_open(gtx, id, flags, data_len);
  if (!p)
    return -1;

  if (data_len > 0)
    ggep_write(gtx, data, data_len);

  RUNTIME_ASSERT(gtx->p == &p[data_len]);
  ggep_close(gtx);

  return 0;
}

size_t
ggep_end(ggep_t *gtx)
{
  size_t len;
  
  RUNTIME_ASSERT(gtx != NULL);
  RUNTIME_ASSERT(gtx->magic == GGEP_T_MAGIC);
  RUNTIME_ASSERT(gtx->data != NULL);
  RUNTIME_ASSERT((gtx->p != gtx->data) ^ (gtx->last == NULL));
  RUNTIME_ASSERT((gtx->last == 0) || gtx->size >= GGEP_SIZE_MIN);
  RUNTIME_ASSERT(gtx->size <= INT_MAX);
  RUNTIME_ASSERT(!gtx->open);

  if (gtx->last != NULL) {
    RUNTIME_ASSERT(ggep_is_magic(gtx->data));
    RUNTIME_ASSERT(0 != (*gtx->last & 0x0f));
    RUNTIME_ASSERT(0 != (*gtx->last & GGEP_F_LAST));
  }

  len = ggep_consumed(gtx);
  RUNTIME_ASSERT(len == 0 || (len >= GGEP_SIZE_MIN && len <= gtx->size));
  return len; 
}

size_t
ggep_data_min_left(ggep_t *gtx, ggep_id_t id)
{
  size_t used, left, oh, id_len;
  
  RUNTIME_ASSERT(gtx != NULL);
  RUNTIME_ASSERT(gtx->magic == GGEP_T_MAGIC);
  RUNTIME_ASSERT(gtx->data != NULL);

  used = ggep_consumed(gtx);
  RUNTIME_ASSERT((0 != used) ^ (gtx->last == NULL));

  id_len = ggep_id_len(id);
  RUNTIME_ASSERT(id_len > 0 && id_len < GGEP_ID_BUFLEN);
  left = gtx->size - used;
  oh = used ? 0 : 1; /* magic (1) */
  oh += 1 + id_len + 3; /* flags (1) + ID (1-15) + length (1-3) */
      
  return left > oh ? left - oh : 0;
}

char *
ggep_open(ggep_t *gtx, ggep_id_t id, int flags, size_t data_len)
{
  char *p;
  size_t left;
  size_t id_len, len_len, block_len;
  const char *id_name;
  
  RUNTIME_ASSERT(gtx != NULL);
  RUNTIME_ASSERT(flags == (flags & (GGEP_F_DEFLATE | GGEP_F_COBS)));
  RUNTIME_ASSERT(gtx->magic == GGEP_T_MAGIC);
  RUNTIME_ASSERT(gtx->size >= GGEP_SIZE_MIN && gtx->size <= INT_MAX);
  RUNTIME_ASSERT(!gtx->open);
  
  RUNTIME_ASSERT(id > 0 && id < NUM_GGEP_ID);
  RUNTIME_ASSERT(data_len <= INT_MAX);
  RUNTIME_ASSERT(data_len <= GGEP_LEN_MAX);

  id_name = ggep_id_name(id);
  RUNTIME_ASSERT(id_name != NULL);
  id_len = ggep_id_len(id);
  RUNTIME_ASSERT(id_len > 0 && id_len < GGEP_ID_BUFLEN);
  
  len_len = 1 + (0 != (data_len >> 6)) + (0 != (data_len >> 12));
  RUNTIME_ASSERT(0 == data_len >> 18);
  
  left = gtx->size - ggep_consumed(gtx);
  RUNTIME_ASSERT(left <= gtx->size);
  block_len = 1 + id_len + len_len + data_len + !gtx->last;
  if (left < block_len)
    return NULL;

  if (data_len < GGEP_DEFLATE_THRESHOLD)
    flags &= ~GGEP_F_DEFLATE;

#ifndef HAVE_ZLIB_SUPPORT
   flags &= ~GGEP_F_DEFLATE;
#endif
  
   
  p = gtx->p;
  if (!gtx->last) {
    RUNTIME_ASSERT(NULL == gtx->last);
    p = append_char(p, &left, GGEP_MAGIC); /* GGEP magic */
  } else {
    RUNTIME_ASSERT(NULL != gtx->last);
  }

  if (gtx->last) {
    RUNTIME_ASSERT(0 != (*gtx->last & GGEP_F_LAST));
    *gtx->last &= ~GGEP_F_LAST;
  }
  gtx->last = p;
    
  flags |= GGEP_F_LAST | id_len;
  p = append_char(p, &left, flags);     /* GGEP flags */
  p = append_chars(p, &left, id_name, id_len);  /* GGEP ID */

  gtx->p_data_len = p;
  ggep_set_data_length(gtx, data_len);
  
  return gtx->p;
}

void
ggep_write(ggep_t *gtx, const char *data, size_t data_len)
{
  size_t left;

  RUNTIME_ASSERT(gtx != NULL);
  RUNTIME_ASSERT(gtx->magic == GGEP_T_MAGIC);
  RUNTIME_ASSERT(gtx->open != NULL);
  RUNTIME_ASSERT(data != NULL);

  left = gtx->size - ggep_consumed(gtx); 
  RUNTIME_ASSERT(left >= data_len);
  gtx->p = append_chars(gtx->p, &left, data, data_len);
}

void
ggep_close(ggep_t *gtx)
{
#ifdef HAVE_ZLIB_SUPPORT  
  static z_stream zs_deflate;
  static z_streamp zsp_deflate;
#endif /* HAVE_ZLIB_SUPPORT */
  bool use_deflate;
  
  RUNTIME_ASSERT(gtx != NULL);
  RUNTIME_ASSERT(gtx->magic == GGEP_T_MAGIC);
  RUNTIME_ASSERT(gtx->size >= GGEP_SIZE_MIN && gtx->size <= INT_MAX);
  RUNTIME_ASSERT(gtx->open != NULL);
  RUNTIME_ASSERT(gtx->last != NULL);
  RUNTIME_ASSERT(0 != (*gtx->last & GGEP_F_LAST));
  RUNTIME_ASSERT(gtx->data_len == (size_t) (gtx->p - gtx->open));

#ifdef HAVE_ZLIB_SUPPORT  
  use_deflate = *gtx->last & GGEP_F_DEFLATE;
  if (use_deflate) {
    int ret;

    if (!zsp_deflate) {
      zs_deflate.zalloc = NULL;
      zs_deflate.zfree = NULL;
      zs_deflate.opaque = NULL;
      zsp_deflate = &zs_deflate;
      ret = deflateInit(zsp_deflate, Z_BEST_COMPRESSION);
    } else {
      ret = deflateReset(zsp_deflate);
    }
    switch (ret) {
    case Z_OK:
      break;
    case Z_STREAM_ERROR:
    case Z_VERSION_ERROR:
    default:
      use_deflate = false; 
#if 0
      WARN("deflateInit() failed: %s", 
        zs_deflate.msg ? zs_deflate.msg : "Unknown error");
#endif
    }
  }
    
  if (use_deflate) {
    int ret;
    char buf[4096];
    
    zs_deflate.next_in = (void *) gtx->open;
    zs_deflate.next_out = (void *) buf;
    zs_deflate.avail_in = gtx->data_len;
    zs_deflate.avail_out = sizeof buf;

    for (;;) {
      ret = deflate(zsp_deflate, Z_FINISH);
      if (Z_OK == ret)
        continue;
      
      if (Z_STREAM_END == ret) {
        size_t clen = zs_deflate.total_out;

        if (clen >= gtx->data_len) {
#if 0
          DBUG("deflate would waste %d bytes", (int) (clen - gtx->data_len));
#endif
          use_deflate = false;
        } else {
#if 0
          DBUG("Saved %d bytes by deflate (ratio=%d%%)",
              (int) (gtx->data_len - clen),
              (int) (clen * 100 / gtx->data_len));
#endif
          ggep_set_data_length(gtx, clen);
          (void) append_chars(gtx->open, &clen, buf, clen);
          RUNTIME_ASSERT(0 == clen);
        }
        break;
      }
      
      switch (ret) {
      case Z_BUF_ERROR:
      case Z_STREAM_ERROR:
      default:
        use_deflate = false;
#if 0
        WARN("deflateInit() failed: %s", 
          zs_deflate.msg ? zs_deflate.msg : "Unknown error");
#endif
      }
      break;
    }

    ret = deflateReset(zsp_deflate);
    switch (ret) {
    case Z_OK:
      break;
    case Z_STREAM_ERROR:
    case Z_DATA_ERROR:
    default:
#if 0
        WARN("deflateInit() failed: %s", 
      WARN("deflateReset() failed: %s", 
        zs_deflate.msg ? zs_deflate.msg : "Unknown error");
#endif
      ;
    }
  }
#else
  use_deflate = false;
#endif /* HAVE_ZLIB_SUPPORT */
  
  if (use_deflate)
    *gtx->last |= GGEP_F_DEFLATE;
  else
    *gtx->last &= ~GGEP_F_DEFLATE;

  gtx->p = &gtx->open[gtx->data_len];
  gtx->open = NULL;
}

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
