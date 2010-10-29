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

#include "fifo.h"
#include "mem.h"

typedef enum fifo_magic {
  FIFO_MAGIC = 0x306d0815
} fifo_magic_t;

struct fifo {
  fifo_magic_t magic;
  size_t in, out, fill, space, size;
  char data[1 /* pseudo-size */];
};

void
fifo_check(fifo_t *f)
{
  RUNTIME_ASSERT(f);
  RUNTIME_ASSERT(FIFO_MAGIC == f->magic);
  RUNTIME_ASSERT((ssize_t) f->size > 0);
  RUNTIME_ASSERT(f->in < f->size);
  RUNTIME_ASSERT(f->out < f->size);
  RUNTIME_ASSERT(f->space <= f->size);
  RUNTIME_ASSERT(f->fill <= f->size);
}

fifo_t *
fifo_new(size_t size)
{
  fifo_t *f = mem_chunk_alloc(size + sizeof *f);

  if (f) {
    f->magic = FIFO_MAGIC;
    f->in = 0;
    f->out = 0;
    f->fill = 0;
    f->space = size;
    f->size = size;
    fifo_check(f);
  }
  return f;
}

ssize_t
fifo_read(fifo_t *f, char *dst, ssize_t size)
{
  ssize_t i;
  const char *p = f->data;
  char *q = dst;

  fifo_check(f);
  if (size < 0)
    return (ssize_t) -1;

  if ((ssize_t) f->fill < size)
    size = (ssize_t) f->fill;
  
  for (i = 0; i < size; i++, q++)
    *q = p[(f->out + i) % f->size];
  
  f->fill -= i;
  f->space += i;
  if (f->fill == 0) {
    f->in = 0;
    f->out = 0;
  } else {
    f->out = (f->out + i) % f->size;
  }
  fifo_check(f);
  return i;
}

ssize_t
fifo_discard(fifo_t *f, ssize_t size)
{
  fifo_check(f);
  if (size < 0)
    return (ssize_t) -1;

  if ((ssize_t) f->fill < size)
    size = (ssize_t) f->fill;
  
  f->fill -= size;
  f->space += size;
  if (f->fill == 0) {
    f->in = 0;
    f->out = 0;
  } else {
    f->out = (f->out + size) % f->size;
  }
  fifo_check(f);
  return size;
}

ssize_t
fifo_skip_chars(fifo_t *f, size_t maxlen, const char *charset)
{
  const char *p;
  size_t i;

  fifo_check(f);
  RUNTIME_ASSERT(charset);
  
  if ((size_t) maxlen > f->fill)
    maxlen = f->fill;
  
  p = f->data;
  for (i = 0; i < maxlen; i++) {
    size_t j = (f->out + i) % f->size;
    int c = (unsigned char) p[j];
    
    if ('\0' == c || NULL == strchr(charset, c)) {
      f->out = j;
      break;
    }
  }
  
  return i;
}

ssize_t
fifo_findchar(fifo_t *f, char c, ssize_t size)
{
  ssize_t i;
  const char *p;

  fifo_check(f);
  if (size < 0)
    return -1;

  if ((size_t) size > f->fill)
    size = f->fill;
  
  p = f->data;
  for (i = 0; i < size; i++) {
   if (c == p[(f->out + i) % f->size])
     return i;
  }
  
  return -1;
}

ssize_t
fifo_findstr(fifo_t *f, const char *str, ssize_t off)
{
  size_t i;
  const char *p = f->data;
  const char *q = str;
  char c;

  RUNTIME_ASSERT(f);
  RUNTIME_ASSERT(str);
  RUNTIME_ASSERT(off >= 0);
  
  fifo_check(f);
  if (off < 0 || (size_t) off > f->fill)
    return -1;

  c = *str;
  if (c == '\0')
    return -1;

  for (i = off; i < f->fill; i++)
    if (c == p[(f->out + i) % f->size]) {
      c = q[1];
      if (c == '\0')
        return i - (q - str);
      q++;
    } else {
      q = str;
      c = *str;
    }
  
  return -1;
}

ssize_t
fifo_write(fifo_t *f, const char *src, ssize_t size)
{
  ssize_t i;
  const char *p = src;
  char *q = f->data;

  fifo_check(f);
  if (size < 0) {
    WARN("size is negative");
    return (ssize_t) -1;
  }

  if (size > (ssize_t) f->space)
    size = (ssize_t) f->space;

  for (i = 0; i < size; i++)
    q[(f->in + i) % f->size] = *p++;

  f->in = (f->in + i) % f->size;
  f->fill += i;
  f->space -= i;
  fifo_check(f);
  return i;
}

ssize_t
fifo_write_str(fifo_t *f, const char *str)
{
  return fifo_write(f, str, strlen(str));
}

ssize_t
fifo_recv(fifo_t *f, int fd)
{
  struct iovec iov[2];
  ssize_t ret;
  size_t size;
  void *base;
  int i;

  fifo_check(f);
  RUNTIME_ASSERT(fd >= 0);
  if (fd < 0) {
    errno = EBADF;
    return -1;
  }

  if (f->space < 1) {
    errno = ENOBUFS;
    return -1;
  }

  i = 0;
  size = f->size - f->in;
  base = f->data + f->in;
  if (size < f->space) {
    /* Take care of the following situation:
     * [FFFFFFFDDDiFFF]
     * (F)ree, (D)ata, (i)n
     */
#if 0
    DBUG("<recv> iov[0].base=%p", base);
    DBUG("<recv> iov[0].len=%ld", (long) size);
#endif
    iov[i].iov_base = base;
    iov[i].iov_len = size;
    base = f->data;
    size = f->space - size;
    i++;
  } else if (size > f->space) {
    size = f->space;
  }
  if (size > 0) {
#if 0
    DBUG("<recv> iov[1].base=%p", base);
    DBUG("<recv> iov[1].len=%ld", (long) size);
#endif
    iov[i].iov_base = base;
    iov[i].iov_len = size;
    i++;
  }
  
  ret = readv(fd, iov, i);
  if (ret != (ssize_t) -1 && ret != 0) {
    f->fill += ret;
    f->space -= ret;
    f->in = (f->in + ret) % (f->fill + f->space);
  }
  fifo_check(f);
  return ret;
}

ssize_t
fifo_readv_n(fifo_t *f, int fd, ssize_t n)
{
  struct iovec iov[2];
  ssize_t ret;
  size_t size;
  void *base;
  int i;

  fifo_check(f);
  RUNTIME_ASSERT(fd >= 0);
  if (fd < 0) {
    errno = EBADF;
    return -1;
  }

  if (n < 0) {
    WARN("n is negative");
    return (ssize_t) -1;
  }

  if (f->space < 1) {
    errno = ENOBUFS;
    return -1;
  }

  i = 0;
  size = f->size - f->in;
  base = f->data + f->in;
  if (size < f->space) {
    /* Take care of the following situation:
     * [FFFFFFFDDDiFFF]
     * (F)ree, (D)ata, (i)n
     */
#if 0
    DBUG("<recv> iov[0].base=%p", base);
    DBUG("<recv> iov[0].len=%ld", (long) size);
#endif

    iov[i].iov_base = base;
    iov[i].iov_len = MIN((size_t) n, size);
    i++;
    base = f->data;

    if (size >= (size_t) n) {
      n = size = 0;
    } else {
      n -= size;
      size = f->space - size;
    }
  } else if (size > f->space) {
    size = MIN((size_t) n, f->space);
  }
  if (size > 0 && n > 0) {
#if 0
    DBUG("<recv> iov[1].base=%p", base);
    DBUG("<recv> iov[1].len=%ld", (long) size);
#endif
    iov[i].iov_base = base;
    iov[i].iov_len = MIN((size_t) n, size);
    i++;
  }
  
  ret = readv(fd, iov, i);
  if (ret != (ssize_t) -1 && ret != 0) {
    f->fill += ret;
    f->space -= ret;
    f->in = (f->in + ret) % (f->fill + f->space);
  }
  fifo_check(f);
  return ret;
}


#if 0
ssize_t
fifo_send(fifo_t *f, int fd)
{
  ssize_t ret;
  size_t size;
  void *base;

  fifo_check(f);
  RUNTIME_ASSERT(fd >= 0);
  if (fd < 0) {
    errno = EBADF;
    CRIT("negative file descriptor");
    return (ssize_t) -1;
  }

  if (f->fill < 1)
    return 0;

  size = f->size - f->out;
  base = &f->data[f->out];
  if (size > f->fill) {
    size = f->fill;
  }

#ifdef HAVE_MSG_MORE
  ret = send(fd, base, size, SEND_MSG_MORE);
#else
  ret = write(fd, base, size);
#endif
  
  if (ret != (ssize_t) -1 && ret != 0) {
    f->fill -= ret;
    f->space += ret;
    if (f->fill == 0) {
      f->out = 0;
      f->in = 0;
    } else {
      f->out = (f->out + ret) % (f->fill + f->space);
    }
  }
  fifo_check(f);
  return ret;
}
#endif

ssize_t
fifo_writev(fifo_t *f, int fd)
{
  struct iovec iov[2];
  ssize_t ret;
  size_t size;
  void *base;
  int i;

  fifo_check(f);
  RUNTIME_ASSERT(fd >= 0);
  if (fd < 0) {
    errno = EBADF;
    CRIT("negative file descriptor");
    return (ssize_t) -1;
  }

  if (f->fill < 1)
    return 0;

  i = 0;
  base = &f->data[f->out];
  size = f->size - f->out;
  if (size < f->fill) {
    /* Take care of the following situation:
     * [DDDDDDDFFFoDDD]
     * (F)ree, (D)ata, (o)n
     */
#if 0
    DBUG("<send> iov[0].base=%p", base);
    DBUG("<send> iov[0].len=%ld", (long) size);
#endif
    iov[i].iov_base = base;
    iov[i].iov_len = size;
    base = f->data;
    size = f->fill - size;
    i++;
  } else if (size > f->fill) {
    size = f->fill;
  }
  if (size > 0) {
#if 0
    DBUG("<send> iov[1].base=%p", base);
    DBUG("<send> iov[1].len=%ld", (long) size);
#endif
    iov[i].iov_base = base;
    iov[i].iov_len = size;
    i++;
  }
  
  ret = writev(fd, iov, i);
  if (ret != (ssize_t) -1 && ret != 0) {
    f->fill -= ret;
    f->space += ret;
    if (f->fill == 0) {
      f->out = 0;
      f->in = 0;
    } else {
      f->out = (f->out + ret) % (f->fill + f->space);
    }
  }
  fifo_check(f);
  return ret;
}

ssize_t
fifo_writev_n(fifo_t *f, int fd, ssize_t n)
{
  struct iovec iov[2];
  ssize_t ret;
  size_t size;
  void *base;
  int i;

  fifo_check(f);
  RUNTIME_ASSERT(fd >= 0);
  if (fd < 0) {
    errno = EBADF;
    CRIT("negative file descriptor");
    return (ssize_t) -1;
  }
  
  if (n < 0) {
    CRIT("n is negative");
    return (ssize_t) -1;
  }


  if (f->fill < 1)
    return 0;

  i = 0;
  base = &f->data[f->out];
  size = f->size - f->out;
  if (size < f->fill) {
    /* Take care of the following situation:
     * [DDDDDDDFFFoDDD]
     * (F)ree, (D)ata, (o)n
     */
#if 0
    DBUG("<send> iov[0].base=%p", base);
    DBUG("<send> iov[0].len=%ld", (long) size);
#endif
    iov[i].iov_base = base;
    iov[i].iov_len = MIN((size_t) n, size);
    i++;
    base = f->data;

    if (size > (size_t) n) {
      size = n = 0;
    } else {
      n -= size;
      size = f->fill - size;
    }
  } else if (size > f->fill) {
    size = MIN((size_t) n, f->fill);
    n -= size;
  }
  if (size > 0 && n > 0) {
#if 0
    DBUG("<send> iov[1].base=%p", base);
    DBUG("<send> iov[1].len=%ld", (long) size);
#endif
    iov[i].iov_base = base;
    iov[i].iov_len = MIN((size_t) n, size);
    i++;
  }
  
  ret = writev(fd, iov, i);
  if (ret != (ssize_t) -1 && ret != 0) {
    f->fill -= ret;
    f->space += ret;
    if (f->fill == 0) {
      f->out = 0;
      f->in = 0;
    } else {
      f->out = (f->out + ret) % (f->fill + f->space);
    }
  }
  fifo_check(f);
  return ret;
}


bool
fifo_empty(fifo_t *f)
{
  fifo_check(f);
  return f->fill == 0;
}

bool
fifo_full(fifo_t *f)
{
  fifo_check(f);
  return f->space == 0;
}

size_t
fifo_fill(fifo_t *f)
{
  fifo_check(f);
  return f->fill;
}

size_t
fifo_space(fifo_t *f)
{
  fifo_check(f);
  return f->space;
}

void
fifo_destruct(fifo_t *f)
{
  if (f) {
    fifo_check(f);
    mem_chunk_free(f, f->size + sizeof *f);
  }
}

/* vi: set ai et sts=2 sw=2 cindent: */
