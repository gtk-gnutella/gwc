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

#ifndef FIFO_HEADER_FILE
#define FIFO_HEADER_FILE

#include "common.h"

typedef struct fifo fifo_t;

fifo_t *fifo_new(size_t size);
ssize_t fifo_discard(fifo_t *f, ssize_t size);
ssize_t fifo_read(fifo_t *f, char *dst, ssize_t size);
ssize_t fifo_write(fifo_t *f, const char *src, ssize_t size);
#define fifo_send fifo_writev
/* ssize_t fifo_send(fifo_t *f, int fd); */
ssize_t fifo_writev(fifo_t *f, int fd);
ssize_t fifo_writev_n(fifo_t *f, int fd, ssize_t n);
ssize_t fifo_readv_n(fifo_t *f, int fd, ssize_t n);
ssize_t fifo_recv(fifo_t *f, int fd);
ssize_t fifo_write_str(fifo_t *f, const char *str);
bool fifo_empty(fifo_t *f);
bool fifo_full(fifo_t *f);
size_t fifo_fill(fifo_t *f);
size_t fifo_space(fifo_t *f);
ssize_t fifo_findchar(fifo_t *f, char c, ssize_t size);
ssize_t fifo_skip_chars(fifo_t *f, size_t maxlen, const char *charset);
ssize_t fifo_findstr(fifo_t *f, const char *str, ssize_t off);
void fifo_destruct(fifo_t *f);

#endif /* FIFO_HEADER_FILE */
