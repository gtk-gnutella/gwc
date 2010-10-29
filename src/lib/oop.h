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

#ifndef OOP_HEADER_FILE
#define OOP_HEADER_FILE

#include "common.h"

#define DESTRUCT(object) \
MACRO_BEGIN { \
  RUNTIME_ASSERT(object); \
  (object)->destruct((object)); \
  object = NULL; \
  RUNTIME_ASSERT(!object); \
} MACRO_END

#define ATTRIBUTE_GET(prefix, type, attr) \
type prefix ## _get_ ## attr (prefix ## _t *(obj)) NON_NULL; \
type  \
prefix ## _get_ ## attr (prefix ## _t *(obj)) \
{ \
  return ((prefix ## _union *) (obj))->priv.attr; \
}

#define ATTRIBUTE_SET(prefix, type, attr) \
void prefix ## _set_ ## attr (prefix ## _t *(obj), type val); \
void  \
prefix ## _set_ ## attr (prefix ## _t *(obj), type val) \
{ \
  RUNTIME_ASSERT(obj != NULL); \
  ((prefix ## _union *) (obj))->priv.attr = (val); \
}

/* vi: set ai et sts=2 sw=2 cindent: */
#endif /* OOP_HEADER_FILE */
