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

#ifndef CONNECTION_HEADER_FILE
#define CONNECTION_HEADER_FILE

#include "common.h"
#include "event_source.h"
#include "net_addr.h"

typedef struct connection connection_t;
typedef void (*connection_event_cb)(connection_t *, ev_type_t);

/**
 * Constructors
 */
connection_t *connection_new(const net_addr_t addr, uint16_t);
connection_t *connection_listen(const net_addr_t addr, uint16_t port,
                int backlog);
connection_t *connection_accept(connection_t *) NON_NULL;
connection_t *connection_udp(const net_addr_t addr, uint16_t port);

/**
 * Getters
 */
bool              connection_get_listening(connection_t *);
char *            connection_get_addrstr(connection_t *, char *, size_t);
ev_source_t *     connection_get_source(connection_t *);
net_addr_t        connection_get_addr(connection_t *);
uint16_t          connection_get_port(connection_t *);
void *            connection_get_context(connection_t *);
int               connection_get_fd(connection_t *);

/**
 * Setters
 */
int               connection_set_blocking(connection_t *, bool block);
int               connection_set_defer_accept(connection_t *, int);
int               connection_set_nodelay(connection_t *, bool); 
int               connection_set_nopush(connection_t *, bool);
int               connection_set_quick_ack(connection_t *, bool);
int               connection_set_rcvbuf(connection_t *, int);
int               connection_set_rcvlowat(connection_t *, unsigned int);
int               connection_set_sndbuf(connection_t *, int);
int               connection_set_tos_lowdelay(connection_t *); 
int               connection_set_tos_reliability(connection_t *); 
int               connection_set_tos_throughput(connection_t *); 
void              connection_set_context(connection_t *, void *);
void              connection_set_source(connection_t *, ev_source_t *);
void              connection_set_event_cb(connection_t *, connection_event_cb);

/**
 * Miscellaneous methods  
 */
void              connection_check(connection_t *);
int               connection_accept_http_filter(connection_t *);
void              connection_close(connection_t *);
bool              connection_is_closed(connection_t *);

/**
 * Reference counting
 */
void              connection_ref(connection_t *);
void              connection_unref(connection_t *);

/* vi: set ai et sts=2 sw=2 cindent: */
#endif /* CONNECTION_HEADER_FILE */
