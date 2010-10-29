/*
 * Copyright (c) 2004
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

#include "lib/common.h"
#include "lib/connection.h"
#include "lib/event_watcher.h"
#include "lib/filter.h"

#include "peercache.h"

/* How many pongs per lease to emit per IP address at most */
#define UHC_PONG_GRANT 3

int uhc_init(ev_watcher_t *watcher,
      connection_t *udp_con, connection_t *udp6_con);
void uhc_send_ping(net_addr_t addr, in_port_t port);
void uhc_set_filter(struct addr_filter *af);
void uhc_set_peercache(peer_cache_t *pc);
bool uhc_get_secondary(net_addr_t *addr, in_port_t *port);
int uhc_reopen_logs(void);

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
