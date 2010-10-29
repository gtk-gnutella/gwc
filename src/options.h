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

#ifndef OPTIONS_HEADER_FILE
#define OPTIONS_HEADER_FILE

#include "lib/common.h"
#include "lib/nettools.h"
#include "lib/net_addr.h"

typedef enum {
  OPTIONS_MAGIC = 0x92c41cbc
} options_magic_t;

typedef struct {
  net_addr_t listen_address;
  net_addr_t listen6_address;
  in_port_t listen_port;
  int       listen_backlog;
  char      *gwc_url;
  char      *gwc_fqdn;
  uint16_t  gwc_port;
  char      *gwc_uri;
  hash_t    gwc_url_hash;
  char      *chroot_directory;
  char      *coredump_directory;
  char      *working_directory;
  char      *log_access;
  char      *log_alert;
  char      *log_checks;
  char      *log_dns;
  char      *log_main;
  char      *log_uhc;
  char      *peer_cache;
  char      *bad_url_cache;
  char      *good_url_cache;
  char      *address_filter;
  char      *user;
  char      *group;
  ssize_t   hostfile_lines;
  ssize_t   urlfile_lines;
  ssize_t   peers_per_get;
  ssize_t   gwcs_per_get;
  unsigned  gwc_lock_time;
  unsigned  same_vendor_ratio;
  unsigned  max_connect_time;
  unsigned  idle_timeout;
  unsigned  url_check_delay;
  unsigned  max_accepts_per_sec;
  bool      support_v2;
  bool      expose_sysname;
  bool      pause_on_crash;
  bool      daemonize;
  int       priority;
  bool      allow_anonymous;
  bool      auto_discovery;
  bool      ban_bad_vendors;
  int       tcp_defer_accept_timeout;
  ssize_t   tcp_rcvbuf_size;
  ssize_t   tcp_sndbuf_size;
  ssize_t   udp_rcvbuf_size;
  ssize_t   udp_sndbuf_size;
  ssize_t   url_check_max_size;
  ssize_t   request_max_size;
  bool      http_dump_headers;
  bool      send_x_remote_ip;
  bool      send_x_gwc_url;
  bool      send_from_header;
  bool      url_check_strict;
  bool      url_check_allow_dupes;
  bool      late_filter;
  char      *network_id;
  char      *data_key;
  char      *data_template;
  char      *base_template;
  char      *contact_address;
  ssize_t   max_cached_peers;
  bool      support_gwc;
  
  /* UHC options */
  bool      support_uhc;
  char      *uhc_hostname;
  net_addr_t uhc_bind_address;
  net_addr_t uhc_bind6_address;
  in_port_t uhc_port;
  uint32_t  uhc_peers_per_pong;
  uint32_t  uhc_pongs_per_sec;
  uint32_t  uhc_pong_timeout_msec;
  unsigned  uhc_lock_time;

  /* Internals */
  bool has_listen_address;
  bool has_listen6_address;
  bool has_uhc_bind_address;
  bool has_uhc_bind6_address;
  
  options_magic_t  magic; /* last member */
} options_t;

int options_load(const char *pathname);
const options_t *options_get(void);

/* vi: set ai et sts=2 sw=2 cindent: */
#endif /* OPTIONS_HEADER_FILE */
