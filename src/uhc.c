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

#include "lib/append.h"
#include "lib/ggep.h"
#include "lib/guid.h"
#include "lib/gwc.h"
#include "lib/peerlock.h"
#include "lib/hashtable.h"
#include "lib/list.h"
#include "lib/mem.h"
#include "lib/net_addr.h"

#include "uhc.h"
#include "options.h"

static void
UHC_DEBUG(const char *fmt, ...)
{
  va_list ap;
  
  (void) fmt;
  (void) ap;
}

static const options_t *opts_;
#define OPTION(x) ((opts_ != NULL ? opts_ : (opts_ = options_get()))->x)

static connection_t *udp_con, *udp6_con;
static peer_cache_t *peer_cache;
static struct addr_filter *addr_filter;
static peer_lock_set_t *ping_locks, *pong_locks;
static hashtable_t *ht_pongs; /* Stores (mainly) peers from UHC IPP pong */
static list_t *list_pongs; /* Stores peers from UHC IPP pong */
static FILE *uhc_logger;

struct pong_info {
  net_addr_t addr;
  in_port_t port;
};

uint32_t
pong_info_hash(const void *key)
{
  const net_addr_t *addr = key;
  
  return net_addr_hash(*addr);
}

bool
pong_info_cmp(const void *p, const void *q)
{
  const net_addr_t *a = p, *b = q;
  
  return net_addr_equal(*a, *b);
}

typedef enum {
  GNET_P_PING = 0x00,
  GNET_P_PONG = 0x01,
  GNET_P_PUSH = 0x40,
  GNET_P_QASK = 0x80,
  GNET_P_QHIT = 0x81
} gnet_p_t;

typedef struct ping_info {
  guid_t guid;
  struct timeval tv;
  net_addr_t addr;
  in_port_t port;
  bool replied;
} ping_info_t;

static list_t *list_ping_info;

int
uhc_reopen_logs(void)
{
  if (uhc_logger) {
    if (!freopen(OPTION(log_uhc), "w", uhc_logger)) {
      CRIT("freopen() failed for log_uhc: %s", compat_strerror(errno));
      return -1;
    }
  }
  return 0;
}

static void
uhc_log_msg(const struct timeval *tv, bool sent,
    net_addr_t addr, in_addr_t port, const char *msg)
{
  if (uhc_logger) {
    char addr_buf[NET_ADDR_PORT_BUFLEN];
    char date_buf[RFC1123_DATE_BUFLEN];

    print_net_addr_port(addr_buf, sizeof addr_buf, addr, port);
    print_iso8601_date(date_buf, sizeof date_buf, tv->tv_sec);
    fprintf(uhc_logger, "%s %s %s %s\n",
        date_buf, sent ? "TX" : "RX", addr_buf, msg);
  }
}

static void
uhc_log_sent_ping(const struct timeval *tv, net_addr_t addr, in_port_t port,
    size_t packet_size)
{
  char buf[1024], *p = buf;
  size_t avail = sizeof buf;

  p = append_uint(p, &avail, (unsigned) packet_size);
  p = append_string(p, &avail, " PING");
  uhc_log_msg(tv, true, addr, port, buf);
}

static void
uhc_log_received_ping(const struct timeval *tv, net_addr_t addr, in_port_t port,
    const char *vendor, unsigned packet_size)
{
  char buf[1024], *p = buf;
  size_t avail = sizeof buf;

  p = append_uint(p, &avail, packet_size);
  p = append_string(p, &avail, " PING ");
  p = append_string(p, &avail, vendor ? vendor : "-");
  uhc_log_msg(tv, false, addr, port, buf);
}

static void
uhc_log_sent_pong(const struct timeval *tv, net_addr_t addr, in_port_t port,
    unsigned packet_size)
{
  char buf[1024], *p = buf;
  size_t size = sizeof buf;

  p = append_uint(p, &size, packet_size);
  p = append_string(p, &size, " PONG ");

  uhc_log_msg(tv, true, addr, port, buf);
}

static void
uhc_log_received_pong(const struct timeval *tv, net_addr_t addr, in_port_t port,
    const char *vendor, int rtt)
{
  char buf[1024], *p = buf;
  size_t size = sizeof buf;

  p = append_uint(p, &size, (unsigned) size);
  p = append_string(p, &size, " PONG ");
  if (rtt >= 0) {
    p = append_uint(p, &size, (unsigned) rtt);
  } else {
    p = append_string(p, &size, "-");
  }
  p = append_string(p, &size, " ");
  p = append_string(p, &size, vendor ? vendor : "-");

  uhc_log_msg(tv, false, addr, port, buf);
}

static bool
peer_is_acceptable(const net_addr_t addr, in_port_t port)
{
  const char *reason;

  if (port < 1024) {
    reason = "Port is privileged";
  } else if (net_addr_equal(addr, OPTION(uhc_bind_address))) {
    reason = "Pong from myself(?)";
  } else if (net_addr_is_private(addr)) {
    reason = "Private address";
  } else if (net_addr_is_multicast(addr)) {
    reason = "Multicast address";
  } else if (addr_filter && addr_filter_match(addr_filter, addr)) {
    reason = "Hostile address";
  } else {
    return true;
  }

#if 0
  {
    char addr_buf[NET_ADDR_PORT_BUFLEN];
  
    print_net_addr_port(addr_buf, sizeof addr_buf, addr, port);
    UHC_DEBUG("%s (%s)", reason, addr_buf);
  }
#endif
  
  return false;
}

static bool
uhc_send_packet(const net_addr_t addr, in_port_t port, void *data, size_t size)
{
  const struct sockaddr *to;
  socklen_t to_len;
  ssize_t ret;
  connection_t *c;

  RUNTIME_ASSERT(udp_con || udp6_con);
  RUNTIME_ASSERT(data);

  switch (net_addr_family(addr)) {
  case AF_INET:
    if (NULL == (c = udp_con))
        return false;
    to_len = net_addr_sockaddr(addr, port, &to);
    break;
    
#ifdef HAVE_IPV6_SUPPORT
  case AF_INET6:
    if (NULL == (c = udp6_con))
      return false;
    to_len = net_addr_sockaddr_ipv6(addr, port, &to);
    break;
#endif /* HAVE_IPV6_SUPPORT */

  default:
    return false;
  }

  RUNTIME_ASSERT(c);
  RUNTIME_ASSERT(to_len > 0);
  
  ret = sendto(connection_get_fd(c), data, size, 0, to, to_len);
  if ((ssize_t) -1 == ret) {
    DBUG("sendto() failed: %s", compat_strerror(errno));
  } else if (ret == 0) {
    DBUG("sendto() returned zero");
  } else if ((size_t) ret != size) {
    DBUG("sendto() partial write: ret=%d", (int) ret);
  } else {
#if 0
    DBUG("sendto() succeeded");
#endif
  }
  return true;
}

static bool
uhc_send_pong(const struct timeval *tv, const void *guid,
    net_addr_t addr, in_port_t port)
{
  static const char pong_data[] = {
/*    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,*/ /* GUID */
    GNET_P_PONG,  /* Function (PONG) */
    1,            /* TTL */
    0,            /* Hops */
    0, 0, 0, 0,   /* Size (corrected before sent) */
    0, 0,         /* Port (corrected before sent) */

    0, 0, 0, 0,   /* IP address */
    0, 0, 0, 0,   /* Files */
    0, 0, 0, 0,   /* KBs */
  };
  static uint32_t pongs_sent;
  static struct timeval last_tv;
  const peer_t *peerv[200];
  size_t peer_count, len, n;
  char buf[4096], *p = buf;
  size_t left = sizeof buf, min_left, size;
  const char *fqdn = OPTION(uhc_hostname);
  ggep_t gtx;

  RUNTIME_ASSERT(tv);
  RUNTIME_ASSERT(guid);
  
  if (DIFFTIMEVAL(tv, &last_tv) >= 1000000) {
    last_tv = *tv;
    pongs_sent = 0;
  }
    
  if (pongs_sent > OPTION(uhc_pongs_per_sec))
    return false;
  
  if (peer_lock_set_locked(pong_locks, addr, tv->tv_sec))
    return false;
  peer_lock_set_add(pong_locks, addr, tv->tv_sec);

  pongs_sent++;
    
  p = append_chars(p, &left, guid, 16);
  p = append_chars(p, &left, pong_data, sizeof pong_data);

  n = MIN((int) ARRAY_LEN(peerv), OPTION(uhc_peers_per_pong));
  RUNTIME_ASSERT(n > 0 && n <= (ssize_t) ARRAY_LEN(peerv));
  peer_count = peer_cache_get(peer_cache, peerv, n, tv->tv_sec, addr);

  (void) ggep_init(&gtx, p, left);
  if (fqdn) {
    ggep_pack(&gtx, GGEP_ID_UDPHC, 0, fqdn, strlen(fqdn));
  }
 
  min_left = ggep_data_min_left(&gtx, GGEP_ID_IPP);
  if (peer_count > 0 && min_left > 6) {
    size_t blen = peer_count * 6;
    
    if (blen > min_left) {
      peer_count = min_left / 6;
      blen = peer_count * 6;
    }
    RUNTIME_ASSERT(0 == (blen % 6));
    RUNTIME_ASSERT(blen >= 6);
    RUNTIME_ASSERT(peer_count > 0);
    
    p = ggep_open(&gtx, GGEP_ID_IPP, GGEP_F_DEFLATE, blen);
    RUNTIME_ASSERT(p != NULL);

    for (n = 0; n < peer_count; n++) {
      const peer_t *peer = peerv[n];
      in_addr_t ip;
      char e[6];

      RUNTIME_ASSERT(peer);
      RUNTIME_ASSERT(peer->port);

      if (!net_addr_is_ipv4_mapped(peer->addr))
        continue;

      ip = net_addr_ipv4(peer->addr);
      memcpy(&e, &ip, 4);
      e[4] = peer->port & 0xff;
      e[5] = peer->port >> 8;
      ggep_write(&gtx, e, sizeof e);
    }
    
    ggep_close(&gtx);
  }
  
  len = ggep_end(&gtx);
  RUNTIME_ASSERT(left >= len);
  left -= len;

  RUNTIME_ASSERT(left <= sizeof buf);
  size = sizeof buf - left;
  RUNTIME_ASSERT(size >= 23);
  len = size - 23;
  RUNTIME_ASSERT(len < sizeof buf);
  
  /* Correct the payload length field of the Gnutella header */
  poke_le16(&buf[19], len);

  /* Correct the port of the pong */
  poke_le16(&buf[23], OPTION(uhc_port));

  if (uhc_send_packet(addr, port, buf, size)) {
    uhc_log_sent_pong(tv, addr, port, size);
    return true;
  }
  return false;
}

void 
ping_info_garbage_collect(time_t now)
{
  list_iter_t i;
  bool v;

  for (v = list_iter_first(&i, list_ping_info); v; v = list_iter_next(&i)) {
    ping_info_t *pi;

    pi = list_iter_get_ptr(&i);
    RUNTIME_ASSERT(pi != NULL);
    if (difftime(now, pi->tv.tv_sec) < 60)
      break;

    list_iter_delete(&i);
    guid_remove(&pi->guid);
    mem_chunk_free(pi, sizeof *pi);
  }
}

void
uhc_send_ping(net_addr_t addr, in_port_t port)
{
  static const char ping_data[] = {
    /* 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,*/ /* GUID */
    GNET_P_PING,  /* Function (PING) */
    1,            /* TTL */
    0,            /* Hops */
    0, 0, 0, 0,   /* Size (corrected before sent) */
  };
  struct timeval tv;
  char pref;
  uint8_t buf[4096];
  char *p = cast_to_void_ptr(buf);
  size_t left = sizeof buf, len, size;
  ggep_t gtx;
  ping_info_t *pi;
  const char *fqdn = OPTION(uhc_hostname);
 
  STATIC_ASSERT(23 - 16 == sizeof ping_data);
  STATIC_ASSERT(16 == sizeof pi->guid);

  if (!OPTION(support_uhc))
    return;
  
  RUNTIME_ASSERT(udp_con || udp6_con);
 
  compat_mono_time(&tv);
  /* Record that we've sent a ping, but don't enforce the limit here */
  peer_lock_set_add(ping_locks, addr, tv.tv_sec);

  ping_info_garbage_collect(tv.tv_sec);

  if (NULL == (pi = mem_chunk_alloc(sizeof *pi))) {
    CRIT("mem_chunk_alloc() failed");
    return;
  }

  guid_create(&pi->guid);
  pi->addr = addr;
  pi->port = port;
  pi->tv = tv;
  pi->replied = false;

  if (guid_is_magic(&pi->guid, NULL)) {
    mem_chunk_free(pi, sizeof *pi);
    CRIT("Oops GUID collision");
    return;
  }
  if (guid_add(&pi->guid, pi)) {
    mem_chunk_free(pi, sizeof *pi);
    CRIT("guid_add() failed");
    return;
  }
  if (!list_append(list_ping_info, pi)) {
    guid_remove(&pi->guid);
    mem_chunk_free(pi, sizeof *pi);
    return;
  }

  /* 128-bit Message ID */
  p = append_chars(p, &left, cast_to_void_ptr(&pi->guid.u8[0]), 16);
  /* Pseudo ping header */
  p = append_chars(p, &left, ping_data, sizeof ping_data);
   
  (void) ggep_init(&gtx, p, left);
  /* LimeWire 4.2.2 doesn't reply to SCP pings without a preference
   * for either ultrapeers or leaves */ 
  pref ^= random() & 1;
  ggep_pack(&gtx, GGEP_ID_SCP, 0, &pref, 1);
  if (fqdn) {
    ggep_pack(&gtx, GGEP_ID_UDPHC, 0, fqdn, strlen(fqdn));
  }
  len = ggep_end(&gtx);
  RUNTIME_ASSERT(left >= len);
  left -= len;

  RUNTIME_ASSERT(left <= sizeof buf);
  size = sizeof buf - left;
  RUNTIME_ASSERT(size >= 23);
  
  len = size - 23;
  RUNTIME_ASSERT(len < sizeof buf);

  /* Correct the payload length field of the Gnutella header */
  poke_le16(&buf[19], len);

#if 0 
  {
    char addr_buf[NET_ADDR_PORT_BUFLEN];
    
    print_net_addr(addr_buf, sizeof addr_buf, pi->addr, pi->port);
    DBUG("Ping (%s) GUID: %02x %02x %02x %02x %02x %02x %02x %02x - "
      "%02x %02x %02x %02x %02x %02x %02x %02x",
      addr_buf,
      buf[0x0], buf[0x1], buf[0x2], buf[0x3],
      buf[0x4], buf[0x5], buf[0x6], buf[0x7],
      buf[0x8], buf[0x9], buf[0xa], buf[0xb],
      buf[0xc], buf[0xd], buf[0xe], buf[0xf]);

    RUNTIME_ASSERT(0 == memcmp(buf, pi->guid.u8, 16));
    RUNTIME_ASSERT(guid_is_magic(&pi->guid, NULL));
  }
#endif

  if (uhc_send_packet(addr, port, buf, size)) {
    uhc_log_sent_ping(&tv, addr, port, size);
  }
}

static void
uhc_add_to_secondary(const struct timeval *tv, net_addr_t addr, in_port_t port)
{
  /* Skip addresses that are already in the primary cache */
  if (peer_cache_lookup(peer_cache, addr))
    return;

  if (!peer_is_acceptable(addr, port))
    return;
          
  if (hashtable_fill(ht_pongs) > 4 * 3600)
    return;

  /* If we sent a ping to the peer during the last hour, don't
   * record it again. Either we got a pong or the peer is dead. */
  if (peer_lock_set_locked(ping_locks, addr, tv->tv_sec))
    return;

  /* Check whether we've already seen this address in a pong */
  if (!hashtable_get(ht_pongs, &addr, NULL)) {
    struct pong_info *peer;

    if (NULL == (peer = mem_chunk_alloc(sizeof *peer))) {
      CRIT("mem_chunk_alloc() failed");
      return;
    }
    peer->addr = addr;
    peer->port = port;

    if (!list_append(list_pongs, peer)) {
      mem_chunk_free(peer, sizeof *peer);
      return;
    }

    hashtable_add(ht_pongs, &peer->addr, peer);
  }
}


static void
handle_packet(connection_t *c, const char *data, const size_t data_size,
    net_addr_t sender_addr, in_port_t sender_port)
{
  unsigned int function, ttl, hops, size;
  const char *p = data;
  size_t data_len;
  char id_name[GGEP_ID_BUFLEN];
  char addr_buf[NET_ADDR_PORT_BUFLEN];
  ggep_t gtx;
  ggep_id_t id;
  net_addr_t pong_addr = net_addr_unspecified;
  in_port_t pong_port = 0;
  char vendor[5] = { 0, 0, 0, 0, 0 };
  bool host_is_udphc = false;
  bool host_is_full = false;
  bool has_scp = false;
  bool has_vc = false;  /* set if there was a GGEP VC block */
  uint32_t vc = 0;  /* vendor code */
  int num_ipp_peers = 0;
  peer_t ipp_peers[50];

  (void) c;

  if (data_size < 23) {
    /* Packet is too small */
    return;
  }
  
  function = (uint8_t) data[16];
  ttl = (uint8_t) data[17];
  hops = (uint8_t) data[18];
  size = peek_le32(&data[19]);

#if 0 
  DBUG("GUID: %02x %02x %02x %02x %02x %02x %02x %02x - "
    "%02x %02x %02x %02x %02x %02x %02x %02x\n"
    "function: %02x, ttl: %3d, hops: %3d, size: %d",
    (uint8_t) data[0x0], (uint8_t) data[0x1],
    (uint8_t) data[0x2], (uint8_t) data[0x3],
    (uint8_t) data[0x4], (uint8_t) data[0x5],
    (uint8_t) data[0x6], (uint8_t) data[0x7],
    (uint8_t) data[0x8], (uint8_t) data[0x9],
    (uint8_t) data[0xa], (uint8_t) data[0xb],
    (uint8_t) data[0xc], (uint8_t) data[0xd],
    (uint8_t) data[0xe], (uint8_t) data[0xf],
    function, ttl, hops, size);
#endif
  
  if (GNET_P_PING != function && GNET_P_PONG != function) {
    /* Not a ping or pong */
    return;
  }
  /* TTL of 0 or 1 should be OK */
  if (ttl > 1) {
    /* Invalid TTL */
    return;
  }
  if (0 != hops) {
    /* Invalid Hops */
    return;
  }
  if (size + 23 != data_size) {
    /* Invalid size */
    return;
  }
  
  switch ((gnet_p_t) function) {
  case GNET_P_PING:
    p = &data[23];

    break;

  case GNET_P_PONG:
    {
      unsigned long files, kbs;
      in_addr_t ip;
      
      if (data_size < 37) {
        /* Pong is too small */
        return;
      }

      pong_port = peek_le16(&data[23]);
      memcpy(&ip, &data[25], sizeof ip);
      pong_addr = 0 != ip ? net_addr_set_ipv4(ip) : net_addr_unspecified;
      files = peek_le32(&data[29]);
      kbs = peek_le32(&data[33]);
      print_ipv4_addr(addr_buf, sizeof addr_buf, ip);
      UHC_DEBUG("Got %spong (ip=%s, port=%u, files=%lu, kbs=%lu)",
        data_size == 37 ? "bare " : "", addr_buf, pong_port, files, kbs);
      
      p = &data[37];
    }
    break;
    
  case GNET_P_PUSH:
  case GNET_P_QASK:
  case GNET_P_QHIT:
    break;
  } 
  data_len = data_size - (p - data);

  if (!ggep_decode(&gtx, p, data_len)) {
    /* No GGEP data in packet */
    return;
  }
  
  for (;;) {
    char ggep_buf[4096];
    int ret;

    ret = ggep_next(&gtx, id_name);
    if (0 == ret)
      break;
    
    if (-1 == ret) {
      /* Could not get next GGEP block */
      break;
    }
    
    id = ggep_map_id_name(id_name, NULL);
    if (GGEP_ID_INVALID == id) {
      /* Unknown GGEP ID */
      continue;
    }

    data_len = ggep_data(&gtx, cast_to_void_ptr(&p), ggep_buf, sizeof ggep_buf);
    if ((size_t) -1 == data_len) {
      /* Decompression of GGEP block */
      continue;
    }
    
    switch (id) {
    case GGEP_ID_UDPHC:
      {

        host_is_udphc = true;
        if (data_len == 0) {
          /* No hostname given */
        } else {
          char host[256 + 1], *ep;
          size_t host_size = sizeof host;
          bool truncated = false;

          if (host_size >= data_len + 1) {
            host_size = data_len + 1;
          } else {
            /* Hostname is too long */
            truncated = true;
          }

          ep = append_string(host, &host_size, p);
          if (host_size > 1) {
            /* Hostname contained NUL */
          }
          UHC_DEBUG("UDPHC: Hostname=\"%s%s\"", host, truncated ? " ..." : "");
        }
      }
      break;

    case GGEP_ID_IP:
      /* Ignore this one */
      break;
      
    case GGEP_ID_IPP:
      if (0 == data_len || 0 != (data_len % 6)) {
        UHC_DEBUG("IPP payload length (%u) is not a multiple of 6",
          (unsigned) data_len);
      } else {
        UHC_DEBUG("%u peers in IPP", (unsigned) (data_len / 6));

        while (data_len) {
          in_addr_t ip;
          in_port_t port;
            
          if ((size_t) num_ipp_peers >= ARRAY_LEN(ipp_peers)) {
            break;
          }
          
          memcpy(&ip, p, sizeof ip);
          p += sizeof ip;
          port = peek_le16(p);
          p += 2;
          
          print_ipv4_addr(addr_buf, sizeof addr_buf, ip);
          UHC_DEBUG("IPP: %s:%u", addr_buf, port);
          
          RUNTIME_ASSERT(data_len >= 6);
          data_len -= 6;
          
          ipp_peers[num_ipp_peers].addr = net_addr_set_ipv4(ip);
          ipp_peers[num_ipp_peers].port = port;
          num_ipp_peers++;
        }
      }
      break;

    case GGEP_ID_GTKG_IPP6:
      if (0 == data_len || 0 != (data_len % 6)) {
        UHC_DEBUG("IPP payload length (%u) is not a multiple of 16",
            (unsigned) data_len);
      } else {
        UHC_DEBUG("%d peers in IPP", (int) (data_len / 6));

        while (data_len) {
          net_addr_t a;
          in_port_t port;
            
          if ((size_t) num_ipp_peers >= ARRAY_LEN(ipp_peers)) {
            break;
          }
          
          memcpy(&a.ipv6, p, 16);
          p += 16;
          port = peek_le16(p);
          p += 2;
         
          {
            char buf[NET_ADDR_PORT_BUFLEN];
            print_net_addr_port(buf, sizeof buf, a, port);
            UHC_DEBUG("GTKG.IPP6: %s", buf);
          }
          
          RUNTIME_ASSERT(data_len >= 6);
          data_len -= 6;
          
          ipp_peers[num_ipp_peers].addr = a;
          ipp_peers[num_ipp_peers].port = port;
          num_ipp_peers++;
        }
      }
      break;
      
    case GGEP_ID_GTKG_IPV6:
      {
        /* XXX: Handle this */
      }
      break;
      
    case GGEP_ID_SCP:
      if (has_scp)
        WARN("Multiple GGEP SCP blocks");

      has_scp = true;
      if (data_len > 0) {
        UHC_DEBUG("SCP: Prefers free %s slots", *p & 1 ? "ultrapeer" : "leaf");
      } else {
        UHC_DEBUG("SCP: No slot preference");
      }
      break;

    case GGEP_ID_PHC:
      if (0 == data_len) {
        /* PHC: No payload */
      }
      
      while (data_len > 0) {
        char buf[512];
        const char *q;
        size_t left, len;

        RUNTIME_ASSERT(data_len <= INT_MAX);
        q = memchr(p, '\n', data_len);
        if (q) {
          q++;
        } else {
          q = &p[data_len];
        }
        len = q - p;
        RUNTIME_ASSERT(data_len >= len);
        data_len -= len;
        left = MIN(sizeof buf, (len + 1));
        (void) append_string(buf, &left, p);
        p = q;

        UHC_DEBUG("PHC: \"%s\"", buf);
      }
      break;

    case GGEP_ID_DU:
      if (data_len > 3 || data_len < 1) {
        UHC_DEBUG("Invalid length of DU payload: data_len=%d", (int) data_len);
      } else {
        size_t i = data_len;
        unsigned long uptime = 0;

        do {
          uptime = (uptime << 8) | (uint8_t) p[--i];
        } while (i != 0);
        UHC_DEBUG("Daily Uptime: %lu seconds", uptime);
      }
      break;

    case GGEP_ID_LOC:
      if (data_len >= 2) {
        char loc[32], *q;
        size_t left = sizeof loc - 1;
       
        q = append_escaped_chars(loc, &left, p, data_len);
        *q = '\0';

        UHC_DEBUG("Locale preference: \"%s\"", loc);
      } else {
        UHC_DEBUG("Invalid length for LOC (len=%d)", (int) data_len);
      }
      break;

    case GGEP_ID_GUE:
      UHC_DEBUG("Node supports GUESS");

      if (data_len > 0) {
        char buf[64], *q;
        size_t left = sizeof buf - 1;

        q = append_escaped_chars(buf, &left, p, data_len);
        *q = '\0';
        
        UHC_DEBUG("GUE payload: \"%s\"", buf);
      }
      break;

    case GGEP_ID_VC:
      if (has_vc)
        WARN("Multiple GGEP VC blocks");
      
      if (data_len < 5) {
        UHC_DEBUG("Invalid length for VC (len=%d)", (int) data_len);
      }
      
      if (data_len >= ARRAY_LEN(vendor) && !has_vc) {
        size_t i;

        vc = peek_be32(p);
        for (i = 0; i < ARRAY_LEN(vendor) - 1; i++) {
          int ch = (unsigned char) p[i];
          vendor[i] = isalnum(ch) ? ch : '.';
        }
        vendor[i] = '\0';
        UHC_DEBUG("Vendor: \"%s\" char=%02x", vendor, p[4]);
      }

      has_vc = true;
      break;

    case GGEP_ID_UP:
      if (data_len == 3) {
        UHC_DEBUG("Free slots: %u/%u (UP/Leaf) char=%02x",
            (uint8_t) p[1], (uint8_t) p[2], p[0]);
        if (0 == p[1] && 0 == p[2])
          host_is_full = true;
        
      } else {
        UHC_DEBUG("Invalid length for UP (len=%d)", (int) data_len);
      }
      break;

    default:
      UHC_DEBUG("Unknown GGEP ID: \"%s\"", id_name);
    }

  }

  switch (function) {
  case GNET_P_PONG: 
    { 
      guid_t guid;
      bool is_magic, ip_match = true, port_match = true, is_dupe = false;
      ping_info_t *pi = NULL;
      void *udata;
      struct timeval tv;
      int rtt = -1;
    
      memcpy(guid.u8, data, sizeof guid.u8);
      is_magic = guid_is_magic(&guid, &udata);
      if (!is_magic) {
        /* Non-magic GUID */
      } else {
        RUNTIME_ASSERT(udata != NULL);

        pi = udata;
        compat_mono_time(&tv);
        rtt = DIFFTIMEVAL(&tv, &pi->tv) / 1000;
        ip_match = net_addr_equal(pi->addr, sender_addr) ||
                      net_addr_equal(pi->addr, net_addr_unspecified);
        port_match = pi->port == sender_port;
        is_dupe = pi->replied;
        pi->replied = ip_match && port_match;
      
        print_net_addr_port(addr_buf, sizeof addr_buf,
          sender_addr, sender_port);

        UHC_DEBUG("Extracted: RTT=%dms Peer=%s \t%s%s",
          rtt, addr_buf,
          ip_match && port_match ? "" : " MISMATCH!",
          is_dupe ? "DUPE!" : "");

        uhc_log_received_pong(&tv, sender_addr, sender_port, vendor, rtt);
      }

      if (
          !ip_match ||
          (
            !net_addr_equal(pong_addr, sender_addr) &&
            !net_addr_equal(pong_addr, net_addr_unspecified)
          )
      ) {
        /* Address mismatch */
      } else if (!port_match || sender_port != pong_port) {
        /* Port mismatch */
      } else if (!is_magic) {
        /* GUID is not magic */
      } else if (is_dupe) {
        /* Sender resent pong(?) */
      } else if (rtt < 0 || (unsigned) rtt > OPTION(uhc_pong_timeout_msec)) {
        /* Pong is out of time */
      } else if (!peer_is_acceptable(sender_addr, sender_port)) {
        /* Discard */
      } else {
        int i;
      
        if (!host_is_udphc && !host_is_full) {
          UHC_DEBUG("Adding peer from %spong", 0 == data_size ? "bare " : "");
          peer_cache_add(peer_cache, tv.tv_sec, sender_addr, sender_port);
        } else {
          uhc_add_to_secondary(&tv, sender_addr, sender_port);
        }

        for (i = 0; i < num_ipp_peers; i++) {
          uhc_add_to_secondary(&tv, ipp_peers[i].addr, ipp_peers[i].port);
        }
      }
      
    }
    break;
    
  case GNET_P_PING:
    {
      struct timeval tv;
      bool sent_pong = false;
      guid_t guid;

      compat_mono_time(&tv);
      memcpy(&guid.u8, data, sizeof guid);

      uhc_log_received_ping(&tv, sender_addr, sender_port, vendor, data_size);

      if (!has_scp) {
        /* Nothing to do */
      } else if (sender_port < 1024) {
        /* Not ponging privileged port */
      } else if (net_addr_equal(sender_addr, OPTION(uhc_bind_address))) {
        /* Ping from myself(?) */
      } else if (guid_is_bogus(&guid)) {
        /* Not ponging bogus GUID */
      } else if (net_addr_is_multicast(sender_addr)) {
        /* Not ponging multicast address */
      } else if (addr_filter && addr_filter_match(addr_filter, sender_addr)) {
        /* Not ponging hostile address */
      } else {
        sent_pong = uhc_send_pong(&tv, &data[0], sender_addr, sender_port);

        if (hashtable_fill(ht_pongs) < 1000) {
          uhc_add_to_secondary(&tv, sender_addr, sender_port);
        }
      }
      
    }
    break;

  case GNET_P_PUSH:
  case GNET_P_QASK:
  case GNET_P_QHIT:
    break;
  }
  
}

static const char *
handle_sockaddr(const struct sockaddr_storage *from,
    net_addr_t *addr, in_port_t *port)
{
  static char addr_buf[NET_ADDR_PORT_BUFLEN];

  RUNTIME_ASSERT(from);
  RUNTIME_ASSERT(addr);
  RUNTIME_ASSERT(port);
  
  switch (from->ss_family) {
  case AF_INET:
    {
      const struct sockaddr_in *sin4 = cast_to_const_void_ptr(from);
      struct sockaddr_in sin4_copy;

      memcpy(&sin4_copy, sin4, sizeof *sin4);
      *addr = net_addr_set_ipv4(sin4_copy.sin_addr.s_addr);
      *port = ntohs(sin4_copy.sin_port);
      print_net_addr_port(addr_buf, sizeof addr_buf, *addr, *port);
    }
    break;

#ifdef HAVE_IPV6_SUPPORT
  case AF_INET6:
    {
      const struct sockaddr_in6 *sin6 = cast_to_const_void_ptr(from);
      struct sockaddr_in6 sin6_copy;

      memcpy(&sin6_copy, sin6, sizeof *sin6);
      *addr = net_addr_peek_ipv6(sin6_copy.sin6_addr.s6_addr);
      *port = ntohs(sin6_copy.sin6_port);
      print_net_addr_port(addr_buf, sizeof addr_buf, *addr, *port);
    }
    break;
#endif /* HAVE_IPV6_SUPPORT */

  default:
    {
      size_t avail = sizeof addr_buf;

      *addr = net_addr_unspecified;
      *port = 0;
      append_string(addr_buf, &avail, "<none>"); 
    }
  }

  return addr_buf;
}

static void
handle_udp(connection_t *c, ev_type_t ev)
{
  int fd = connection_get_fd(c);
  int i;
  
  if (0 == (ev & EVT_READ))
    return;

  /* Loop here to decrease the poll->recvfrom->poll cycles */
  for (i = 0; i < 8; i++) {
    static const struct sockaddr_storage zero_from;
    struct sockaddr_storage from;
    socklen_t len = sizeof from;
    char buf[4096];
    ssize_t ret;

    from = zero_from;
    ret = recvfrom(fd, buf, sizeof buf, 0, cast_to_void_ptr(&from), &len);
    if ((ssize_t) -1 == ret) {
      if (!is_temporary_error(errno)) {
        DBUG("recvfrom() failed: %s", compat_strerror(errno));
      }
      return;
    } else {
      const char *from_str;
      net_addr_t addr;
      in_port_t port;
      
      RUNTIME_ASSERT(ret >= 0 && (size_t) ret <= sizeof buf);
      from_str = handle_sockaddr(&from, &addr, &port);
      UHC_DEBUG("recvfrom()=%u (from=%s)", (unsigned) ret, from_str);
      handle_packet(c, buf, ret, addr, port);
    }
  }
}

static void
uhc_init_con(ev_watcher_t *watcher, connection_t *c)
{
  RUNTIME_ASSERT(watcher);
  RUNTIME_ASSERT(c);
  
  connection_set_blocking(c, false);
  connection_set_rcvlowat(c, 23); /* Minimum Gnutella packet size */
  if (OPTION(udp_rcvbuf_size)) {
    connection_set_rcvbuf(c, OPTION(udp_rcvbuf_size));
  }
  if (OPTION(udp_sndbuf_size)) {
    connection_set_sndbuf(c, OPTION(udp_sndbuf_size));
  }

  connection_set_event_cb(c, handle_udp);
  ev_watcher_watch_source(watcher, connection_get_source(c), EVT_READ);
}

int
uhc_init(ev_watcher_t *watcher, connection_t *udp_c, connection_t *udp6_c)
{
  RUNTIME_ASSERT(watcher);
  RUNTIME_ASSERT(udp_c || udp6_c);
  
  udp_con = udp_c;
  udp6_con = udp6_c;

  if (OPTION(network_id) && 0 != strcmp(OPTION(network_id), "gnutella")) {
    CRIT("The UDP hostcache cannot used for other networks than \"Gnutella\".");
    return -1;
  }
  
  if (OPTION(log_uhc)) {
    uhc_logger = safer_fopen(OPTION(log_uhc), SAFER_FOPEN_APPEND);
    if (!uhc_logger) {
      CRIT("Could not open log_uhc (\"%s\"): %s",
          OPTION(log_uhc), compat_strerror(errno));
      return -1;
    }
  }

  /* 256 GUIDs should be enough, considering we ping about 1 peer per
   * second and don't accept PONGs older than a minute */
  if (guid_init(256)) {
    CRIT("guid_init() failed");
    return -1;
  }

  if (NULL == (list_ping_info = list_new())) {
    CRIT("list_new() failed");
    return -1;
  }
  
  if (NULL == (list_pongs = list_new())) {
    CRIT("list_new() failed");
    return -1;
  }
  
  if (NULL == (ht_pongs = hashtable_new(4 * 3600, pong_info_hash, pong_info_cmp))) {
    CRIT("hashtable_new() failed");
    return -1;
  }

  if (NULL == (ping_locks = peer_lock_set_new(3600, 3600, 1))) {
    CRIT("peer_lock_set_new() failed");
    return -1;
  }

  {
    size_t size;

    size = OPTION(uhc_pongs_per_sec);
    size *= OPTION(uhc_lock_time);
    size = MAX(1, size);
    pong_locks = peer_lock_set_new(size, OPTION(uhc_lock_time), UHC_PONG_GRANT);
  }

  if (!pong_locks) {
    CRIT("peer_lock_set_new() failed");
    return -1;
  }

  if (udp_con) {
    uhc_init_con(watcher, udp_con);
  }
  if (udp6_con) {
    uhc_init_con(watcher, udp6_con);
  }

  return 0;
}

void
uhc_set_filter(struct addr_filter *af)
{
  addr_filter = af;
}

void
uhc_set_peercache(peer_cache_t *pc)
{
  peer_cache = pc;
}

/**
 * Retrieves a peer (IP address and port number) from the secondary UHC
 * cache which holds peers reported through pongs. The peer is then removed
 * from this cache.
 *
 * @ip will be set to the IP address of the peer - if any.
 * @port will be set to the port number of the peer - if any.
 *
 * @return true, if a peer was retrieved. Otherwise false.
 */
bool
uhc_get_secondary(net_addr_t *addr, in_port_t *port)
{
  list_iter_t i;
  struct pong_info *pi;
  void *key, *value;
  
  RUNTIME_ASSERT(ht_pongs != NULL);
  RUNTIME_ASSERT(list_pongs != NULL);

  if (!list_iter_first(&i, list_pongs))
    return false;

  key = list_iter_get_ptr(&i);
  RUNTIME_ASSERT(key != NULL);
  
  if (!hashtable_get(ht_pongs, key, &value)) {
    /* If it's in the list it must be in the table */
    RUNTIME_ASSERT(0);
    return false;
  }
  RUNTIME_ASSERT(value != NULL);
 
  pi = value;
  *addr = pi->addr;
  *port = pi->port;

  list_iter_delete(&i);
  hashtable_remove(ht_pongs, key);
  mem_chunk_free(pi, sizeof *pi);

  return true;
}

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
