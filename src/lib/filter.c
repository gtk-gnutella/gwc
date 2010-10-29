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

#include "filter.h"
#include "snode.h"
#include "nettools.h"

struct net_set {
    uint32_t  *addrs;
    size_t    n;
};

struct addr_filter {
  struct net_set nets[31];
  snode_t *names;
};


static int
cmp_addr_filter_entry(const void *p, const void *q)
{
  uint32_t a = *(const uint32_t *) p, b = *(const uint32_t *) q;
  return a == b ? 0 : (a > b ? 1 : -1);
}

static bool
pattern_matches(const char *pattern, const char *s)
{
  const char *p, *end_p;
  size_t p_len;

  RUNTIME_ASSERT(pattern);
  RUNTIME_ASSERT(s);
 
  for (p = pattern; '\0' != *p; p = end_p) {
    bool wildcard;

    wildcard = '*' == *p;
    while ('*' == *p) {
      p++;
    }

    end_p = p;
    for (end_p = p; '\0' != *end_p; end_p++) {
      if ('*' == *end_p)
        break;
    }
    p_len = end_p - p;
    if (0 == p_len)
      return true;

    while (0 != strncmp(s, p, p_len)) {
      if (!wildcard || '\0' == s[0])
        return false;

      s = strchr(&s[1], p[0]);
      if (!s)
        return false;
    }
    s += p_len;
  }

  return '\0' == s[0];
}


struct addr_filter *
addr_filter_load(const char *filename)
{
  static const struct addr_filter zero_af;
  struct addr_filter *af;
  FILE *f;
  unsigned int line_number;
  size_t i;
  char line[4096];

  /* XXX */
  {
    RUNTIME_ASSERT(pattern_matches("", ""));
    RUNTIME_ASSERT(pattern_matches("*", ""));
    RUNTIME_ASSERT(pattern_matches("*", "dfksdkfsdk"));
    RUNTIME_ASSERT(pattern_matches("*", "."));
    RUNTIME_ASSERT(pattern_matches("x*", "x"));
    RUNTIME_ASSERT(pattern_matches("x*", "xdskfjdsk"));
    RUNTIME_ASSERT(pattern_matches("x*", "x"));
    RUNTIME_ASSERT(pattern_matches("*x", "x"));
    RUNTIME_ASSERT(pattern_matches("*x", "x"));
    RUNTIME_ASSERT(pattern_matches("*x", "x"));
    RUNTIME_ASSERT(pattern_matches("*xolox.nl", "xolox.nl"));
    RUNTIME_ASSERT(pattern_matches("*xolox.nl", "*xolox.nl"));
    RUNTIME_ASSERT(pattern_matches("*xolox.nl", "*.xolox.nl"));
    RUNTIME_ASSERT(pattern_matches("*xolox.nl", "*gdkkgdkfxolox.nl"));
    RUNTIME_ASSERT(pattern_matches("*xolox.nl", "wha.tht.efuck.xolox.nl"));
    RUNTIME_ASSERT(pattern_matches("bearshare.net", "bearshare.net"));
    RUNTIME_ASSERT(pattern_matches("bearshare.net*", "bearshare.net"));
    RUNTIME_ASSERT(pattern_matches("bearshare.*", "bearshare.net"));
    RUNTIME_ASSERT(pattern_matches("bearshare.*", "bearshare.com"));
    RUNTIME_ASSERT(pattern_matches("bearshare.*", "bearshare."));
    RUNTIME_ASSERT(!pattern_matches("bearshare.*", "bearshare"));
    RUNTIME_ASSERT(!pattern_matches("*bearshare.*", "bearshare"));
    RUNTIME_ASSERT(!pattern_matches("*bearshare.", "bearshare"));
    RUNTIME_ASSERT(!pattern_matches("*bearshare.", "bearshare.x"));
  }
  
  af = malloc(sizeof *af);
  if (!af) {
    CRIT("Out of memory");
    return NULL;
  }
  *af = zero_af; 
  
  for (i = 0; i < ARRAY_LEN(af->nets); ++i) {
    af->nets[i].addrs = NULL;
    af->nets[i].n = 0;
  }
  
  f = safer_fopen(filename, SAFER_FOPEN_RD);
  if (!f) {
    WARN("could not open \"%s\": %s", filename, compat_strerror(errno));
    return NULL;
  }
  
  for (line_number = 1; fgets(line, sizeof line, f); line_number++) {
    uint32_t addr, mask;
    char *endptr, *p;

    endptr = strchr(line, '\n');
    if (!endptr) {
      CRIT("Non-terminated or overlong line in configuration file (%u)",
        line_number);
      goto failure;
    }
    *endptr = '\0';

    p = line;
    endptr = skip_spaces(p);
    if ('#' == *endptr || '\0' == *endptr) {
      /* skip comments and empty lines */
      continue;
    }

    if (parse_ipv4_addr(p, &addr, &endptr)) {
      unsigned v;

      if ('/' == endptr[0]) {
        uint32_t u;
        int error;
        bool ret;

        p = &endptr[1];
        v = parse_uint32(p, &endptr, 10, &error);
        if (v < 1 || v > 32 || '\0' != *endptr) {
          ret = parse_ipv4_addr(p, &mask, &endptr);
          if (!ret || 0 == mask || '\0' != *endptr) {
            WARN("Invalid data in line %u; "
                "expected IPv4 netmask (line ignored)",
                line_number);
            continue;
          }

          v = 32;
          for (u = ntohl(mask); !(u & 1); u >>= 1) {
            v--;
          }
          u = 0xffffffffU << (32 - v);
          if (mask != htonl(u)) {
            WARN("Strange netmask in line %u; expected IPv4 netmask "
                "(line ignored)", line_number);
            continue;
          }
        } else {
          u = 0xffffffffU << (32 - v);
          mask = htonl(u);
        }
      } else {
        endptr = skip_spaces(endptr);
        if ('\0' == endptr[0] || '#' == endptr[0]) {
          mask = ~((uint32_t) 0U);
          v = 32;
        } else {
          WARN("Unexpected non-comment data after address in line %u "
                "(line ignored)", line_number);
          continue;
        }
      }

      RUNTIME_ASSERT(mask != 0);
      v = 32 - v;
      RUNTIME_ASSERT((int) v >= 0 && v < ARRAY_LEN(af->nets));

      {
        void *q;
        
        q = realloc(af->nets[v].addrs,
            (af->nets[v].n + 1) * sizeof af->nets[v].addrs[0]);
        if (!q) {
          CRIT("Out of memory");
          break;
        }

        af->nets[v].addrs = q;
        af->nets[v].addrs[af->nets[v].n] = addr & mask;
        af->nets[v].n++;
      }
    } else {
      const char *pattern = p;
      int c;

      while ('\0' != (c = (unsigned char) *p)) {
        if (isspace(c)) {
          *p = '\0';
          break;
        }
        if (!isalnum(c) && '*' != c && '-' != c && '.' != c) {
          WARN("Invalid character in name pattern in line ne %u; "
              "(line ignored)", line_number);
          pattern = NULL;
          break;
        }
        *p++ = tolower(c);
      }

      if (pattern && '\0' != pattern[0]) {
        af->names = snode_prepend(af->names, snode_new(compat_strdup(pattern)));
      }
    }

  }
  fclose(f);
  f = NULL;

  for (i = 0; i < ARRAY_LEN(af->nets); i++) {
    if (!af->nets[i].addrs)
      continue;
    
    qsort(af->nets[i].addrs, af->nets[i].n, sizeof af->nets[i].addrs[0],
      cmp_addr_filter_entry);
  }
  af->names = snode_reverse(af->names);
  
  return af;

failure:
  if (f) {
    fclose(f);
    f = NULL;
  }
  DO_FREE(af);
  return NULL;
}

bool
addr_filter_match_name(const struct addr_filter *af, const char *fqdn)
{
  const snode_t *sn;

  RUNTIME_ASSERT(af);
  RUNTIME_ASSERT(fqdn);

  for (sn = af->names; NULL != sn; sn = sn->next) {
    RUNTIME_ASSERT(sn->ptr);
    if (pattern_matches(sn->ptr, fqdn))
      return true;
  }
  return false;
}

bool
addr_filter_match(const struct addr_filter *af, net_addr_t addr)
{
  in_addr_t ip;
  size_t i;

  RUNTIME_ASSERT(af);

  /* XXX: Add IPv6 support */
  if (!net_addr_is_ipv4_mapped(addr))
    return false;
  ip = net_addr_ipv4(addr);
  
  for (i = 0; i < ARRAY_LEN(af->nets); ++i) {
    in_addr_t v;
    void *p;
   
    if (!af->nets[i].addrs)
      continue;
    
    v = ip;
    v &= htonl(((in_addr_t) -1) << i);

    p = bsearch(&v, af->nets[i].addrs, af->nets[i].n,
          sizeof af->nets[i].addrs[0], cmp_addr_filter_entry);
    if (p != NULL)
      return true;
  }

  return false;
}

/* vi: set ai et sts=2 sw=2 cindent: */
