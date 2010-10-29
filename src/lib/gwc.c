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

#include "gwc.h"
#include "http.h"
#include "hashtable.h"
#include "mem.h"

struct gwc_cache {
  hashtable_t *ht;
};

static bool
gwc_url_cmp(const void *a, const void *b)
{
  RUNTIME_ASSERT(a != NULL);
  RUNTIME_ASSERT(b != NULL);
  return a == b || 0 == strcmp((const char *) a, (const char *) b);
}

static uint32_t 
gwc_url_hash(const void *p)
{
  uint32_t h;
  
  RUNTIME_ASSERT(p != NULL);
  
  h = hash_str((const char *) p);
  h = (h >> 24) ^ (h >> 16) ^ (h >> 8) ^ h;
  return h;
}

gwc_cache_t *
gwc_new(size_t size)
{
  gwc_cache_t *cache;

  cache = calloc(1, sizeof *cache);
  if (cache) {
    cache->ht = hashtable_new(size, gwc_url_hash, gwc_url_cmp);
  }
  return cache;
}

void
gwc_add_entry(gwc_cache_t *cache, const char *url, time_t stamp, int num_checks)
{
  gwc_url_t *g;
 
  RUNTIME_ASSERT(cache != NULL);
  RUNTIME_ASSERT(url != NULL);
  RUNTIME_ASSERT(num_checks >= 0);
  
  g = gwc_url_lookup(cache, url);
  if (g) {
    WARN("Tried to add URL which was already cached: \"%s\"", url);
    return;
  }

  g = mem_chunk_alloc(sizeof *g);
  if (!g)
    return;
  
  g->len = strlen(url);
  g->url = mem_chunk_alloc(g->len + 1);
  if (!g->url) {
    mem_chunk_free(g, sizeof *g);
    return;
  }
  memcpy(g->url, url, g->len + 1);
  g->stamp = stamp;
  g->num_checks = num_checks;

  hashtable_add(cache->ht, g->url, g);
}

void
gwc_add_url(gwc_cache_t *cache, const char *url)
{
  RUNTIME_ASSERT(cache != NULL);
  RUNTIME_ASSERT(url != NULL);

  gwc_add_entry(cache, url, compat_mono_time(NULL), 1);
}

bool
gwc_move_url(gwc_cache_t *from, gwc_cache_t *to, const char *url)
{
  gwc_url_t *a, *b;

  RUNTIME_ASSERT(from != NULL);
  RUNTIME_ASSERT(to != NULL);
  RUNTIME_ASSERT(from != to);
  RUNTIME_ASSERT(url != NULL);

  /* Add the URL to the ``to'' before removing it from the ``from''
   * cache because ``url'' might be a->url. gwc_add_url() copies the
   * the URL. */
  b = gwc_url_lookup(to, url);
  if (!b) {
    gwc_add_url(to, url);
  }
  
  a = gwc_url_lookup(from, url);
  if (a) {
    gwc_url_remove(from, a->url, true);
    return true;
  }

  return false;
}

gwc_url_t *
gwc_url_lookup(gwc_cache_t *cache, const char *url)
{
  void *p;
  bool found;
  
  RUNTIME_ASSERT(cache != NULL);
  RUNTIME_ASSERT(url != NULL);

  found = hashtable_get(cache->ht, url, &p);
  return found ? (gwc_url_t *) p : NULL;
}

void
gwc_url_remove(gwc_cache_t *cache, const char *url, bool free_entry)
{
  void *p;
  
  RUNTIME_ASSERT(cache != NULL);
  RUNTIME_ASSERT(url != NULL);

  if (free_entry && hashtable_get(cache->ht, url, &p)) {
    gwc_url_t *g = p;

    hashtable_remove(cache->ht, url);
    mem_chunk_free(g->url, g->len + 1);
    mem_chunk_free(g, sizeof *g);
  } else {
    hashtable_remove(cache->ht, url);
  }
}

void
gwc_foreach(const gwc_cache_t *cache, hashtable_foreach_cb func, void *udata)
{
  RUNTIME_ASSERT(cache != NULL);
  RUNTIME_ASSERT(cache->ht != NULL);
  RUNTIME_ASSERT(func != NULL);

  hashtable_foreach(cache->ht, func, udata);
}

typedef enum {
  GWC_URL_OK = 0,
  GWC_URL_NOT_HTTP,
  GWC_URL_NOT_ALPHANUM_HOST,
  GWC_URL_MISSING_HOSTNAME,
  GWC_URL_LOCAL_HOSTNAME,
  GWC_URL_WRONG_DOT,
  GWC_URL_INVALID_HOST_CHAR,
  GWC_URL_INVALID_DOMAIN,
  GWC_URL_ERROR_AFTER_COLON,
  GWC_URL_ERROR_AFTER_PORT,
  GWC_URL_ERROR_AFTER_HOST,
  GWC_URL_NON_ASCII,
  GWC_URL_UPPERCASE_PATH,
  GWC_URL_UNSAFE_CHAR,
  GWC_URL_TRAILING_DOT_DOT,
  GWC_URL_BEYOND_ROOT,
  GWC_URL_TOO_LONG,
  GWC_URL_STATIC_DATA,
  GWC_URL_OUT_OF_MEMORY
} gwc_url_res_t;

const char *
gwc_url_normalize_result(int res)
{
  switch ((gwc_url_res_t) res) {
  case GWC_URL_OK:
    return NULL;
  case GWC_URL_NOT_HTTP:
    return "URL isn't preceded by \"http://\"";
  case GWC_URL_NOT_ALPHANUM_HOST:
    return "HTTP prefix MUST be followed by an alphanum";
  case GWC_URL_MISSING_HOSTNAME:
    return "URLs without hostnames are disallowed";
  case GWC_URL_LOCAL_HOSTNAME:
    return "URLs with local hostnames are disallowed";
  case GWC_URL_WRONG_DOT:
    return "A dot must be preceded and followed by an alphanum";
  case GWC_URL_INVALID_HOST_CHAR:
    return "Invalid character in ``host:port'' part";
  case GWC_URL_INVALID_DOMAIN:
    return "No or invalid top-level domain";
  case GWC_URL_ERROR_AFTER_COLON:
    return "':' MUST be followed a by port value (1-65535)";
  case GWC_URL_ERROR_AFTER_PORT:
    return "Port number must be followed by '/' or NUL";
  case GWC_URL_ERROR_AFTER_HOST:
    return "host must be followed by ':', '/' or NUL";
  case GWC_URL_NON_ASCII:
    return "Non-ASCII character in URL; rejected";
  case GWC_URL_UPPERCASE_PATH:
    return "Uppercase character in the path of the URL; rejected";
  case GWC_URL_UNSAFE_CHAR:
    return "Unsafe character in URL; rejected";
  case GWC_URL_TRAILING_DOT_DOT:
    return "Trailing \"/..\" in URI; rejected";
  case GWC_URL_BEYOND_ROOT:
    return "URI ascents beyond root per \"/../\"";
  case GWC_URL_TOO_LONG:
    return "URL is longer than allowed";
  case GWC_URL_STATIC_DATA:
    return "URL points probably to static data; rejected";
  case GWC_URL_OUT_OF_MEMORY:
    return "Normalization failed; out of memory";
  }

  /* NOT REACHED */
  RUNTIME_ASSERT(0);
  return NULL;
}

char *
gwc_url_normalize(char *url, int *res)
{
#define DO_FAIL(x) \
  do { if (res != NULL) *res = (x); return NULL; } while(0)
#define TYPE_ENTRY(x) { ((sizeof x) - 1), x }
  static const struct {
    ssize_t len;
    const char *ext;
  } static_types[] = {
    TYPE_ENTRY(".html"),
    TYPE_ENTRY(".htm"),
    TYPE_ENTRY(".txt")
#undef TYPE_ENTRY
  };
  char *p, *q, *endptr, *path, *anchor, *tld = NULL;
  bool squeezed = false;
  int dots = 0;

  RUNTIME_ASSERT(url != NULL);
  
  if (NULL == (q = skip_ci_prefix(url, http_prefix))) {
    DO_FAIL(GWC_URL_NOT_HTTP);
  }
  memcpy(url, http_prefix, sizeof http_prefix - 1);

  if (!isalnum((unsigned char) *q)) {
    DO_FAIL(GWC_URL_NOT_ALPHANUM_HOST);
  }

  /* XXX: Parse IPv6 address */
  if (
    parse_net_addr(q, NULL, &endptr) &&
    ('/' == *endptr || ':' == *endptr || '\0' == *endptr)
  ) {
    DO_FAIL(GWC_URL_MISSING_HOSTNAME);
  }
  
  /* the ``host'' part is not an IP address */  
  for (/* NOTHING */; *q != '\0'; q++) {
    int c;
      
    for (/* NOTHING */; (c = (unsigned char) *q) != '\0'; q++) {
      if (isalpha(c)) {
        if (isupper(c))
          *q = tolower(c);
      } else if (!isdigit(c)) {
        break;
      }
    }
      
    if (c == '\0' || c == '/' || c == ':') {
      break;
    } else if (c == '-') {

      if (q[1] == '.')
        DO_FAIL(GWC_URL_WRONG_DOT);
      
    } else if (c == '.') {
      int d = (unsigned char) q[1];
        
      if (d == '\0' || d == ':' || d == '/')
        break;

      if (d == '.' || d == '-') {
        DO_FAIL(GWC_URL_WRONG_DOT);
      }
      
      dots++;
      tld = &q[1];
    } else {
      DO_FAIL(GWC_URL_INVALID_HOST_CHAR);
    }
  }

  if (!tld || !dots)
    DO_FAIL(GWC_URL_LOCAL_HOSTNAME);

  for (p = tld; *p != '\0'; p++) {
    int c= (unsigned char) *p;

    if (c == '.' || c == '/' || c == ':')
      break;

    if (!isalpha(c))
      DO_FAIL(GWC_URL_INVALID_DOMAIN);
  }

  if (p == tld || p == &tld[1])
    DO_FAIL(GWC_URL_INVALID_DOMAIN);


  anchor = q;
  if (*q == '.') {
    *q++ = '\0';
    squeezed = true;
  }
  
  if (*q == ':') {
    uint16_t port = 0;

    p = q++;
    while (*q == '0')
      q++;

    if (!parse_port_number(q, &port, &endptr)) {
      DO_FAIL(GWC_URL_ERROR_AFTER_COLON);
    }
    if (*endptr != '/' && *endptr != '\0') {
      DO_FAIL(GWC_URL_ERROR_AFTER_PORT);
    }

    if (port != HTTP_DEFAULT_PORT) {
      size_t len = endptr - q;
      
      if (p != anchor) {
        *anchor++ = ':';
        squeezed = true;
        memmove(anchor, q, len);
        anchor += len;
      } else {
        anchor += len + 1;
      }
    } else {
        squeezed = true;
    }

    q = endptr;
  }

  if (*q != '/' && *q != '\0') {
    DO_FAIL(GWC_URL_ERROR_AFTER_HOST);
  }

  path = p = q;

  /* scan path */
  for (/* empty */; *p != '\0'; q++, p++) {
    int c = (unsigned char) *p;

    /* Reject any unreasonable bullshit */
    if (!isascii(c)) {
      DO_FAIL(GWC_URL_NON_ASCII);
    }
    if (c != tolower(c)) {
      DO_FAIL(GWC_URL_UPPERCASE_PATH);
    }
    if (!isalnum(c) && NULL == strchr("/._-~", c)) {
      DO_FAIL(GWC_URL_UNSAFE_CHAR);
    }
      
    /* Handle relative paths i.e., /. and /.. */
    if (c != '/') {
      *q = c;
      continue;
    }

    /* Special handling for '/' follows */

    do {
        
      *q = '/';

      if (p[1] == '/') {
        squeezed = true;
        do {
          p++;
        } while (p[1] == '/');
      }

      if (!strcmp(p, "/.")) {
        p++;
        /* Ignoring trailing \"/.\" in URI */
      } else if (!strcmp(p, "/..")) {
        DO_FAIL(GWC_URL_TRAILING_DOT_DOT);
      } else if (!strncmp(p, "/./", sizeof "/./" - 1)) {
        squeezed = true;
        p += 2;
        /* Ignoring unnecessary \"/./\" in URI */
      } else if (!strncmp(p, "/../", sizeof "/../" - 1)) {
        squeezed = true;
        p += 3;
        /* Ascending one component in URI" */

        do {
          if (q == path)
            DO_FAIL(GWC_URL_BEYOND_ROOT);
        } while (*--q != '/');
          
      } else {
        break;
      }

    } while (*p == '/' && (p[1] == '/' || p[1] == '.'));
    
  }
  *q = '\0';

  if ((size_t) (q - url) > MAX_ALLOWED_GWC_URL_LENGTH)
    DO_FAIL(GWC_URL_TOO_LONG);

 
  /* add a trailing slash; if the URI is empty to prevent dupes */
  if (*path == '\0') {
    size_t len = anchor - url;
   
    if (!squeezed) {
      p = malloc(len + sizeof "/");
      if (!p) {
        DO_FAIL(GWC_URL_OUT_OF_MEMORY);
      }
      memcpy(p, url, len);
      url = p;
    }

    url[len] = '/';
    url[len + 1] = '\0';
  } else {
    size_t i;

    RUNTIME_ASSERT(*path == '/');
    
    if (anchor != path) {
      size_t len = q - path;

      RUNTIME_ASSERT(squeezed);
      memmove(anchor, path, len + 1);
      path = anchor;
      q = &anchor[len];
    }

    
    /* Check for probably static files */
    for (i = 0; i < ARRAY_LEN(static_types); i++) {
      p = q - static_types[i].len;
      if (!strcasecmp(p, static_types[i].ext))
        DO_FAIL(GWC_URL_STATIC_DATA);
    }
    
  }

  if (res != NULL)
    *res = GWC_URL_OK;

  return url;
#undef DO_FAIL
}

void
gwc_check_url_entry(const gwc_url_t *g)
{
  RUNTIME_ASSERT(g->url != NULL);
  RUNTIME_ASSERT(g->len > sizeof http_prefix && g->len <= MAX_ALLOWED_GWC_URL_LENGTH);
  RUNTIME_ASSERT(NULL != skip_prefix(g->url, http_prefix));
  RUNTIME_ASSERT(g->url[g->len] == '\0');
  RUNTIME_ASSERT(g->url[g->len - 1] != '\0');
}

#ifdef GWC_C_TEST
static const struct {
  const char *url;
  const char *url_norm;
} cases[] = {
  { "", NULL },
  { "http://", NULL },
  { "http://a", NULL },
  { "http://a/", NULL },
  { "http://a./", NULL },
  { "http://a.c/", NULL },
  { "http://a.co", "http://a.co/" },
  { "http://a.co.", "http://a.co/" },
  { "HTTP://a.co./", "http://a.co/" },
  { "http://-.co./", NULL },
  { "http://-a.co./", NULL },
  { "http://-example.com/", NULL },
  { "http://example-.com/", NULL },
  { "http://eXAMple.-Com/", NULL },
  { "http://example-.-com/", NULL },
  { "http://example.c-Om/", NULL },
  { "http://example.c0M/", NULL },
  { "http://example.com /", NULL },
  { "http://exA:PLE.com/", NULL },
  { "http://exa\x80ple.com/", NULL },
  { "http://exa?PLE.Com/", NULL },
  { "http://example .coM/", NULL },
  { "http://e xample.com/", NULL },
  { "http:// example.cOm/", NULL },
  { "http://example..com/", NULL },
  { "http://example...com/", NULL },
  { "http://example.com../", NULL },
  { "http://.example.com../", NULL },
  { "http://x-y.co./", "http://x-y.co/" },
  { "hTTp://x.invalid.:80", "http://x.invalid/" },
  { "http://x.invalid:80/", "http://x.invalid/" },
  { "HTtp://x.invalid.:80/", "http://x.invalid/" },
  { "htTP://X.INVALID.:080/", "http://x.invalid/" },
  { "http://x.invalid.:080", "http://x.invalid/" },
  { "hTTp://x.invalid.:080", "http://x.invalid/" },
  { "hTTp://x.invalid.:0080", "http://x.invalid/" },
  { "hTTp://a.b.C.Test.:0080", "http://a.b.c.test/" },
  { "hTTp://x.invalid.:8080", "http://x.invalid:8080/" },
  { "http://X.INVALid:8080/", "http://x.invalid:8080/" },
  { "HTtp://x.invALID.:8080/", "http://x.invalid:8080/" },
  { "htTP://x.invalid.:08080/", "http://x.invalid:8080/" },
  { "http://x.invalid.:08080", "http://x.invalid:8080/" },
  { "hTTp://x.invalid.:08080", "http://x.invalid:8080/" },
  { "hTTp://X.INvalid.:008080", "http://x.invalid:8080/" },
  { "hTTp://a.b.c.test.:0080", "http://a.b.c.test/" },
  { "hTTp://192.0.2.0:80", NULL },
  { "hTTp://0.0.0.0/", NULL },
  { "hTTp://255.255.255.255/", NULL },
  { "hTTp://192.0.2.0", NULL },
  { "hTTp://192.0.2.0/", NULL },
  { "hTTp://192.0.2.0./", NULL },
  { "hTTp://192.0.2.0../", NULL },
  { "hTTp://192.0.2.0.a/", NULL },
  { "HTTP://192.0.2.0.aa/", "http://192.0.2.0.aa/" },
  { "http://example.com:80/blah", "http://example.com/blah" },
  { "http://example.com:80/.", "http://example.com/" },
  { "http://example.com:80/..", NULL },
  { "http://example.com:80/../", NULL },
  { "http://example.com././", "http://example.com/" },
  { "http://example.com/./", "http://example.com/" },
  { "http://example.com/./../", NULL },
  { "http://example.com/../.", NULL },
  { "http://example.com/x/../.", "http://example.com/" },
  { "http://example.com/x/y/../.", "http://example.com/x/" },
  { "http://examPLE.COm/x/y/../..", NULL },
  { "http://example.com/x/y/../../", "http://example.com/" },
  { "http://example.com/X/y/.../.../", "http://example.com/X/y/.../.../" },
  { "http://example.com/..X/Y/.../.../", "http://example.com/..X/Y/.../.../" },
  { "http://example.com/.x/Y/.../.../", "http://example.com/.x/Y/.../.../" },
  { "http://example.com/..x/.y/.../.../", "http://example.com/..x/.y/.../.../"},
  { "http://example.com/blah.txt", NULL },
  { "http://example.com/blah.htm", NULL },
  { "http://example.com/blah.html", NULL },
  { "http://example.com/./././blah.html", NULL },
  { "http://example.com./blah.html", NULL },
  { "http://example.com:80/blah.html", NULL },
  { "http://example.com:0000080/blah.html", NULL },
  { "http://example.com:80/blubb/../blah.html", NULL },
  { "http://example.com:0/", NULL },
  { "http://example.com:65536/", NULL },
  { "http://example.com:10000000000/", NULL },
  { "http://example.com:+1000/", NULL },
  { "http://example.com: 1000/", NULL },
  { "http://example.com:80 /", NULL },
  { "http://user:pass@example.com/", NULL },
  { "http://user@example.com/", NULL },
  { "http://example/", NULL },
  { "http://example.c/", NULL },
  { "http://example.-/", NULL },
  { "http://example.0/", NULL },
  { "http://a-host.example.com//", "http://a-host.example.com/" },
  { "http://example.com/./", "http://example.com/" },
  { "http://example.com/./", "http://example.com/" },
  { "http://example.com/.//.//", "http://example.com/" },
  { "http://example.com.//././/", "http://example.com/" },
  { "http://example.com.//././/////", "http://example.com/" },
  { "http://example.com/////", "http://example.com/" },
  { "http://example.com:8080/////", "http://example.com:8080/" },
  { "http://example.com/blah/blubb..////../", "http://example.com/blah/" },
  { "http://example.com/blah/blubb..////../////.//..", NULL },
  { "http://example.com/heise/blah..////../////.//..//../", NULL },
};

int
main(void)
{
  size_t i;
  size_t pagesize = compat_getpagesize();
  char *m;
  
  m = compat_page_align(2 * pagesize);
  mprotect(&m[pagesize], pagesize, PROT_READ);
  RUNTIME_ASSERT(m != NULL);
  
  for (i = 0; i < ARRAY_LEN(cases); i++) {
    char *url, *url_res;
    size_t size;
    int res;

    size = strlen(cases[i].url) + 1;
    RUNTIME_ASSERT(size > 0 && size < pagesize);
    memset(m, 0, pagesize);
    url = &m[pagesize - size];
    memcpy(url, cases[i].url, size);
    
    RUNTIME_ASSERT(url != NULL);
    printf(" in: \"%s\"\n", url);
    url_res = gwc_url_normalize(url, &res);
    printf("out: \"%s\"\n%s\n\n",
        url_res ? url_res : "NULL",
        res != GWC_URL_OK ? gwc_url_normalize_result(res) : "");
   
    if (url_res == NULL) {
      RUNTIME_ASSERT(NULL == cases[i].url_norm);
      RUNTIME_ASSERT(res != GWC_URL_OK);
    } else {
      RUNTIME_ASSERT(NULL != cases[i].url_norm);
      RUNTIME_ASSERT(0 == strcmp(url_res, cases[i].url_norm));
      RUNTIME_ASSERT(res == GWC_URL_OK);
    }

    if (url != url_res)
      DO_FREE(url_res);
  }

  return 0;
}
#endif /* GWC_C_TEST */

/* vi: set ai et sts=2 sw=2 cindent: */
