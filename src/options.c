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

#include "lib/gwc.h"        /* gwc_url_normalize() */
#include "lib/http.h"       /* http_prefix */
#include "lib/nettools.h"   /* safer_fopen() */

#include "options.h"

#include <pwd.h>


/* TODO:  Use accessors instead of a public structure or an union with the
 *        all public members being const qualified */

static options_t global_default_options = { 
  { { 0 } },        /* listen_address */
  { { 0 } },        /* listen6_address */
  0,                /* listen_port */
  32,               /* listen_backlog */
  NULL,             /* gwc_url */
  NULL,             /* gwc_fqdn */
  0,                /* gwc_port */
  NULL,             /* gwc_uri */
  0,                /* gwc_url_hash */
  NULL,             /* chroot_directory */
  NULL,             /* coredump_directory */
  NULL,             /* working_directory */
  NULL,             /* log_access */
  NULL,             /* log_alert */
  NULL,             /* log_checks */
  NULL,             /* log_dns */
  NULL,             /* log_main */
  NULL,             /* log_uhc */
  NULL,             /* peer_cache */
  NULL,             /* bad_url_cache */
  NULL,             /* good_url_cache */
  NULL,             /* address_filter */
  NULL,             /* user */
  NULL,             /* group */
  20,               /* hostfile_lines */
  10,               /* urlfile_lines */
  16,               /* peers_per_get */
  4,                /* gwcs_per_get */
  600,              /* gwc_lock_time */
  40,               /* same_vendor_ratio */
  15,               /* max_connect_time */
  10,               /* idle_timeout */
  30,               /* url_check_delay */
  0,                /* max_accepts_per_sec */
  false,            /* support_v2 */
  false,            /* expose_sysname */
  false,            /* pause_on_crash */
  true,             /* daemonize */
  0,                /* priority */
  false,            /* allow_anonymous */
  false,            /* auto_discovery */
  false,            /* ban_bad_vendors */
  20,               /* tcp_defer_accept_timeout */
  1024,             /* tcp_rcvbuf_size */
  4096,             /* tcp_sndbuf_size */
  0,                /* udp_rcvbuf_size */
  0,                /* udp_sndbuf_size */
  4096,             /* url_check_max_size */
  1024,             /* request_max_size */
  false,            /* http_dump_headers */
  false,            /* send_x_remote_ip */
  false,            /* send_x_gwc_url */
  false,            /* send_from_header */
  true,             /* url_check_strict */
  false,            /* url_check_allow_dupes */
  false,            /* late_filter */
  NULL,             /* network_id */
  NULL,             /* data_key */
  NULL,             /* data_template */
  NULL,             /* base_template */
  NULL,             /* contact_address */
  10000,            /* max_cached_peers */
  true,             /* support_gwc */
 
  /* UHC options */
  false,            /* support_uhc */
  NULL,             /* uhc_hostname */
  { { 0 } },        /* uhc_bind_address */
  { { 0 } },        /* uhc_bind6_address */
  0,                /* uhc_port */
  (uint32_t) 50,    /* uhc_peers_per_pong */
  (uint32_t) 20,    /* uhc_pongs_per_sec */
  (uint32_t) 60000, /* uhc_pong_timeout_msec */
  (unsigned) 600,   /* uhc_lock_time */

  /* Internals */
  false,            /* has_listen_address */
  false,            /* has_listen6_address */
  false,            /* has_uhc_bind_address */
  false,            /* has_uhc_bind6_address */

  OPTIONS_MAGIC     /* magic */
};

static options_t *global_options = NULL;

void
options_check(const options_t * const options)
{
  RUNTIME_ASSERT(options);
  RUNTIME_ASSERT(OPTIONS_MAGIC == options->magic);
}

const options_t *
options_get(void)
{
  options_check(global_options);
  return global_options;
}

static int
options_set_string(char **dst, const char *name, const char *val)
{
  const char *p;
  
  RUNTIME_ASSERT(dst);
  RUNTIME_ASSERT(name);
  RUNTIME_ASSERT(val);
  
  if (*dst) {
    CRIT("\"%s\" multiple times specified", name);
    return -1;
  }

  for (p = val; '\0' != *p; p++) {
    int c = (unsigned char) *p;
    if (iscntrl(c)) {
      CRIT("Control character (0x%02x) in value of \"%s\"; rejected.", c, name);
      return -1;
    }
  }
  
  *dst = compat_protect_strdup(val);
  if (!*dst) {
    perror("compat_protect_strdup() failed");
    return -1;
  }
  return 0;
}

static int
options_set_user(options_t *options, const char *name, const char *val)
{
  options_check(options);
  RUNTIME_ASSERT(name);
  RUNTIME_ASSERT(val);
  
  if (options->user) {
    fprintf(stderr, "Multiple users specified");
    return -1;
  }

  if (!isalpha((unsigned char) val[0])) {
    fprintf(stderr, "Invalid user name\n");
    return -1;
  }
  
  return options_set_string(&options->user, name, val);
}

static int
options_set_group(options_t *options, const char *name, const char *val)
{
  options_check(options);
  RUNTIME_ASSERT(name);
  RUNTIME_ASSERT(val);
  
  if (options->group) {
    fprintf(stderr, "Multiple groups specified");
    return -1;
  }

  if (!isalpha((unsigned char) val[0])) {
    fprintf(stderr, "Invalid group name\n");
    return -1;
  }
  
  return options_set_string(&options->group, name, val);
}

static int
options_set_address(net_addr_t *addr_ptr, const char *name, const char *val,
    bool *has_ptr)
{
  char *endptr = NULL;
  net_addr_t addr;

  RUNTIME_ASSERT(addr_ptr);
  RUNTIME_ASSERT(name);
  RUNTIME_ASSERT(val);
  RUNTIME_ASSERT(has_ptr);

  if (*has_ptr) {
    CRIT("Multiple addresses specified for option \"%s\"", name);
    return -1;
  }
  
  if (!parse_net_addr(val, &addr, &endptr) || '\0' != *endptr) {
    CRIT("Invalid IPv4 address: \"%s\"", val);
    return -1;
  }

  *has_ptr = true;
  *addr_ptr = addr;
  return 0;
}

#define OPTIONS_SET_ADDRESS(option__) \
static int \
options_set_ ## option__(options_t *options, const char *name, const char *val) \
{ \
  options_check(options); \
  return options_set_address(&options->option__,  \
            name, val, &options->has_ ## option__); \
}

OPTIONS_SET_ADDRESS(listen_address)
OPTIONS_SET_ADDRESS(listen6_address)
OPTIONS_SET_ADDRESS(uhc_bind_address)
OPTIONS_SET_ADDRESS(uhc_bind6_address)
  
static int
options_set_port(uint16_t *port, const char *name, const char *val)
{
  char *endptr = NULL;
  uint64_t v;
  int error;

  RUNTIME_ASSERT(port != NULL);
  RUNTIME_ASSERT(name != NULL);
  RUNTIME_ASSERT(val != NULL);
  
  if (0 != *port) {
    CRIT("Multiple port values given for \"%s\"", name);
    return -1;
  }

  v = parse_uint64(val, &endptr, 10, &error);
  if (0 == v || v > 65535 || *endptr != '\0') {
    CRIT("Invalid port value for \"%s\": \"%s\"", name, val);
    return -1;
  }

  if (0 == strcmp(name, "uhc_port") && v < 1024) {
    CRIT("The port value of \"%s\" must be above 1023: \"%s\"", name, val);
    return -1;
  }

  *port = v;
  return 0;
}

#define OPTIONS_SET_PORT(option__) \
static int \
options_set_ ## option__(options_t *options, const char *name, const char *val)\
{ \
  options_check(options); \
  return options_set_port(&options->option__, name, val); \
}


OPTIONS_SET_PORT(listen_port)
OPTIONS_SET_PORT(uhc_port)
  
static int
options_set_location(options_t *options, const char *name, const char *val)
{
  char *url, *fqdn, *ret, *p;
  size_t fqdn_size;
  int res;

  options_check(options);
  RUNTIME_ASSERT(name != NULL);
  RUNTIME_ASSERT(val != NULL);

  if (
    options->gwc_fqdn ||
    options->gwc_url ||
    options->gwc_uri ||
    options->gwc_port
  ) {
    fprintf(stderr, "Multiple URLs specified");
    return -1;
  }

  if (strncmp(val, http_prefix, sizeof http_prefix - 1)) {
    WARN("Invalid %s: \"%s\"", name, val);
    return -1;
  }

  url = compat_strdup(val);
  if (!url) {
    perror("compat_strdup() failed");
    return -1;
  }
  fqdn_size = strlen(url); /* over-allocated */
  fqdn = malloc(fqdn_size);
  if (!fqdn) {
    perror("malloc() failed");
    return -1;
  }
  fqdn[0] = '\0'; /* Just in case the above isn't calloc() */

  ret = gwc_url_normalize(url, &res);
  if (!ret) {
    fprintf(stderr, "The specified URL isn't acceptable: %s\n",
        gwc_url_normalize_result(res));
    return -1;
  }
  if (ret != url) {
    DO_FREE(url);
    url = ret;
  }

  for (p = url; *p != '\0'; ++p)
    if (isupper((unsigned char) *p)) {
      fprintf(stderr,
          "Upper-case characters are not allowed in GWebCache URLs\n");
      return -1;
    }
  
  p = compat_protect_strdup(url);
  DO_FREE(url);
  if (!p) {
    perror("compat_protect_strdup() failed");
    return -1;
  }
  url = p;
  
  if (url_split(url, fqdn, fqdn_size,
        &options->gwc_port, (const char **) &options->gwc_uri)
  ) {
    fprintf(stderr, "The specified URL isn't accepted (\"%s\")\n", name);
    return -1;
  }
  if (options->gwc_port < 1) {
    fprintf(stderr, "Invalid port in URL (\"%s\")\n", name);
    return -1;
  }
  if (!url || options->gwc_uri[0] != '/') {
    fprintf(stderr, "The URL contains no valid path; "
        "a \"/\" is minimum (\"%s\")", name);
    return -1;
  }
  
  p = compat_protect_strdup(fqdn);
  DO_FREE(fqdn);
  if (!p) {
    perror("compat_protect_strdup() failed");
    return -1;
  }
  fqdn = p;
  
  options->gwc_fqdn = fqdn;
  options->gwc_url = url;
  options->gwc_url_hash = hash_str(url);

  /* TODO: Perform a DNS lookup to make sure it works and is correct(?),
   *      or rather let the checker verify it later(?) */

  return 0;
}

static int
options_set_uhc_hostname(options_t *options, const char *name, const char *val)
{
  char *fqdn, *p;

  options_check(options);
  RUNTIME_ASSERT(name != NULL);
  RUNTIME_ASSERT(val != NULL);

  if (options->uhc_hostname) {
    fprintf(stderr, "Multiple specifications of option \"%s\"", name);
    return -1;
  }

  if (strlen(val) < strlen("x.xx")) {
    CRIT("Hostname is too short in option \"%s\"", name);
    return -1;
  }
  if (!strchr(val, '.')) {
    CRIT("Please specify a fully-qualified domain name (\"%s\")", name);
    return -1;
  }
  
  fqdn = compat_strdup(val);
  if (!fqdn) {
    perror("calloc() failed");
    return -1;
  }

  p = http_parse_host(fqdn);
  if (!p || '\0' != *p) {
    CRIT("Hostname is invalid (\"%s\")", name);
    return -1;
  }
  if (parse_net_addr(fqdn, NULL, NULL)) {
    CRIT("The hostname must not be a numeric address (\"%s\")", name);
    return -1;
  }
  
  for (p = fqdn; *p != '\0'; ++p) {
    int c = (unsigned char) *p;
    if (isupper(c)) {
      *p = tolower(c);
    }
  }
  
  options->uhc_hostname = compat_strdup(fqdn);
  DO_FREE(fqdn);
  if (!options->uhc_hostname) {
    perror("compat_protect_strdup() failed");
    return -1;
  }

  return 0;
}

static int
options_set_abs_path(char **dst, const char *name, const char *val)
{
  char *buf;
  int ret;
  
  RUNTIME_ASSERT(dst);
  RUNTIME_ASSERT(name);
  RUNTIME_ASSERT(val);
  
  if (*dst) {
    CRIT("\"%s\" multiple times specified", name);
    return -1;
  }

  /* Translate ~user/path and ~/path to absolute paths. */
  if ('~' == val[0]) {
    const char *home_dir, *user_ptr, *slash_ptr;
    
    user_ptr = &val[1];
    slash_ptr = strchr(user_ptr, '/');
    if (!slash_ptr) {
      CRIT("Expected username or slash after tilde in value of \"%s\"",
        name);
      return -1;
    }
   
    if (slash_ptr == user_ptr) {
      home_dir = getenv("HOME");
      if (!home_dir) {
        const struct passwd *pw;
        
        pw = getpwuid(getuid());
        if (!pw) {
          CRIT("options_set_abs_path: getpwuid() failed");
          return -1;
        }
        home_dir = pw->pw_dir;
      }
    } else {
      const struct passwd *pw;
      char user_buf[256];
      size_t len;

      len = slash_ptr - user_ptr;
      if (len >= sizeof user_buf || '/' != user_ptr[len]) {
        CRIT("Username after tilde is too long");
        return -1;
      }
      strncpy(user_buf, user_ptr, len);
      user_buf[len] = '\0';

      pw = getpwnam(user_buf);
      if (!pw) {
        CRIT("options_set_abs_path: getpwnam() for user \"%s\" failed",
          user_buf);
        return -1;
      }
      home_dir = pw->pw_dir;
    }

    if (!home_dir) {
      CRIT("options_set_abs_path: home_dir is NULL");
      return -1;
    }
    
    buf = create_pathname(home_dir, &slash_ptr[1]);
    if (!buf) {
      CRIT("options_set_abs_path: getpathname() failed");
      return -1;
    }
    val = buf;
  } else {
    buf = NULL;
  }

  if ('/' != val[0]) {
    CRIT("\"%s\" must be an absolute path", name);
    return -1;
  }

  ret = options_set_string(dst, name, val);
  DO_FREE(buf);
  return ret;
}

static int
options_set_network_id(options_t *options, const char *name, const char *val)
{
  const char *p;
  char net[33], *q = net;
  
  options_check(options);
  RUNTIME_ASSERT(name != NULL);
  RUNTIME_ASSERT(val != NULL);
  
  if (options->network_id) {
    CRIT("\"network_id\" must not be specified more than once");
    return -1;
  }

  if (val[0] == '\0') {
    CRIT("\"network_id\" must be a non-empty string");
    return -1;
  }
  
  if (strlen(val) >= sizeof net) {
    CRIT("\"network_id\" must not exceed %u characters",
        (unsigned) sizeof net - 1);
    return -1;
  }
  
  for (p = val; *p != '\0'; p++) {
    static const char set[] = "+-./_";
    int c = (unsigned char) *p;

    if (!isalnum(c) && !strchr(set, c)) {
      fprintf(stderr, "Invalid character in \"network_id\"\n");
      return -1;
    }

    RUNTIME_ASSERT(q != &net[sizeof net - 1]);
    *q++ = tolower(c);
  }
  *q = '\0';
  
  return options_set_string(&options->network_id, name, net);
}

static int
options_set_data_key(options_t *options, const char *name, const char *val)
{
  const char *p;
  
  options_check(options);
  RUNTIME_ASSERT(name);
  RUNTIME_ASSERT(val);
  
  if (options->data_key) {
    fprintf(stderr, "\"data_key\" must not be specified more than once");
    return -1;
  }

  if (val[0] == '\0') {
    fprintf(stderr, "\"data_key\" must be a non-empty string");
    return -1;
  }
  
  for (p = val; *p != '\0'; p++) {
    if (!isalnum((unsigned char) *p)) {
      fprintf(stderr, "Invalid character in \"data_key\"\n");
      return -1;
    }
  }
  
  return options_set_string(&options->data_key, name, val);
}


#define OPTIONS_SET_PATH(option__) \
static int \
options_set_ ## option__(options_t *options, const char *name, const char *val)\
{ \
  options_check(options); \
  return options_set_abs_path(&options->option__, name, val); \
}


OPTIONS_SET_PATH(chroot_directory)
OPTIONS_SET_PATH(coredump_directory)
OPTIONS_SET_PATH(working_directory)
OPTIONS_SET_PATH(log_access)
OPTIONS_SET_PATH(log_alert)
OPTIONS_SET_PATH(log_checks)
OPTIONS_SET_PATH(log_dns)
OPTIONS_SET_PATH(log_main)
OPTIONS_SET_PATH(log_uhc)
OPTIONS_SET_PATH(peer_cache)
OPTIONS_SET_PATH(bad_url_cache)
OPTIONS_SET_PATH(good_url_cache)
OPTIONS_SET_PATH(address_filter)
OPTIONS_SET_PATH(data_template)
OPTIONS_SET_PATH(base_template)

static int
options_get_value(const char *s, uint64_t *value)
{
  char *ep = NULL;
  int error;
  uint64_t v;
  
  RUNTIME_ASSERT(s);
  RUNTIME_ASSERT(value);
  
  if (!isdigit((unsigned char) *s)) {
    CRIT("Expected a decimal number: \"%s\"", s);
    return -1;
  }
  v = parse_uint64(s, &ep, 10, &error);
  if (error || *ep != '\0') {
    CRIT("Invalid value: \"%s\"", s);
    return -1;
  }
  
  *value = v;
  return 0;
}

static int
options_get_long(const char *s, long *value)
{
  char *ep = NULL;
  long v;
  
  RUNTIME_ASSERT(s);
  RUNTIME_ASSERT(value);
  
  if (
    !isdigit((unsigned char) *s) &&
    (('-' != *s && '+' != *s) || !isdigit((unsigned char) s[1]))
  ) {
    CRIT("Expected a decimal number: \"%s\"", s);
    return -1;
  }

  errno = 0;
  v = strtol(s, &ep, 10);
  if (0 != errno || '\0' != *ep) {
    CRIT("Invalid value: \"%s\"", s);
    return -1;
  }
  
  *value = v;
  return 0;
}


static int
options_get_boolean(const char *name, const char *s, bool *value)
{
  RUNTIME_ASSERT(name);
  RUNTIME_ASSERT(s);
  RUNTIME_ASSERT(value);
 
  *value = false;
  if (!strcmp(s, "0") || !strcasecmp(s, "false")) {
    *value = false;
    return 0;
  } else if (!strcmp(s, "1") || !strcasecmp(s, "true")) {
    *value = true;
    return 0;
  }
 
  WARN("\"%s\" is not set to a boolean value: \"%s\"", name, s);
  return -1;
}

#define OPTIONS_SET_NUMBER(option__, min_val__, max_val__) \
static int \
options_set_ ## option__(options_t *options, const char *name, const char *val)\
{                                                                         \
  uint64_t v;                                                             \
  options_check(options);                                                 \
  if (options_get_value(val, &v))                                         \
        return -1;                                                        \
  if ((int64_t)v < min_val__ || v > max_val__) {                          \
    CRIT("%s is out of range: \"%s\"", name, val);                        \
    return -1;                                                            \
  }                                                                       \
  options->option__ = v;                                                  \
  return 0;                                                               \
}

#define OPTIONS_SET_LONG(option__, min_val__, max_val__) \
static int \
options_set_ ## option__(options_t *options, const char *name, const char *val)\
{                                                                         \
  long v;                                                                 \
  options_check(options);                                                 \
  if (options_get_long(val, &v))                                          \
        return -1;                                                        \
  if (v < min_val__ || v > max_val__) {                                   \
    CRIT("%s is out of range: \"%s\"", name, val);                        \
    return -1;                                                            \
  }                                                                       \
  options->option__ = v;                                                  \
  return 0;                                                               \
}


OPTIONS_SET_NUMBER(hostfile_lines, 1, MAX_PEERS_PER_REQ)
OPTIONS_SET_NUMBER(urlfile_lines, 1, MAX_GWCS_PER_REQ)
OPTIONS_SET_NUMBER(peers_per_get, 1, MAX_PEERS_PER_REQ)
OPTIONS_SET_NUMBER(gwcs_per_get, 1, MAX_GWCS_PER_REQ)
OPTIONS_SET_NUMBER(gwc_lock_time, 0, 24 * 3600)
OPTIONS_SET_NUMBER(uhc_lock_time, 0, 24 * 3600)
OPTIONS_SET_NUMBER(same_vendor_ratio, 0, 100)
OPTIONS_SET_NUMBER(max_connect_time, 1, 3600)
OPTIONS_SET_NUMBER(idle_timeout, 1, 3600)
OPTIONS_SET_NUMBER(url_check_delay, 0, (24 * 3600))
OPTIONS_SET_NUMBER(max_accepts_per_sec, 0, INT_MAX)
OPTIONS_SET_NUMBER(uhc_peers_per_pong, 1, MAX_PEERS_PER_REQ)
OPTIONS_SET_NUMBER(uhc_pongs_per_sec, 0, 1000)
OPTIONS_SET_NUMBER(listen_backlog, 1, 256)
OPTIONS_SET_NUMBER(tcp_defer_accept_timeout, 0, INT_MAX)
OPTIONS_SET_NUMBER(tcp_rcvbuf_size, 0, (64 * 1024))
OPTIONS_SET_NUMBER(tcp_sndbuf_size, 0, (64 * 1024))
OPTIONS_SET_NUMBER(udp_rcvbuf_size, 0, (4096 * 1024))
OPTIONS_SET_NUMBER(udp_sndbuf_size, 0, (64 * 1024))
OPTIONS_SET_NUMBER(url_check_max_size, 128, (128 * 1024))
OPTIONS_SET_NUMBER(request_max_size, 128, (64 * 1024))
OPTIONS_SET_NUMBER(max_cached_peers, 100, 1000000)

OPTIONS_SET_LONG(priority, COMPAT_MIN_PRIORITY, COMPAT_MAX_PRIORITY)

static int
options_generic_set_bool(options_t *options, const char *name, const char *val,
    bool *option)
{
  options_check(options);
  RUNTIME_ASSERT(name);
  RUNTIME_ASSERT(val);
  RUNTIME_ASSERT(option);

  if (options_get_boolean(name, val, option))
    return -1;

  return 0; 
}

#define OPTIONS_SET_BOOL(option__) \
static int \
options_set_ ## option__(options_t *options, const char *name, const char *val)\
{ \
  options_check(options); \
  return options_generic_set_bool(options, name, val, &options->option__); \
}

OPTIONS_SET_BOOL(support_gwc)
OPTIONS_SET_BOOL(support_uhc)
OPTIONS_SET_BOOL(support_v2)
OPTIONS_SET_BOOL(expose_sysname)
OPTIONS_SET_BOOL(pause_on_crash)
OPTIONS_SET_BOOL(daemonize)
OPTIONS_SET_BOOL(allow_anonymous)
OPTIONS_SET_BOOL(auto_discovery)
OPTIONS_SET_BOOL(ban_bad_vendors)
OPTIONS_SET_BOOL(http_dump_headers)
OPTIONS_SET_BOOL(send_x_remote_ip)
OPTIONS_SET_BOOL(send_x_gwc_url)
OPTIONS_SET_BOOL(send_from_header)
OPTIONS_SET_BOOL(url_check_strict)
OPTIONS_SET_BOOL(url_check_allow_dupes)
OPTIONS_SET_BOOL(late_filter)

#define OPTIONS_SET_STRING(option__) \
static int \
options_set_ ## option__(options_t *options, const char *name, const char *val)\
{ \
  options_check(options); \
  return options_set_string(&options->option__, name, val); \
}

OPTIONS_SET_STRING(contact_address)
  
typedef  int (* options_handler_t) (options_t *, const char *, const char *);

static const struct {
  const char        *name;
  options_handler_t  func;
} options_handlers[] = {
#define OPTION_SET(x) { STRINGIFY(x), options_set_ ## x }

  /* Generic options */
  OPTION_SET(user),
  OPTION_SET(group),
  OPTION_SET(chroot_directory),
  OPTION_SET(coredump_directory),
  OPTION_SET(working_directory),
  OPTION_SET(daemonize),
  OPTION_SET(priority),
  OPTION_SET(log_access),
  OPTION_SET(log_alert),
  OPTION_SET(log_checks),
  OPTION_SET(log_dns),
  OPTION_SET(log_main),
  OPTION_SET(log_uhc),
  OPTION_SET(peer_cache),
  OPTION_SET(address_filter),
  OPTION_SET(late_filter),
  OPTION_SET(max_cached_peers),
  OPTION_SET(same_vendor_ratio),
  
  /* GWebCache related options */
  OPTION_SET(support_gwc),
  OPTION_SET(location),
  OPTION_SET(listen_address),
  OPTION_SET(listen6_address),
  OPTION_SET(listen_port),
  OPTION_SET(listen_backlog),
  OPTION_SET(bad_url_cache),
  OPTION_SET(good_url_cache),
  OPTION_SET(urlfile_lines),
  OPTION_SET(hostfile_lines),
  OPTION_SET(peers_per_get),
  OPTION_SET(gwcs_per_get),
  OPTION_SET(gwc_lock_time),
  OPTION_SET(max_connect_time),
  OPTION_SET(idle_timeout),
  OPTION_SET(url_check_delay),
  OPTION_SET(support_v2),
  OPTION_SET(expose_sysname),
  OPTION_SET(pause_on_crash),
  OPTION_SET(max_accepts_per_sec),
  OPTION_SET(allow_anonymous),
  OPTION_SET(auto_discovery),
  OPTION_SET(ban_bad_vendors),
  OPTION_SET(tcp_defer_accept_timeout),
  OPTION_SET(tcp_rcvbuf_size),
  OPTION_SET(tcp_sndbuf_size),
  OPTION_SET(url_check_max_size),
  OPTION_SET(request_max_size),
  OPTION_SET(http_dump_headers),
  OPTION_SET(send_x_remote_ip),
  OPTION_SET(send_x_gwc_url),
  OPTION_SET(send_from_header),
  OPTION_SET(url_check_strict),
  OPTION_SET(url_check_allow_dupes),
  OPTION_SET(network_id),
  OPTION_SET(data_key),
  OPTION_SET(data_template),
  OPTION_SET(base_template),
  OPTION_SET(contact_address),
  
  /* UHC related options */
  OPTION_SET(support_uhc),
  OPTION_SET(uhc_hostname),
  OPTION_SET(uhc_port),
  OPTION_SET(uhc_bind_address),
  OPTION_SET(uhc_bind6_address),
  OPTION_SET(uhc_peers_per_pong),
  OPTION_SET(uhc_pongs_per_sec),
  OPTION_SET(uhc_lock_time),
  OPTION_SET(udp_rcvbuf_size),
  OPTION_SET(udp_sndbuf_size),
};

/**
 * Unescapes the given token in-place. A single slash '\' escapes the next
 * character, this is useful to escape a '"' or ':'. Escaping NUL characters
 * is not allowed. A double-quote '"' escapes all characters up to the next
 * double-quote except slashes. This is especially useful for IPv6 addresses.
 * Escaping NUL characters or non-closed * double-quotes cause a failure. Empty
 * quoted strings ("") are tolerated.
 *
 * @return -1 on failure and 0 on success. 
 */
int
unescape_token(char *token)
{
  const char *p;
  char *q;
  bool quoted = false;

  q = token;
  for (p = token; '\0' != *p; p++) {
    if ('\\' == *p) {
      p++;
      if ('\0' == *p)
        return -1;
    } else if ('"' == *p) {
      quoted = !quoted;
      if ('\0' == *p) {
        break;
      }
      continue;
    }
    *q++ = *p;
  }
  *q = '\0';

  return quoted ? -1 : 0;
}

/**
 * Finds the next non-escaped/quoted space (token separator) and replaces
 * it with a NUL character.
 *
 * @return  NULL if no token separator was found or a pointer to start of
 *          the next token.
 */
char *
separate_token(char * const token)
{
  bool esc = false, quoted = false;
  char *p;
 
  for (p = token; p != NULL; p++) {
    if ('\0' == *p) {
      if (esc || quoted) {
        p = NULL; /* Quoting or escaping NUL is invalid */
      }
      break;
    } else if (esc) {
      esc = false;
      continue;
    } else if (isspace((unsigned char) *p)) {
      if (!quoted)
        break;
    } else if ('"' == *p) {
      quoted = !quoted;
    } else if ('\\' == *p) {
      esc = true;
    }
  }

  if (p && '\0' != *p) {
    *p = '\0';
    p = skip_spaces(&p[1]);
  }

  return p;
}

/**
 * Extracts the next token from the given string 'line'. The token is
 * unescaped and terminated with a NUL character.
 *
 * @return NULL on failure or a pointer to the start of the extracted token.
 */
char *
get_token(char * const line, char **endptr)
{
  char *ep;
  
  ep = separate_token(line);
  if (endptr) {
    *endptr = ep;
  }
  if (!ep) {
    WARN("Non-terminated token");
    return NULL;
  }
  if (0 != unescape_token(line)) {
    WARN("Badly escaped token");
    return NULL;
  }
  return line;
}

static int
options_process_setting(options_t *options, const char *name, const char *value)
{
  options_handler_t func;
  size_t i;

  options_check(options);
  RUNTIME_ASSERT(name);
  RUNTIME_ASSERT(value);

  func = NULL;
  for (i = 0; i < ARRAY_LEN(options_handlers); i++) {
    if (!strcasecmp(name, options_handlers[i].name)) {
      func = options_handlers[i].func;
      break;
    }
  }

  if (!func) {
    WARN("Unknown setting \"%s\"", name);
    return -1;
  }

  if (func(options, name, value)) {
    return -1;
  }

  return 0;
}
 
int
options_load(const char *pathname)
{
  unsigned int line_number;
  FILE *f = NULL;
  options_t options;
  char line[4096];

  RUNTIME_ASSERT(pathname);
  RUNTIME_ASSERT(!global_options);
  
  options = global_default_options;
  options_check(&options);

  f = safer_fopen(pathname, SAFER_FOPEN_RD);
  if (!f) {
    WARN("Could not open \"%s\": %s", pathname, compat_strerror(errno));
    goto failure;
  }

  for (line_number = 1; fgets(line, sizeof line, f); line_number++) {
    const char *name, *value;
    char *ep;

    ep = strchr(line, '\n');
    if (!ep) {
      CRIT("Non-terminated or overlong line in configuration file (%u)",
        line_number);
      goto failure;
    }
    *ep = '\0';

    ep = skip_spaces(line);
    /* Ignore comments and empty lines */
    if ('#' == ep[0] || '\0' == ep[0]) {
      continue;
    }

    /* Skip all non-spaces */
    ep = line;
    while ('\0' != ep[0] && !isspace((unsigned char) ep[0])) {
      ep++;
    }

    if ('#' == ep[0] || '\0' == ep[0]) {
      *ep = '\0';
      WARN("Line %u: Missing value for setting \"%s\"", line_number, line);
      goto failure;
    }

    /* Separate the name of the setting */
    name = line;
    *ep = '\0';

    ep = skip_spaces(&ep[1]);
    value = get_token(ep, &ep);
    if (!value) {
      WARN("Line %u: Cannot parse value of setting \"%s\"", line_number, name);
      goto failure;
    }
    if ('\0' == value[0]) {
      WARN("Line %u: Empty value for setting \"%s\"", line_number, name);
      goto failure;
    }

    if ('\0' != ep[0] && '#' != ep[0]) {
      WARN("Line %u: Extra data after value: \"%s\"", line_number, ep);
      goto failure;
    }

    if (0 != options_process_setting(&options, name, value)) {
      goto failure;
    }
  }
 
  if (options.support_gwc) {
    if (!options.listen_port)
      options.listen_port = options.gwc_port;

    if (!options.has_listen_address && !options.has_listen6_address) {
      options.listen_address = net_addr_set_ipv4(INADDR_ANY);
      options.has_listen_address = true;

#ifdef HAVE_IPV6_SUPPORT
      options.listen6_address = net_addr_unspecified;
      options.has_listen6_address = true;
#endif /* HAVE_IPV6_SUPPORT */
    }
  }

  if (options.support_uhc) {
    if (!options.has_uhc_bind_address && !options.has_uhc_bind6_address) {
      options.uhc_bind_address = net_addr_set_ipv4(INADDR_ANY);
      options.has_uhc_bind_address = true;
      
#ifdef HAVE_IPV6_SUPPORT
      options.uhc_bind6_address = net_addr_unspecified;
      options.has_uhc_bind6_address = true;
#endif /* HAVE_IPV6_SUPPORT */
    }
  }

  if (!options.log_main) {
    options.log_main = compat_protect_strdup(DEV_NULL);
  }
  if (!options.log_dns) {
    options.log_dns = compat_protect_strdup(DEV_NULL);
  }

  global_options = compat_protect_memdup(&options, sizeof options);
  fclose(f);
  return 0;

failure:
 
  if (f) {
    fclose(f);
    f = NULL;
  }

#if 0
  /* XXX: These strings are mapped read-only, so the memory can't just be
   *      free()ed. */
  DO_FREE(options.base_template);
  DO_FREE(options.data_template);
  DO_FREE(options.data_key);
  DO_FREE(options.network_id);
  DO_FREE(options.chroot_directory);
  DO_FREE(options.coredump_directory);
  DO_FREE(options.working_directory);
  DO_FREE(options.log_main);
  DO_FREE(options.log_dns);
  DO_FREE(options.log_checks);
  DO_FREE(options.peer_cache);
  DO_FREE(options.bad_url_cache);
  DO_FREE(options.good_url_cache);
  DO_FREE(options.address_filter);
  DO_FREE(options.user);
  DO_FREE(options.group);
#endif
  memset(&options, 0, sizeof options);
  
  return -1;
}

/* vi: set ai et sts=2 sw=2 cindent: */
