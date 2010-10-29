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

#include <pwd.h>
#include <grp.h>

#include "lib/oop.h"
#include "lib/http.h"
#include "lib/filter.h"
#include "lib/event_watcher.h"
#include "lib/fifo.h"
#include "lib/nettools.h"
#include "lib/append.h"
#include "lib/acclog.h"

#include "options.h"
#include "webcache.h"
#include "dnshelper.h"

#if 0 
#include "bintree.h"

int
main(void)
{
  bintree_test();
  return 0;
}

#else

static ev_watcher_t *watcher;
static connection_t *listen_con, *listen6_con, *udp_con, *udp6_con;

static inline const options_t *
opts_(void)
{
  static const options_t *options;

  if (!options) {
    options = options_get();
  }
  return options;
}
#define OPTION(x) (opts_()->x)

static const struct {
  const char *desc;
  int signo;
} fatal_sigs[] = {
#ifdef HAVE_SIGBUS
  { "SIGBUS",   SIGBUS  },
#endif /* SIGBUS */
  { "SIGFPE",   SIGFPE  },
  { "SIGILL",   SIGILL  },
  { "SIGSEGV",  SIGSEGV },
#ifdef HAVE_SIGSYS
  { "SIGSYS",   SIGSYS  },
#endif /* SIGSYS */
  { "SIGABRT",  SIGABRT }
};

static void
fatalsig_handler_dump(int signo)
{
  char buf[64] = "\n", *p = buf;
  const char *cause = "CRASH";
  size_t i;

  for (i = 0; i < ARRAY_LEN(fatal_sigs); i++) {
    set_signal(fatal_sigs[i].signo, SIG_DFL);
    if (signo == fatal_sigs[i].signo)
      cause = fatal_sigs[i].desc;
  }

  *p++ = '\n';
  while (cause && *cause != '\0' && p != &buf[sizeof buf - 1]) {
    *p++ = *cause++;
  }
  *p++ = '\n';
  
  (void) write(STDERR_FILENO, buf, p - buf);
  if (OPTION(coredump_directory)) {
    if (chdir(OPTION(coredump_directory))) {
      static const char msg[] = "chdir() failed\n";

      (void) write(STDERR_FILENO, msg, sizeof msg - 1);
      _exit(EXIT_FAILURE);
    }
  }
  
  abort();
  /* NOT REACHED */
  _exit(EXIT_FAILURE);
}

static void
fatalsig_handler_pause(int signo)
{
  sigset_t oset;
  size_t i;

  (void) signo;
  
  sigprocmask(SIG_BLOCK, NULL, &oset);
  sigsuspend(&oset);

  for (i = 0; i < ARRAY_LEN(fatal_sigs); i++) {
    set_signal(fatal_sigs[i].signo, SIG_DFL);
  }

  _exit(EXIT_FAILURE);
}


static void
fatal_sigs_setup(void)
{
  size_t i;
  void (* handler)(int);

  if (OPTION(coredump_directory)) {
    struct rlimit lim;

    RUNTIME_ASSERT(OPTION(coredump_directory)[0] == '/');

    if (getrlimit(RLIMIT_CORE, &lim)) {
      CRIT("getrlimit(RLIMIT_CORE, &lim) failed: %s", compat_strerror(errno));
      exit(EXIT_FAILURE);
    }
    if (lim.rlim_cur == 0 || lim.rlim_max == 0) {
      WARN("Option \"coredump_directory\" is set but coredumps are disabled");
    } else if (lim.rlim_cur != RLIM_INFINITY && lim.rlim_cur < 1024 * 1024) {
      WARN("Option \"coredump_directory\" is set but the soft limit for the "
          "size of coredumps is very low: %" PRIu64, (uint64_t) lim.rlim_cur);
    } else if (lim.rlim_max != RLIM_INFINITY && lim.rlim_max < 1024 * 1024) {
      WARN("Option \"coredump_directory\" is set but the hard limit for the "
          "size of coredumps is very low: %" PRIu64, (uint64_t) lim.rlim_max);
    }
  } else {
    if (compat_disable_coredumps()) {
      exit(EXIT_FAILURE);
    }
  }
  
  handler = OPTION(pause_on_crash)
    ? fatalsig_handler_pause : fatalsig_handler_dump;
    
  for (i = 0; i < ARRAY_LEN(fatal_sigs); i++)
    if (SIG_ERR == (set_signal(fatal_sigs[i].signo, handler))) {
      fprintf(stderr, "Cannot set up signal handler for %s: %s\n",
         fatal_sigs[i].desc, compat_strerror(errno));
      exit(EXIT_FAILURE);
    }
}

static int
reopen_logs(void)
{
  if (!freopen(OPTION(log_main), "a", stderr))
    return -1;

  if (webcache_reopen_logs()) {
    CRIT("webcache_reopen_logs() failed: \"%s\"", compat_strerror(errno));
    return -1;
  }
  
  return 0;
}

static void
usage(void)
{
  printf(
    "Usage: gwc -h\n"
    "       gwc -f FILE\n");

  printf(
    "\n-f FILE\n"
    "\tFILE is the absolute pathname of the configuration file.\n");
  
  printf(
    "\n-h\n"
    "\tShow this usage information.\n");
}

static int
process_args(int argc, char ** const argv)
{
  char *cfg_pathname = NULL;
  int c;
 
  RUNTIME_ASSERT(argc > 0);
  RUNTIME_ASSERT(argv);
  
  while ((c = getopt(argc, argv, "hf:")) != -1) {
    switch (c) {
    case 'h':
      usage();
      exit(EXIT_SUCCESS);
      break;

    case 'f':
      if (cfg_pathname) {
        fprintf(stderr, "Multiple use of -f.\n");
        usage();
        exit(EXIT_SUCCESS);
      }
      if (*optarg != '/') {
        fprintf(stderr, "Use -f with an absolute pathname.\n");
        usage();
        exit(EXIT_SUCCESS);
      }
      cfg_pathname = compat_strdup(optarg);
      if (!cfg_pathname) {
        fprintf(stderr, "compat_strdup() failed\n");
        exit(EXIT_SUCCESS);
      }
      break;
     
    default:
      usage();
      exit(EXIT_FAILURE);
    }
  }

  if (!cfg_pathname) {
    usage();
    exit(EXIT_FAILURE);
  }

  if (options_load(cfg_pathname)) {
    CRIT("options_load() failed");
    exit(EXIT_FAILURE);
  }
  DO_FREE(cfg_pathname);

  return 0;
}

int
apply_options(void)
{
  struct group *gr = NULL;
  uid_t uid = (uid_t) -1;
  gid_t gid = (gid_t) -1;
  
  if (!OPTION(support_gwc) && !OPTION(support_uhc)) {
    fprintf(stderr,
      "You must enable \"support_gwc\" or \"support_uhc\"\n");
    return -1;
  }
    
  if (!OPTION(peer_cache)) {
    fprintf(stderr, "No \"peer_cache\" specified(?)\n");
    return -1;
  }
  
  if (OPTION(support_gwc)) {

    if (
      !OPTION(gwc_port) ||
      !OPTION(gwc_url) ||
      !OPTION(gwc_uri) ||
      !OPTION(gwc_fqdn)
    ) {
      fprintf(stderr, "No URL specified(?); "
        "use \"location\" and specify an URL to serve\n");
      return -1;
    }

    if (!OPTION(good_url_cache)) {
      fprintf(stderr, "No \"good_url_cache\" specified(?)\n");
      return -1;
    }
    if (!OPTION(bad_url_cache)) {
      fprintf(stderr, "No \"bad_url_cache\" specified(?)\n");
      return -1;
    }
    if (
        0 == strcmp(OPTION(peer_cache), OPTION(good_url_cache)) ||
        0 == strcmp(OPTION(peer_cache), OPTION(bad_url_cache)) ||
        0 == strcmp(OPTION(good_url_cache), OPTION(bad_url_cache))
    ) {
      fprintf(stderr, "You must use different files for caches!\n");
      return -1;
    }
  }
  
  if (OPTION(user)) {
    const struct passwd *pw;

    errno = 0;
    pw = getpwnam(OPTION(user));
    if (!pw) {
      fprintf(stderr, "getpwnam(\"%s\") failed: %s\n", OPTION(user),
          errno ? compat_strerror(errno) : "No such user(?)");
      return -1;
    }
  
    uid = pw->pw_uid;
    if (!uid) {
      fprintf(stderr, "Running as super-user is unacceptable!\n");
      return -1;
    } else if (uid == (uid_t) -1) {
      fprintf(stderr, "User %s has no valid UID!", OPTION(user));
      return -1;
    }
  }

  if (OPTION(group)) {
    errno = 0;
    gr = getgrnam(OPTION(group));
    if (!gr) {
      fprintf(stderr, "getgrnam(\"%s\") failed: %s\n", OPTION(group), 
          errno ? compat_strerror(errno) : "No such group(?)");
      return -1;
    }
    gid = gr->gr_gid;
    if (gid == (gid_t) -1) {
      perror("Group has no valid GID!");
      return -1;
    }
  }

  /***
   *** BEGIN OF SECTION PRIVILEGED SECTION
   ***/
 
  if (OPTION(support_gwc)) {
    
    /* Open socket while being privileged so we can bind a TCP port below 1024
     */
   
    if (OPTION(has_listen_address)) {
      listen_con = connection_listen(OPTION(listen_address),
                        OPTION(listen_port), OPTION(listen_backlog));

      if (!listen_con) {
        FATAL("connection_listen() failed: %s", compat_strerror(errno));
        exit(EXIT_FAILURE);
      }
    }

    if (OPTION(has_listen6_address)) {
      listen6_con = connection_listen(OPTION(listen6_address),
                        OPTION(listen_port), OPTION(listen_backlog));

      if (!listen6_con) {
        FATAL("connection_listen() failed: %s", compat_strerror(errno));
        exit(EXIT_FAILURE);
      }
    }

  }

  if (OPTION(support_uhc)) {

    if (!OPTION(uhc_port)) {
      FATAL("UHC support enabled but \"uhc_port\" is not configured");
      exit(EXIT_FAILURE);
    }
    
    /* Open socket while being privileged so we can bind a
     * UDP port below 1024 */
      
    if (OPTION(has_uhc_bind_address)) {
      udp_con = connection_udp(OPTION(uhc_bind_address), OPTION(uhc_port));
      if (!udp_con) {
        FATAL("connection_udp() failed: %s", compat_strerror(errno));
        exit(EXIT_FAILURE);
      }
    }
    
    if (OPTION(has_uhc_bind6_address)) {
      udp6_con = connection_udp(OPTION(uhc_bind6_address), OPTION(uhc_port));
      if (!udp6_con) {
        FATAL("connection_udp() failed: %s", compat_strerror(errno));
        exit(EXIT_FAILURE);
      }
    }

  }

  if (0 != OPTION(priority)) {
    if (setpriority(PRIO_PROCESS, getpid(), OPTION(priority))) {
      FATAL("setpriority(PRIO_PROCESS, ..., %d) failed: %s",
        (int) OPTION(priority), compat_strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  /* Now change the root directory */
  if (OPTION(chroot_directory) && compat_chroot(OPTION(chroot_directory))) {
    exit(EXIT_FAILURE);
  }
  

  /***
   *** END OF SECTION
   ***/
  
  /* Drop privileges now! */

  /* This is too important to be an assertion which might be compiled away */
  if (!uid) {
    FATAL("config.uid == 0");
    exit(EXIT_FAILURE);
  }
  
  if (!getuid() && uid == (uid_t) -1) {
    fprintf(stderr, "Running as super-user is unacceptable!\n");
    exit(EXIT_FAILURE);
  }
 
  if (gid != (gid_t) -1) {
    RUNTIME_ASSERT(OPTION(group));
    if (setgid(gid) || getgid() != gid) {
      fprintf(stderr, "setgid(%lu) failed: %s\n", (unsigned long) gid,
        compat_strerror(errno));
      exit(EXIT_FAILURE);
    }
  } else {
    RUNTIME_ASSERT(!OPTION(group));
  }
  
  if (uid != (uid_t) -1) {
    
    RUNTIME_ASSERT(OPTION(user));

    if (gid == (gid_t) -1) {
      struct passwd *pw;
      char login[1024];
      size_t size = sizeof login;

      RUNTIME_ASSERT(!OPTION(group));
      
      pw = getpwuid(uid);
      if (!pw) {
        fprintf(stderr, "getpwuid(%lu) failed\n", (unsigned long) pw);
        exit(EXIT_FAILURE);
      }
      gid = pw->pw_gid;

      append_string(login, &size, pw->pw_name);
      if (!size) {
        FATAL("The buffer login[] is too small");
        exit(EXIT_FAILURE);
      }
      if (strcmp(login, pw->pw_name)) {
        FATAL("Buy ECC RAM");
        exit(EXIT_FAILURE);
      }
  
      /* initgroups is a privileged operation, for unprivileged users only
       * setgid() is used. */

      if (!getuid() && initgroups(login, gid)) {
        FATAL("initgroups(%s, %lu) failed: %s", login, (unsigned long) gid,
            compat_strerror(errno));
        exit(EXIT_FAILURE);
      }
      
    } else {
      gid_t gidset[1];
    
      RUNTIME_ASSERT(OPTION(group));
      if (!getuid()) {
        /* setgroups is a privileged operation, for unprivileged users only
         * setgid() is used. */
        
        gidset[0] = gid;
        if (setgroups(ARRAY_LEN(gidset), gidset)) {
          fprintf(stderr, "setgroups(1, {%lu}) failed: %s\n",
            (unsigned long) gidset[0], compat_strerror(errno));
          exit(EXIT_FAILURE);
        }
      }
      
    }
   
    if (setgid(gid) || getgid() != gid) {
      FATAL("setgid(%lu) failed: %s",
        (unsigned long) gid, compat_strerror(errno));
      exit(EXIT_FAILURE);
    }
    
    if (setuid(uid) || getuid() != uid || !getuid()) {
      fprintf(stderr, "setuid(%lu) failed: %s\n", (unsigned long) uid,
        compat_strerror(errno));
      exit(EXIT_FAILURE);
    }
  }
  
  if (!getuid() || !geteuid()) {
    FATAL("Still running as super-user!?!?");
    exit(EXIT_FAILURE);
  }
  
  fatal_sigs_setup();

  http_set_useragent(GWC_USER_AGENT);

#ifdef HAVE_UNAME
  if (OPTION(expose_sysname)) {
    struct utsname name;
    
    if (uname(&name) != -1) {
      size_t size;
      char *ua;
      
      size = (sizeof GWC_USER_AGENT) - 1 + strlen(name.sysname) + sizeof " ()";
      ua = calloc(1, size);

      /* XXX: Make sure the sysname isn't too long and doesn't mess with HTTP */
      if (ua) {
        char *p;
        
        p = ua;
        p = append_string(p, &size, GWC_USER_AGENT);
        p = append_string(p, &size, " ("); 
        p = append_string(p, &size, name.sysname);
        p = append_string(p, &size, ")");
        http_set_useragent(ua);
        DO_FREE(ua);
      } else {
        CRIT("calloc() failed: %s", compat_strerror(errno));
      }
    } else {
      WARN("uname() failed: %s", compat_strerror(errno));
    }
  }
#endif /* HAVE_UNAME */
  return 0;
}

static void
print_options(void)
{
  const char *user;
  const char *group;
  uid_t uid = getuid();
  gid_t gid = getgid();

  RUNTIME_ASSERT(uid != 0);
  RUNTIME_ASSERT(uid == geteuid());
  RUNTIME_ASSERT(!OPTION(chroot_directory) || OPTION(chroot_directory)[0] == '/');
  
  if (OPTION(user)) {
    user = OPTION(user);
  } else {
    const struct passwd *pw;
    
    pw = getpwuid(uid);
    if (!pw) {
      fprintf(stderr, "getpwuid(%lu) failed\n", (unsigned long) uid);
      exit(EXIT_FAILURE);
    }
    RUNTIME_ASSERT(uid == pw->pw_uid);
    user = pw->pw_name;
  }
  
  if (OPTION(group)) {
    group = OPTION(group);
  } else {
    const struct group *gr;

    gr = getgrgid(gid);
    if (!gr) {
      fprintf(stderr, "getpwuid(%lu) failed\n", (unsigned long) gid);
      exit(EXIT_FAILURE);
    }
    group = gr->gr_name;
    RUNTIME_ASSERT(gid == gr->gr_gid);
  }
  RUNTIME_ASSERT(user);
  RUNTIME_ASSERT(group);
    
  INFO("\n"
    "Using the following configuration:\n"
    "----------------------------------\n"
    "User:  \"%s\" (uid=%lu, euid=%lu)\n"
    "Group: \"%s\" (gid=%lu, egid=%lu)\n"
    "Changed root directory: %s%s%s\n"
    "Coredump directory: %s%s%s\n",
    user,
    (unsigned long) getuid(),
    (unsigned long) geteuid(),
    group,
    (unsigned long) getgid(),
    (unsigned long) getegid(),
    OPTION(chroot_directory) ? "\"" : "<",
    OPTION(chroot_directory) ? OPTION(chroot_directory) : "none",
    OPTION(chroot_directory) ? "\"" : ">",
    OPTION(coredump_directory) ? "\"" : "<",
    OPTION(coredump_directory) ? OPTION(coredump_directory) : "none",
    OPTION(coredump_directory) ? "\"" : ">"
  );

  if (OPTION(support_gwc)) {
    char addr_buf[NET_ADDR_BUFLEN];
    char addr6_buf[NET_ADDR_BUFLEN];
    
    print_net_addr(addr_buf, sizeof addr_buf, OPTION(listen_address));
    print_net_addr(addr6_buf, sizeof addr6_buf, OPTION(listen6_address));
    INFO("\n"
      "GWebCache options:\n"
      "----------------------------------\n"
      "Listen address (IPv4): %s%s%s\n"
      "Listen address (IPv6): %s%s%s\n"
      "Listen port: %u\n"
      "GWC URL:  \"%s\"\n"
      "GWC FQDN: \"%s\"\n"
      "GWC port: %u\n"
      "GWC URI:  \"%s\"\n"
      "----------------------------------",
      OPTION(has_listen_address) ? "\"" : "",
      OPTION(has_listen_address) ? addr_buf : "<none>",
      OPTION(has_listen_address) ? "\"" : "",
      OPTION(has_listen6_address) ? "\"" : "",
      OPTION(has_listen6_address) ? addr6_buf : "<none>",
      OPTION(has_listen6_address) ? "\"" : "",
      (unsigned int) OPTION(listen_port),
      OPTION(gwc_url),
      OPTION(gwc_fqdn),
      (unsigned int) OPTION(gwc_port),
      OPTION(gwc_uri));
  }
  
  if (OPTION(support_uhc)) {
    char addr_buf[NET_ADDR_BUFLEN];
    char addr6_buf[NET_ADDR_BUFLEN];
    
    print_net_addr(addr_buf, sizeof addr_buf, OPTION(uhc_bind_address));
    print_net_addr(addr6_buf, sizeof addr6_buf, OPTION(uhc_bind6_address));
    INFO("\n"
      "UDP Hostcache options:\n"
      "----------------------------------\n"
      "UHC hostname: %s%s%s\n"
      "UHC port:     %u\n"
      "UHC bind address (IPv4): %s%s%s\n"
      "UHC bind address (IPv6): %s%s%s\n"
      "----------------------------------",
      OPTION(uhc_hostname) ? "\"" : "",
      OPTION(uhc_hostname) ? OPTION(uhc_hostname) : "<none>",
      OPTION(uhc_hostname) ? "\"" : "",
      (unsigned int) OPTION(uhc_port),
      OPTION(has_uhc_bind_address) ? "\"" : "",
      OPTION(has_uhc_bind_address) ? addr_buf : "<none>",
      OPTION(has_uhc_bind_address) ? "\"" : "",
      OPTION(has_uhc_bind6_address) ? "\"" : "",
      OPTION(has_uhc_bind6_address) ? addr6_buf : "<none>",
      OPTION(has_uhc_bind6_address) ? "\"" : ""
    );
  }

}

static void
initialize(ev_watcher_t *w, int query_fd, int reply_fd)
{
  static bool was_here = false;

  RUNTIME_ASSERT(!was_here);
  was_here = true;
  RUNTIME_ASSERT(w != NULL);

  print_options();

  if (
    webcache_init(w,
      listen_con, listen6_con,
      udp_con, udp6_con,
      query_fd, reply_fd)
  ) {
    CRIT("webcache_init() failed");
    exit(EXIT_FAILURE);
  }
 
}

pid_t
dns_helper_launch(int *query, int *reply)
{
  pid_t pid;
  int ret;
  int query_fd[2] = { -1, -1 };
  int reply_fd[2] = { -1, -1 };
 
  *query = -1;
  *reply = -1;
  
  if (SIG_ERR == set_signal(SIGCHLD, SIG_IGN)) {
    CRIT("set_signal(SIGCHLD, SIG_IGN) failed: %s", compat_strerror(errno));
    return -1;
  }

  ret = pipe(query_fd);
  if (ret) {
    CRIT("1st pipe() failed: %s", compat_strerror(errno));
    return -1;
  }
  
  ret = pipe(reply_fd);
  if (ret) {
    CRIT("2nd pipe() failed: %s", compat_strerror(errno));
    return -1;
  }

#if !defined(HAVE_PTHREAD_SUPPORT)
  fflush(NULL);
  pid = fork();
  if ((pid_t) -1 == pid) {
    CRIT("fork() failed");
    return -1;
  }
  
  if (compat_disable_fork()) {
    _exit(EXIT_FAILURE);
  }

  if (!pid) {

    /* Destroy the listening TCP socket, the DNS helper has no business
     * with it */
    if (listen_con) {
      void *ctx;
      
      connection_close(listen_con);
      ctx = connection_get_context(listen_con);
      RUNTIME_ASSERT(!ctx);
      connection_unref(listen_con);
    }
    if (listen6_con) {
      void *ctx;
      
      connection_close(listen6_con);
      ctx = connection_get_context(listen6_con);
      RUNTIME_ASSERT(!ctx);
      connection_unref(listen6_con);
    }
    
    /* Destroy the UDP socket (for the UHC part), the DNS helper has no
     * business with it */
    if (udp_con) {
      void *ctx;
      
      connection_close(udp_con);
      ctx = connection_get_context(udp_con);
      RUNTIME_ASSERT(!ctx);
      connection_unref(udp_con);
    }
    if (udp6_con) {
      void *ctx;
      
      connection_close(udp6_con);
      ctx = connection_get_context(udp6_con);
      RUNTIME_ASSERT(!ctx);
      connection_unref(udp6_con);
    }
     
    /* Re-assign the pipe descriptors to the lowest available descriptors */
    close(query_fd[1]);
    ret = fcntl(query_fd[0], F_DUPFD, 0);
    close(query_fd[0]);
    query_fd[0] = ret;
    
    close(reply_fd[0]);
    ret = fcntl(reply_fd[1], F_DUPFD, 0);
    close(reply_fd[1]);
    reply_fd[1] = ret;

    /* Signal handlers are not inherited, so this has to be done again */
    fatal_sigs_setup();

#ifdef HAVE_SETPROCTITLE
    /* The BSD version uses printf-style arguments, the Linux one accepts
     * only a string as argument. */
    setproctitle("Crab DNS");
#endif /* HAVE_SET_PROCTITLE */

    if (dns_helper_initialize(query_fd[0], reply_fd[1])) {
      CRIT("gwc_check_init() failed");
    }

    _exit(EXIT_SUCCESS);
  }
  
  /* Re-assign the pipe descriptors to the lowest available descriptors */
  close(query_fd[0]);
  ret = fcntl(query_fd[1], F_DUPFD, 0);
  close(query_fd[1]);
  *query = ret;
    
  close(reply_fd[1]);
  ret = fcntl(reply_fd[0], F_DUPFD, 0);
  close(reply_fd[0]);
  *reply = ret;

#else /* HAVE_PTHREAD_SUPPORT */

  if (dns_helper_initialize(query_fd[0], reply_fd[1])) {
    CRIT("gwc_check_init() failed");
    return -1;
  }

  pid = getpid();
  *query = query_fd[1];
  *reply = reply_fd[0];
  
#endif /* !HAVE_PTHREAD_SUPPORT */

  return pid;
}

#if !defined(HAVE_PTHREAD_SUPPORT)
static void
child_exited(ev_watcher_t *w, pid_t pid)
{
  (void) w;
  (void) pid;

  INFO("DNS helper process exited");
  fflush(NULL);
  exit(0);
}
#endif /* !HAVE_PTHREAD_SUPPORT */

int
main(int argc, char *argv[])
{
  int query_fd = -1, reply_fd = -1;
  pid_t pid = (pid_t) -1;
  struct stat sb;

  (void) argc;
  (void) argv;

  if (fstat(STDIN_FILENO, &sb)) {
    if (!freopen(DEV_NULL, "r", stdin))
      exit(EXIT_FAILURE);
  }
      
  if (fstat(STDOUT_FILENO, &sb)) {
    if (!freopen(DEV_NULL, "w", stdout))
      exit(EXIT_FAILURE);
  }
  
  if (fstat(STDERR_FILENO, &sb)) {
    if (!freopen(DEV_NULL, "w", stderr))
      exit(EXIT_FAILURE);
  }

 
  if (getuid() != geteuid()) {
    CRIT("Refusing to run as set-user-ID process");
    exit(EXIT_FAILURE);
  }
  
  if (process_args(argc, argv)) {
    exit(EXIT_FAILURE);
  }
  if (apply_options()) {
    CRIT("apply_options() failed");
    exit(EXIT_FAILURE);
  }

  RUNTIME_ASSERT(getuid() != 0);
  RUNTIME_ASSERT(geteuid() != 0);

  /* This is just a test to check that ``log_main'' can be opened because if
   * freopen() fails later, there won't be any error message to read.
   */
  {
    FILE *f;

    f = fopen(OPTION(log_main), "a");
    if (!f) {
      CRIT("Cannot open log_main (\"%s\")", OPTION(log_main));
      exit(EXIT_FAILURE);
    }
    fclose(f);
  }

  if (OPTION(daemonize)) {
    if (compat_daemonize("/")) {
      CRIT("Could not daemonize process");
      exit(EXIT_FAILURE);
    }
  } else {
    if (compat_close_std_streams()) {
      exit(EXIT_FAILURE);
    }
  }

  if (OPTION(working_directory)) {
    if (0 != chdir(OPTION(working_directory))) {
      FATAL("Could change working directory to \"%s\"",
        OPTION(working_directory));
      exit(EXIT_FAILURE);
    }
  }

  if (OPTION(support_gwc)) {
    pid = dns_helper_launch(&query_fd, &reply_fd);
    if (pid == (pid_t) -1) {
      CRIT("dns_helper_initialize() failed");
      exit(EXIT_FAILURE);
    }
  }

  if (reopen_logs()) {
    exit(EXIT_FAILURE);
  }
  
  if (compat_disable_fork()) {
    exit(EXIT_FAILURE);
  }

  watcher = ev_watcher_new();
  if (!watcher) {
    CRIT("ev_watcher_new() failed");
    exit(EXIT_FAILURE);
  }
  ev_watcher_set_timeout(watcher, 250);

#if !defined(HAVE_PTHREAD_SUPPORT)
  if ((pid_t) -1 != pid) {
    ev_watcher_watch_process(watcher, pid, child_exited);
  }
#endif /* !HAVE_PTHREAD_SUPPORT */

  initialize(watcher, query_fd, reply_fd);
  ev_watcher_mainloop(watcher);
  ev_watcher_destruct(watcher);

  return EXIT_SUCCESS;
}

#endif

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
