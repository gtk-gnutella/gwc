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

#include "common.h"
#include "socker.h"

#ifdef HAVE_MSGHDR_CONTROL
static inline const struct cmsghdr *
cmsg_next_header(const struct msghdr *msg, const struct cmsghdr *cmsg_ptr)
{
  /* The Linux (glibc) version of this macro discards the const qualifiers.
   * Add explicit casts to suppress these compiler warnings. */
  return CMSG_NXTHDR((struct msghdr *) msg, (struct cmsghdr *) cmsg_ptr);
}

static int
parse_control_msg(const struct msghdr *msg)
{
  const struct cmsghdr *cmsg_ptr;

  RUNTIME_ASSERT(msg);
  
  if (NULL == (cmsg_ptr = CMSG_FIRSTHDR(msg))) {
    /* ignoring datagram without control data */
    return -1;
  }

  for (/* NOTHING */; cmsg_ptr; cmsg_ptr = cmsg_next_header(msg, cmsg_ptr)) {
    if (SOL_SOCKET == cmsg_ptr->cmsg_level) {
      switch (cmsg_ptr->cmsg_type) {
#ifdef SCM_CREDS
      case SCM_CREDS:
        {
          const struct sockcred *cred;

          cred = cast_to_const_void_ptr(CMSG_DATA(cmsg_ptr));
          debug_msg("SCM_CREDS"
              "(sc_uid=%lu, sc_euid=%lu, sc_gid=%lu, sc_egid=%lu)",
              (unsigned long) cred->sc_uid,
              (unsigned long) cred->sc_euid,
              (unsigned long) cred->sc_gid,
              (unsigned long) cred->sc_egid);
        }
        break;
#endif /* SCM_CREDS */

      case SCM_RIGHTS:
        {
          size_t len;

          len = cmsg_ptr->cmsg_len - ptr_diff(CMSG_DATA(cmsg_ptr), cmsg_ptr);

          if (len == sizeof (int)) {
            struct stat sb;
            const int *fd_ptr;
            int fd;
            
            fd_ptr = (const int *) CMSG_DATA(cmsg_ptr);
            fd = *fd_ptr;

            if (0 != fstat(fd, &sb)) {
              debug_error("fstat() failed");
              close(fd);
              fd = -1;
            } else {
              if (S_IFSOCK != (sb.st_mode & S_IFMT)) {
                debug_msg("Not a socket (fd=%d, st_uid=%lu, st_gid=%lu",
                    fd, (unsigned long) sb.st_uid, (unsigned long) sb.st_gid);
              }
              return fd;
            }
          } else {
            debug_msg("Bad length (%lu)", (unsigned long) len);
          }
        }
        break;

      default:
        debug_msg("unknown cmsg type (%u)", (unsigned) cmsg_ptr->cmsg_type);
        break;
      }
    } else {
      debug_msg("unknown cmsg level (%u)", (unsigned) cmsg_ptr->cmsg_level);
    }
  }

  return -1;
}
#endif /* HAVE_MSGHDR_CONTROL */

static int
receive_descriptor(int s)
#ifdef HAVE_MSGHDR_ACCRIGHTS
{
  int fd = -1;

  for (;;) {
    static const struct msghdr zero_msg;
    struct msghdr msg;
    struct iovec iov[1];
    char buf[1];
    int fd_buf[1];
    ssize_t ret;

    memset(buf, 0, sizeof buf);
    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof buf;

    msg = zero_msg;
    msg.msg_iov = iov;
    msg.msg_iovlen = ARRAY_LEN(iov);
    msg.msg_accrights = cast_to_void_ptr(fd_buf);
    msg.msg_accrightslen = sizeof fd_buf;

    ret = recvmsg(s, &msg, 0);
    if ((ssize_t) -1 == ret) {
      if (!is_temporary_error(errno)) {
        debug_error("recvmsg() failed");
        break;
      }
    } else if (ret > 0) {
      if (msg.msg_accrights && msg.msg_accrightslen == sizeof fd)
        memcpy(&fd, msg.msg_accrights, sizeof fd);
      break;
    } else {
      break;
    }
  }

  return fd;
}
#endif /* HAVE_MSGHDR_ACCRIGHTS */
#ifdef HAVE_MSGHDR_CONTROL
{
  struct cmsghdr *cmsg_buf = NULL;
  size_t cmsg_len;
  int fd = -1;

  cmsg_len = CMSG_LEN(sizeof fd);
  cmsg_buf = calloc(1, CMSG_SPACE(sizeof fd));
  if (!cmsg_buf) {
    debug_error("calloc() failed");
    goto failure;
  }

  for (;;) {
    static const struct cmsghdr zero_cmsg;
    static const struct msghdr zero_msg;
    struct msghdr msg;
    struct iovec iov[1];
    char buf[1];
    ssize_t ret;

    memset(buf, 0, sizeof buf);
    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof buf;

    *cmsg_buf = zero_cmsg;

    msg = zero_msg;
    msg.msg_iov = iov;
    msg.msg_iovlen = ARRAY_LEN(iov);
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = cmsg_len;

    ret = recvmsg(s, &msg, 0);
    if ((ssize_t) -1 == ret) {
      if (!is_temporary_error(errno)) {
        debug_error("recvmsg() failed");
        goto failure;
      }
    } else if (ret > 0) {
      fd = parse_control_msg(&msg);
      break;
    } else {
      break;
    }
  }

failure:
  
  if (cmsg_buf) {
    free(cmsg_buf);
    cmsg_buf = NULL;
  }

  return fd;
}
#endif /* HAVE_MSGHDR_CONTROL */

static const char *
socket_domain_to_string(int i)
{
  switch (i) {
#define CASE(x) case (x): return #x;
  CASE(PF_INET) 
#if defined(HAVE_IPV6_SUPPORT)
  CASE(PF_INET6) 
#endif /* HAVE_IPV6_SUPPORT */
#undef CASE
  }
  return NULL;
}

static const char *
socket_type_to_string(int i)
{
  switch (i) {
#define CASE(x) case (x): return #x;
  CASE(SOCK_STREAM)
  CASE(SOCK_DGRAM)
  CASE(SOCK_RAW)
  CASE(SOCK_SEQPACKET)
  CASE(SOCK_RDM)
#undef CASE
  }
  return NULL;
}

int
socker_get(int domain, int type, int protocol,
  const char *addr, unsigned port)
{
  pid_t pid;
  int sv[2];

  if (-1 == socketpair(PF_LOCAL, SOCK_STREAM, 0, sv)) {
    debug_error("socketpair(PF_LOCAL, SOCK_STREAM, 0, sv)");
    return -1;
  }

  pid = fork();
  if ((pid_t) -1 == pid) {
    debug_error("fork()");
    close(sv[0]);
    close(sv[1]);
  } else if (0 == pid) {  /* child */
    static char *argv[] = {
      "socker",
      "-d", NULL,
      "-t", NULL,
      "-p", NULL,
      "-f", NULL,
      "-a", NULL,
      "-P", NULL,
      NULL,
    };
    const char *s_domain, *s_type;
    char s_protocol[32];
    char s_port[32];
    char s_fd[32];
    unsigned i;

    s_domain = socket_domain_to_string(domain);
    if (!s_domain) {
      _exit(EXIT_FAILURE);
    }
    s_type = socket_type_to_string(type);
    if (!s_type) {
      _exit(EXIT_FAILURE);
    }

    snprintf(s_protocol, sizeof s_protocol, "%d", protocol);
    snprintf(s_port, sizeof s_port, "%d", port);
    snprintf(s_fd, sizeof s_fd, "%d", sv[0]);

    close(sv[1]);

    i = 1;

    argv[i++] = "-d";
    argv[i++] = deconstify_char_ptr(s_domain);
    
    argv[i++] = "-t";
    argv[i++] = deconstify_char_ptr(s_type);
    
    argv[i++] = "-p";
    argv[i++] = s_protocol;
    
    argv[i++] = "-f";
    argv[i++] = s_fd;
   
    if (addr) {
      argv[i++] = "-a";
      argv[i++] = deconstify_char_ptr(addr);
   
      if ((unsigned) -1 != port) {
        argv[i++] = "-P";
        argv[i++] = s_port;
      }
    }
    argv[i] = NULL;
    RUNTIME_ASSERT(i < ARRAY_LEN(argv));
 
    execvp(argv[0], argv);
    _exit(EXIT_FAILURE);

  } else {  /* parent */
    int fd;

    close(sv[0]);
    fd = receive_descriptor(sv[1]);
    close(sv[1]);

    if (-1 == fd) {
      debug_msg("receive_descriptor() failed");
    }

    return fd;
  }

  return -1;
}

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
