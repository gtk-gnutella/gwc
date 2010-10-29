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

#include "event_watcher.h"

#if defined(USE_POLL)
#undef USE_KQUEUE
#undef USE_EPOLL
#else /* !USE_POLL */
#if defined(HAVE_KQUEUE)
#define USE_KQUEUE
#endif /* HAVE_KQUEUE */
#if defined(HAVE_EPOLL)
#define USE_EPOLL
#endif /* HAVE_EPOLL */
#endif /* USE_POLL */

#ifdef USE_EPOLL
#include <sys/epoll.h>
#endif /* USE_EPOLL*/

#include <poll.h>

/* If still not defined, just define them */
#ifndef POLLRDNORM
#define POLLRDNORM 0
#endif
#ifndef POLLRDBAND
#define POLLRDBAND 0
#endif
#ifndef POLLWRNORM
#define POLLWRNORM 0
#endif
#ifndef POLLWRBAND
#define POLLWRBAND 0
#endif

#include "event_source.h"
#include "oop.h"

static const size_t source_chunks = 64;

typedef enum {
  EV_WATCHER_NONE,
  EV_WATCHER_POLL,
  EV_WATCHER_KQUEUE,
  EV_WATCHER_EPOLL
} ev_watcher_type_t;

typedef enum {
  EV_WATCHER_MAGIC = 0x6147969b
} ev_watcher_magic_t;

struct ev_watcher {
  ev_watcher_magic_t    magic;
  ev_source_t           **sources;
  size_t                size_sources;
  size_t                num_sources;
  ev_watcher_periodic_cb_t  periodic_cb;
  unsigned long         timeout;  /* delay for periodic callbacks */
  struct timeval        last_gc;
  struct timeval        last_poll;
  struct timeval        last_periodic;

  ev_watcher_type_t     watcher_type;

  void                  *ev_arr; /* array of kevent, pollfd, epoll_event */
  size_t                ev_size; /* size of ev_arr[0] */
  int                   ev_fd;  /* kqueue() or epoll() fd, otherwise -1 */
};

void
ev_watcher_check(ev_watcher_t *w)
{
  RUNTIME_ASSERT(w);
  RUNTIME_ASSERT(EV_WATCHER_MAGIC == w->magic);
}

void
ev_watcher_set_timeout(ev_watcher_t *w, unsigned long timeout)
{
  ev_watcher_check(w);
  w->timeout = timeout;
}

void
ev_watcher_set_periodic_cb(ev_watcher_t *w, ev_watcher_periodic_cb_t cb)
{
  ev_watcher_check(w);

#ifdef USE_KQUEUE
  if (EV_WATCHER_KQUEUE == w->watcher_type) {
    static const struct timespec zero_ts;
    struct kevent kev;

    EV_SET(&kev, PTR2UINT(w),
        EVFILT_TIMER, (cb ? EV_ADD : EV_DELETE), 0, w->timeout, 0);
    if (-1 == kevent(w->ev_fd, &kev, 1, 0, 0, &zero_ts)) {
      WARN("kevent() failed: %s", compat_strerror(errno));
    }
  }
#endif /* USE_KQUEUE */
  
  w->periodic_cb = cb;
}

void
ev_watcher_destruct(ev_watcher_t *w)
{
  if (w) {
    ev_watcher_check(w);
    if (-1 != w->ev_fd) {
      close(w->ev_fd);
      w->ev_fd = -1;
    }
    DO_FREE(w->ev_arr);
    DO_FREE(w);
  }
}

static int
ev_watcher_add_source(ev_watcher_t *w, ev_source_t *evs)
{
  char *p;
  size_t i;
  
  ev_watcher_check(w);
  ev_source_check(evs);

  RUNTIME_ASSERT(ev_source_get_fd(evs) >= 0);
  RUNTIME_ASSERT(NULL == ev_source_get_watcher(evs));

  p = w->ev_arr;
  RUNTIME_ASSERT(w->num_sources <= w->size_sources);
  if (w->num_sources == w->size_sources) {
    size_t n;

    n = w->size_sources;
    n = n < source_chunks ? source_chunks : n * 2;
    p = realloc(p, n * w->ev_size);
    if (!p) {
      return -1;
    }
  }
  RUNTIME_ASSERT(p != NULL);

  RUNTIME_ASSERT(w->ev_size > 0);
  memset(&p[w->num_sources * w->ev_size], 0, w->ev_size);
  w->ev_arr = p;

  if (EV_WATCHER_POLL == w->watcher_type) {
    struct pollfd *fds;

    fds = w->ev_arr;
    fds[w->num_sources].fd = ev_source_get_fd(evs);
    fds[w->num_sources].events = 0;
    fds[w->num_sources].revents = 0;
  }

  /*
   * This is OK when using poll() because the new client is appended
   * so it's not a problem when a event callback adds a client while
   * being in ev_watcher_inform_sources().
   */
 
  if (w->num_sources == w->size_sources) {
    size_t n;
    
    n = w->size_sources;
    n = n < source_chunks ? source_chunks : n * 2;
    p = realloc(w->sources, n * sizeof w->sources[0]);
    if (!p) {
      return -1;
    }

    w->sources = cast_to_void_ptr(p);
    for (i = w->size_sources; i < n; i++) {
      w->sources[i] = NULL;
    }
    w->size_sources = n;
  }
  
  RUNTIME_ASSERT(w->num_sources < w->size_sources);
  for (i = 0; i < w->size_sources; i++) {
    if (!w->sources[i]) {
      w->sources[i] = evs;
      break;
    }
  }
  RUNTIME_ASSERT(i < w->size_sources);
  w->num_sources++;
  ev_source_set_watcher(evs, w);
  ev_source_ref(evs);
  return 0;
}

void
ev_watcher_source_closed(ev_watcher_t *w, ev_source_t *evs)
{
  ev_watcher_check(w);
  ev_source_check(evs);

  RUNTIME_ASSERT(ev_source_get_watcher(evs) == w);
  RUNTIME_ASSERT(w->num_sources > 0);
}

static void
ev_watcher_collect_garbage(ev_watcher_t *w)
{
  struct timeval tv;
  size_t i;

  ev_watcher_check(w);

  compat_mono_time(&tv);
  if (DIFFTIMEVAL(&tv, &w->last_gc) < 500) {
    return;
  }
  w->last_gc = tv;

  i = w->size_sources;
  while (i-- > 0) {
    ev_source_t *evs;

    evs = w->sources[i];
    if (evs) {
      ev_source_check(evs);
      if (ev_source_is_closed(evs)) {
        ev_source_unref(evs);
        w->sources[i] = NULL;
        RUNTIME_ASSERT(w->num_sources > 0);
        w->num_sources--;
      } else {
        /* Checks and delivers timeout */
        ev_source_event(evs, EVT_NONE, &tv);
      }
    }
  }
}

int
ev_watcher_watch_source(ev_watcher_t *w, ev_source_t *evs, ev_type_t evt)
{
  ev_type_t old_evt;
  bool watch_read = false, watch_write = false;
  int fd, ret = 0;

  ev_watcher_check(w);
  ev_source_check(evs);
  fd = ev_source_get_fd(evs);
  RUNTIME_ASSERT(fd >= 0);

  if (!ev_source_get_watcher(evs) && ev_watcher_add_source(w, evs)) {
    return -1;
  }

  old_evt = ev_source_get_eventmask(evs);
  if (old_evt == evt) {
    return 0;
  }
  
  switch (evt) {
  case EVT_READ:
    watch_read = true;
    break;
  case EVT_WRITE:
    watch_write = true;
    break;
  case EVT_NONE:
    break;
  default:
    RUNTIME_ASSERT(0);
  }

#ifdef USE_KQUEUE
  if (EV_WATCHER_KQUEUE == w->watcher_type) {
    struct kevent kev[2];
    size_t n = 0;

    if (EVT_NONE != old_evt) {
      RUNTIME_ASSERT(old_evt == EVT_WRITE || old_evt == EVT_READ);

      EV_SET(&kev[n], fd,
          (old_evt == EVT_READ ? EVFILT_READ : EVFILT_WRITE),
          EV_DELETE | EV_DISABLE, 0, 0, PTR_TO_KEVENT_UDATA(evs));
      n++;
    }

    if (watch_read || watch_write) {
      EV_SET(&kev[n], fd, (watch_read ? EVFILT_READ : EVFILT_WRITE),
          EV_ADD, 0, 0, PTR_TO_KEVENT_UDATA(evs));
      n++;
    }

    if (n != 0) {
      static const struct timespec zero_ts;

      RUNTIME_ASSERT(n <= ARRAY_LEN(kev));
      ret = kevent(w->ev_fd, kev, n, NULL, 0, &zero_ts);
      if (-1 == ret) {
        WARN("kevent() failed: %s", compat_strerror(errno));
      }
    }
  }
#endif /* USE_KQUEUE */
  
#ifdef USE_EPOLL
  if (EV_WATCHER_EPOLL == w->watcher_type) {
    static const struct epoll_event zero_pe;
    struct epoll_event pe;
    int op;

    pe = zero_pe;
    pe.data.ptr = evs;
    if (watch_read) {
      pe.events |= EPOLLIN | EPOLLPRI;
    }
    if (watch_write) {
      pe.events |= EPOLLOUT;
    }
    if (watch_read || watch_write) {
      op = EVT_NONE != old_evt ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
    } else {
      op = EPOLL_CTL_DEL;
    }

    ret = epoll_ctl(w->ev_fd, op, fd, &pe);
    if (-1 == ret) {
      WARN("epoll_ctl() failed: %s", compat_strerror(errno));
    }
  }
#endif /* USE_EPOLL */

  ev_source_set_eventmask(evs, evt);
  return -1 == ret ? -1 : 0;
}

/**
 * This function is only used with kqueue() and because up to NetBSD 2.0H
 * closing a pipe doesn't cause a EVFILT_READ in a remote process reading
 * from the the pipe. Therefore, the other process would wait forever
 * instead of terminating automagically after the remote process.
 */
int
ev_watcher_watch_process(ev_watcher_t *w, pid_t pid, ev_watcher_process_cb_t cb)
#ifdef USE_KQUEUE
{
  static const struct timespec zero_ts;
  struct kevent kev;
  int ret;

  ev_watcher_check(w);

  EV_SET(&kev, pid, EVFILT_PROC, cb != NULL ? EV_ADD : EV_DELETE,
      0, NOTE_EXIT, PTR_TO_KEVENT_UDATA(cb));
  ret = kevent(w->ev_fd, &kev, 1, NULL, 0, &zero_ts);
  if (-1 == ret) {
    WARN("kevent() failed: %s", compat_strerror(errno));
    return -1;
  } else {
    return 0;
  }
}
#else /* !USE_KQUEUE */
{
  ev_watcher_check(w);
  (void) pid;
  (void) cb;
  errno = ENOTSUP;
  return -1;
}
#endif /* USE_KQUEUE */

static inline int
ev_watcher_periodic_handler(ev_watcher_t *w)
{
  ev_watcher_check(w);

  if (
    w->periodic_cb &&
    DIFFTIMEVAL(&w->last_poll, &w->last_periodic) / 1000 >= w->timeout
  ) {
    w->periodic_cb(w, &w->last_poll);
    w->last_periodic = w->last_poll;
  }
  return 0;
}

typedef enum {
  POLL_READ = POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI | POLLHUP,
  POLL_WRITE = POLLOUT | POLLWRNORM | POLLWRBAND,
  POLL_ANY = POLL_READ | POLL_WRITE
} poll_event_t;

static inline int
ev_type_to_poll(ev_type_t evt)
{
  return  (evt & EVT_READ ? POLL_READ : 0) |
          (evt & EVT_WRITE ? POLL_WRITE : 0);
}

static void
ev_watcher_create_pollset(ev_watcher_t *w)
{
  size_t i;
 
  ev_watcher_check(w);

  i = w->num_sources;
  while (i-- > 0) {
    struct pollfd *pfd, *base;
    ev_source_t *evs;
   
    base = w->ev_arr;
    pfd = &base[i];

    evs = w->sources[i];
    if (evs) {
      ev_source_check(evs);
      if (ev_source_is_closed(evs)) {
        evs = NULL;
      } else {
        pfd->fd = ev_source_get_fd(evs);
        RUNTIME_ASSERT(pfd->fd >= 0);
        pfd->events = ev_type_to_poll(ev_source_get_eventmask(evs));
      }
    }
    if (!evs) {
      pfd->fd = -1;
      pfd->events = 0;
      pfd->revents = 0;
    }
  }
}

static void
ev_watcher_inform_sources_poll(ev_watcher_t *w, int n)
{
  size_t i;

  ev_watcher_check(w);
  (void) n;

  i = w->num_sources;
  while (i-- > 0) {
    ev_source_t *evs;

    evs = w->sources[i];
    if (evs) {
      struct pollfd *pfd, *base;
      ev_type_t ev;
      int fd;

      base = w->ev_arr;
      pfd = &base[i];

      if (ev_source_is_closed(evs)) {
        continue;
      }
      fd = ev_source_get_fd(evs);
      RUNTIME_ASSERT(fd >= 0);
      RUNTIME_ASSERT(fd == pfd->fd);

      if (0 == pfd->revents) {
        continue;
      }

      ev = EVT_NONE;
      if (pfd->revents & POLL_READ) {
        ev |= EVT_READ;
      }
      if (pfd->revents & POLL_WRITE) {
        ev |= EVT_WRITE;
      }
      if (pfd->revents & POLLHUP) {
        ev |= EVT_HANGUP;
      }
      if (pfd->revents & POLLERR) {
        ev |= EVT_ERROR;
      }

      if (pfd->revents & POLLNVAL) {
        ev |= EVT_ERROR;
        WARN("POLLNVAL (fd=%d)", pfd->fd);
      }

      if ((EVT_ERROR & ev) || (ev & ev_source_get_eventmask(evs))) {
        ev_source_event(evs, ev, &w->last_poll);
      }
    }
  }
}

#ifdef USE_KQUEUE
static void
ev_watcher_mainloop_kqueue(ev_watcher_t *w)
{
  ev_watcher_check(w);
  RUNTIME_ASSERT(w->ev_fd >= 0);

  for (;;) {
    int ret;

    ev_watcher_collect_garbage(w);

    ret = kevent(w->ev_fd, NULL, 0, w->ev_arr, w->num_sources, NULL);
    if (-1 == ret) {
      if (!is_temporary_error(errno)) {
        WARN("kevent() failed: %s", compat_strerror(errno));
      }
    } else if (ret > 0) {
      struct timeval now;
      bool periodic = false;
      size_t i;
      
      RUNTIME_ASSERT(ret >= 0 && (size_t) ret <= w->num_sources);
      compat_mono_time(&now);
      
      for (i = 0; i < (size_t) ret; i++) {
        const struct kevent *base, *kev;
        
        base = w->ev_arr;
        kev = &base[i];

#if 0
         DBUG("kevent(): ident=%p filter=%lu flags=%lu fflags=%lu "
           "data=%" PRId64 " udata=%p %s",
           (void *) w->kevents[i].ident,
           (unsigned long) w->kevents[i].filter,
           (unsigned long) w->kevents[i].flags,
           (unsigned long) w->kevents[i].fflags,
           w->kevents[i].data,
           (void *) w->kevents[i].udata,
           w->kevents[i].flags & EV_EOF ? "EOF" : ""
         );
#endif

        if (EVFILT_TIMER == kev->filter) {
          RUNTIME_ASSERT(kev->ident == PTR2UINT(w));
          periodic = true;
        } else if (EVFILT_PROC == kev->filter) {
          ev_watcher_process_cb_t cb;
          pid_t pid;

          pid = kev->ident;
          cb = (ev_watcher_process_cb_t) KEVENT_UDATA_TO_PTR(kev->udata);
          RUNTIME_ASSERT(cb != NULL);
          (*cb)(w, pid);
        } else {
          int fd, n;
          ev_source_t *evs;
          ev_type_t ev;

          fd = kev->ident;
          RUNTIME_ASSERT(fd >= 0);
          evs = KEVENT_UDATA_TO_PTR(kev->udata);
          ev_source_check(evs);
          if (ev_source_is_closed(evs)) {
            continue;
          }
          RUNTIME_ASSERT(ev_source_get_fd(evs) == fd);
       
          ev = EVT_NONE;
          n = 1;
          switch (kev->filter) {
          case EVFILT_READ:
            ev = EVT_READ;
#if 0
            if (ev_source_get_listening(evs)) {
              n = MIN(kev->data, 16);
            }
#endif /* XXX */
            if (0 == kev->data) {
              ev |= EVT_HANGUP;
            }
            break;
          case EVFILT_WRITE:
            ev = EVT_WRITE;
            if (0 == kev->data) {
              ev |= EVT_HANGUP;
            }
            break;
          default:
            RUNTIME_ASSERT(0);
          }
        
          while (n-- > 0 && (ev & ev_source_get_eventmask(evs))) {
            ev_source_event(evs, ev, &now);
            if (ev_source_is_closed(evs))
              break;
          }
        }
 
      }

      if (periodic && w->periodic_cb) {
        w->periodic_cb(w, &now);
      }
    
    } else if (0 == w->num_sources && 0 != w->timeout) {
      struct kevent kev;

      ret = kevent(w->ev_fd, NULL, 0, &kev, 1, NULL);
      switch (ret) {
      case 0: break;
      case -1:
        WARN("kevent() failed: %s", compat_strerror(errno));
        break;
      default:  
        if (EVFILT_TIMER == kev.filter && w->periodic_cb) {
          RUNTIME_ASSERT(kev.ident == PTR2UINT(w));
          w->periodic_cb(w, &w->last_poll);
        }
      }
    }
  }
  
}

#endif /* USE_KQUEUE */

#ifdef USE_EPOLL

static void
ev_watcher_inform_sources_epoll(ev_watcher_t *w, int n)
{
  int i;
  
  ev_watcher_check(w);
  RUNTIME_ASSERT(n >= 0);
  RUNTIME_ASSERT((unsigned) n <= w->num_sources);
  
  for (i = 0; i < n; i++) {
    const struct epoll_event *pe, *base;
    ev_source_t *evs;
    ev_type_t evt;
    
    base = w->ev_arr;
    pe = &base[i];
    evs = pe->data.ptr;
    ev_source_check(evs);
    if (ev_source_is_closed(evs)) {
      continue;
    }
    RUNTIME_ASSERT(ev_source_get_fd(evs) >= 0);

    evt = EVT_NONE;
    if ((EPOLLIN | EPOLLPRI) & pe->events) {
      evt |= EVT_READ;
    }
    if (EPOLLOUT & pe->events) {
      evt |= EVT_WRITE;
    }
    if (EPOLLHUP & pe->events) {
      evt |= EVT_HANGUP;
    }
    if (EPOLLERR & pe->events) {
      evt |= EVT_ERROR;
    }
    if (
        (evt & (EVT_ERROR | EVT_HANGUP)) ||
        (evt & ev_source_get_eventmask(evs))
       ) {
      ev_source_event(evs, evt, &w->last_poll);
    }
  }
}

static void
ev_watcher_mainloop_epoll(ev_watcher_t *w)
{
  ev_watcher_check(w);

  for (;;) {
    int ret;

    ev_watcher_collect_garbage(w);

    ret = epoll_wait(w->ev_fd, w->ev_arr, w->num_sources, w->timeout);
    if (-1 == ret && !is_temporary_error(errno)) {
      WARN("epoll_wait() failed: %s", compat_strerror(errno));
      sleep(1); /* prevent exhausting CPU resources */
    }
    compat_mono_time(&w->last_poll);
    ev_watcher_periodic_handler(w);
    if (ret > 0) {
      ev_watcher_inform_sources_epoll(w, ret);
    }
  }
}
#endif /* USE_EPOLL */

static void
ev_watcher_mainloop_poll(ev_watcher_t *w)
{
  ev_watcher_check(w);

  for (;;) {
    int ret;

    ev_watcher_collect_garbage(w);
    ev_watcher_create_pollset(w);

    do {
      ret = poll(w->ev_arr, w->num_sources, w->timeout);
      if (-1 == ret && !is_temporary_error(errno)) {
        WARN("poll failed: %s", compat_strerror(errno));
        sleep(1); /* prevent exhausting CPU resources */
      }
      compat_mono_time(&w->last_poll);
      if (ev_watcher_periodic_handler(w)) {
        break;
      }
    } while (0 == ret);
   
    if (ret > 0) {
      ev_watcher_inform_sources_poll(w, ret);
    }
  }
}

void
ev_watcher_mainloop(ev_watcher_t *w)
{
  ev_watcher_check(w);

  set_signal(SIGPIPE, SIG_IGN);

  switch (w->watcher_type) {
  case EV_WATCHER_KQUEUE:
#ifdef USE_KQUEUE
    ev_watcher_mainloop_kqueue(w);
    return;
#else /* !USE_KQUEUE */
    break;
#endif /* USE_KQUEUE */

  case EV_WATCHER_EPOLL:
#ifdef USE_EPOLL
    ev_watcher_mainloop_epoll(w);
    return;
#else /* !USE_EPOLL */
    break;
#endif /* USE_EPOLL */

  case EV_WATCHER_POLL:
    ev_watcher_mainloop_poll(w);
    return;

  case EV_WATCHER_NONE:
    break;
  }
  RUNTIME_ASSERT(0);
}

static int
ev_watcher_new_kqueue(ev_watcher_t *w)
#ifdef USE_KQUEUE
{
  ev_watcher_check(w);

  w->ev_fd = kqueue();
  if (-1 == w->ev_fd) {
    return -1;
  } else {
    w->ev_size = sizeof(struct kevent);
    w->watcher_type = EV_WATCHER_KQUEUE;
    return 0;
  }
}
#else /* !USE_KQUEUE */
{
  ev_watcher_check(w);
  errno = ENOTSUP;
  return -1;
}
#endif /* USE_KQUEUE */

static int
ev_watcher_new_epoll(ev_watcher_t *w)
#ifdef USE_EPOLL
{
  ev_watcher_check(w);

  w->ev_fd = epoll_create(source_chunks);
  if (-1 == w->ev_fd) {
    return -1;
  } else {
    w->ev_size = sizeof(struct epoll_event);
    w->watcher_type = EV_WATCHER_EPOLL;
    return 0;
  }
}
#else /* !USE_EPOLL */
{
  ev_watcher_check(w);
  errno = ENOTSUP;
  return -1;
}
#endif /* USE_EPOLL */

static int
ev_watcher_new_poll(ev_watcher_t *w)
{
  ev_watcher_check(w);
  w->ev_size = sizeof(struct pollfd);
  w->watcher_type = EV_WATCHER_POLL;
  return 0;
}

ev_watcher_t *
ev_watcher_new(void)
{
  ev_watcher_t *w = calloc(1, sizeof *w);

  if (w) {
    w->magic = EV_WATCHER_MAGIC;
    w->sources = NULL;
    w->size_sources = 0;
    w->num_sources = 0;
    w->periodic_cb = NULL;
    compat_mono_time(&w->last_poll);
    w->last_gc = w->last_poll;
    w->last_periodic = w->last_poll;
   
    w->watcher_type = EV_WATCHER_NONE;
    w->ev_arr = NULL;
    w->ev_size = 0;
    w->ev_fd = -1;

    if (
      0 != ev_watcher_new_kqueue(w) &&
      0 != ev_watcher_new_epoll(w) &&
      0 != ev_watcher_new_poll(w)
    ) {
      DO_FREE(w);
    }
  }
  return w;
}


/* vi: set ai et sts=2 sw=2 cindent: */
