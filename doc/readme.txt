
GhostWhiteCrab Documentation

GhostWhiteCrab/0.9.9 Documentation

Index

Building
Configuration
GWebCache Options
UDP Hostcache Options
Security
Templates
Setup
Signals
Files
Dependencies
Appendix

Building

   Basically, just run make. This will start config.sh
   if there is no file config.h yet and then proceed compiling the
   sources. After successful compilation you should find the executable
   gwc in the src directory.

   The shell script config.sh creates the header file
   config.h and is automagically executed when running make.
   Set CC, CPP, CFLAGS, LDFLAGS
   (or any other variables you use for your compiler) before
   running config.sh so that it uses the same settings as the make
   afterwards. Otherwise,
   config.sh might create a wrong config.h. If you want to
   use -Werror
   with GCC, make sure you don't use it
   while running config.sh or this step will fail. If you use
   TenDRA you should add -Xa
   to CFLAGS and you might have to add -I/usr/include as
   well.

   Run ./config --help for a list of available options. The
   defaults should be fine however.

  If config.sh fails or doesn't work properly, see
  config_test.log. It contains all test programs followed compiler
  output i.e., warnings, errors, other diagnostic messages. If you want to
  change the compiler or compiler settings run make clobber remove
  all object files and config.h. After that run make again to
  re-create config.h and to re-build gwc.

  If you get any compiler warnings, make sure they are harmless. If you
  don't know what they mean or assume they indicate a bug, inform the
  author(s), please.

  If your operating system has support for
  kqueue(),
  gwc will use this instead of poll() to gain better performance.
  On systems with a Linux kernel 2.6 or newer, there's typically support
  for epoll
  which has the same benefits and will be used if detected. You can override
  this by invoking config.sh with --use-poll as argument.

Configuration

  There's no hardcoded location for the configuration file. You have to
  pass the absolute pathname to gwc using the command-line
  option -f:

      gwc -f /path/to/crab.conf

  The process runs as a daemon i.e., detaches from the terminal (if started
  from one) and redirects stderr to the file as configured by log_main
  for the main process and to log_dns for the co-process which resolves
  hostnames. Checks of other GWebCaches are logged to log_checks.
  These files are opened in append-mode so they will continuously
  grow until you move them aside (see below for SIGHUP).

  The cached peers and URLs are read from and saved to peer_cache and
  good_url_cache respectively bad_url_cache approx. every 15
  minutes. They're not saved on exit mainly to prevent clearing the cache
  accidently. The configured pathnames for these must point to regular files,
  not symbolic links or anything else.

  Any client with the client ID GNUT is immediately disconnected
  without handling the request at all as this is a worm and not the
  deprecated Gnutella servent Gnut.

  Updates from peers with a port below 1024 are discarded. There don't seem
  to be any of those but an attacker might use this to keep a server on
  the same machine or the proxy busy.

  The net request is supported regardless of the support_v2
  setting. However gwc doesn't support serving more than one network
  at a time. Use the setting network_id if you want to use
  gwc for something else than the Gnutella network. If you don't
  use the network_id setting, any requests with a net parameter
  other than gnutella will be rejected appropriately. The value is
  treated case-insensitive.

  Anonymous requests are disallowed by default.

  Peers are currently reported for a maximum of 20 minutes. GWCs are validated
  every 5 hours. This can be adjusted at compile-time in gwc.h.
  Keep in mind that you should also adjust the cache sizes then. Failing
  caches are checked again after this time: 1 hour * 2^(number of checks).
  This way they will be contacted less and less if they keep on failing but
  have enough time to recover without getting flooded.

  HTTP redirects are not followed not just because it makes things simpler
  but also because all redirects either lead to 404 sites or already cached
  URLs currently and there's little hope this will ever change. Also, since
  this could cause unwanted dupes and/or traffic for uninvolved third parties,
  following redirects is assumed to be a security issue for Gnutella Web
  Caches.

  See example.conf for more information. It contains all possible
  configuration options along with descriptive comments.

GWebCache Options

  GhostWhiteCrab is at first a GWebCache. The option support_gwc
  is therefore true by default. There are several options that
  are only effective when the GWebCache support is active:

location

  This is the most important option and configure the URL that will be
  used by your GWebCache. A valid example looks like this:

   location http://myhost.example.org:8000/path

  In this example, myhost.example.org has to be the hostname of your
  server. You cannot use a mere IP address instead of fully qualified
  domain name. If you do not specify a port number (like 8000 in the
  example), the default HTTP port 80 is used. The path is not very
  important but restricted to a combination of lowercase letters,
  digits, slashs, dots, underscores, hyphens and tildes. A simple
  slash as path is fine. GhostWhiteCrab will not accept any variants
  (missing trailing slash, URL-encoded characters etc.) of this URL in
  requests. This is a very important feature and not a bug.

bad_url_cache

  This option must be set to the absolute path of the file that
  will be used to store URLs of GWebCaches that failed. This file must
  be read- and writable by the GWebCache user.

good_url_cache

  This option must be set to the absolute path of the file that
  will be used to store URLs of GWebCaches that are currently known to
  be working. This file must be read- and writable by the GWebCache user.

  The following are not necessary in most cases and a therefore optional. They
  might be required under certain circumstances or useful for fine-tuning:

auto_discovery (optional)

  By default newly submitted URLs are not added to list of known good URLs
  but only added the list of bad URLs with a magic number of
  retries (32). Thus, only URLs that are already known as bad or good are
  managed that is verified and propagated. This a precaution against hostile
  parties that might try to inject bad URLs. If you consider this paranoid
  or too much work to add new URLs manually, set this option to true.

expose_sysname (optional)

  This is disabled by default. If enabled, the HTTP Server header
  contains the name of the operating system as a comment. The name is
  retrieved with the uname() system call and is normally the same what
  uname -s shows.

listen_address (optional)

  By default one TCP listening socket is bound to the IPv4 address "0.0.0.0".
  To restrict access to a certain network interface, you can set this the
  appropriate IPv4 address. If "listen6_address" is specified, there is no
  TCP socket created for IPv4 by default.

listen6_address (optional)

  By default one TCP listening socket is bound to the IPv6 address "::". To
  restrict access to a certain network interface, you can set this the
  appropriate IPv6 address.

listen_port (optional)

  By default the port is derived from the option location. However,
  if you use port forwarding (NAT) e.g., to forward incoming traffic
  from TCP port 80 to port 8080, use this in your configuration file:

  listen_port 8080

  so that gwc listens on the correct port.

listen_backlog (optional)

  Use this to adjust the backlog parameter passed to the listen() system
  call. The default is 32. If the frequency of incoming connections is
  very high, it is recommended to increase the value. Most operating
  systems limit this to 128 or 256 internally.

hostfile_lines (optional)

  The amount of peer addresses to return for a hostfile request. The
  default is 20.

urlfile_lines (optional)

  The amount of URLs to return for an urlfile request. The default
  is 10. This should not be lower than 4. Otherwise, other GhostWhiteCrab
  GWebCaches will always consider your URL a bad one.

request_max_size (optional)

  The number of bytes accepted for a HTTP request including headers. The
  default is 1024. Some web browsers might send a huge amount of header
  data. If you experience problems when connecting with your browser,
  try to increase the size.

same_vendor_ratio (optional)

  This is set to 40 by default which means that GhostWhiteCrab attempts
  to return 40 percent of peers of the same vendor for a hostfile
  request. It is meant to help clients that are not well represented
  finding peers of their own kind to reduce connection problems in case
  of compatibility issues.

send_x_remote_ip (optional)

  The default is false. If enabled, HTTP responses contain a
  X-Remote-IP header which tells the client its IP addresses. This
  can help clients behind NAT routers to quickly discover their own IP address.

send_from_header (optional)

  The default is false. If enabled, Crab sends adds a "From:" header
  to HTTP requests when verifying submitted URLs. The content of this header
  is either the URL of your GWebCache or - if configured - your contact
  address. Crab does not aggressively crawl URLs but some webmasters might
  still feel abused. Thus, it's polite to provide contact information. Of
  course, it might just be an invitation for spam. However, the contact
  information is free form, it can be an URL, email address, phone number
  etc.

contact_address (optional)

  This is used together with send_from_header. The value should be
  a short text without control characters. The value can also be used in
  templates under the identifier crab.contact.address;.

idle_timeout (optional)

  The number of seconds after which an idle connection is closed. The default
  is 20 seconds but that might be too long on heavily loaded servers. Some
  clients simply do not properly disconnect or keep the connection open for
  no reason. This will waste a lot of resources and the process might also
  run out of file descriptors. However, be careful because a too low value
  might make it impossible for clients with slow connections to get a
  response. GhostWhite does not support persistent HTTP connections as this
  makes little sense for a GWebCache and will always close the connection
  after all data has been transmitted.

max_connect_time (optional)

  This is similar to idle_timeout but sets the absolute number of
  seconds after which a connection is closed even if there is pending
  data. The default is 30 seconds.

max_accepts_per_sec (optional)

  This option can be used to limit the number of accept() calls per
  second that is incoming connections. The default is zero which means
  no limit is applied. Setting this to an acceptable value limits
  the amount of outbound traffic that can be generated. However if you
  set it too low, the server becomes seemingly dead.

tcp_defer_accept_timeout (optional)

  This option is normally only available on Linux systems. It is ignored
  on supports which do not support it. The default value is 20 seconds.
  In case of problems, it can be disabled by setting the value to zero.
  See the man page tcp(7) for more information. In a nutshell,
  a low value heavily reduces the amount sockets in use because there
  are often many incoming connections which just timeout or hangup without
  sending any request. On FreeBSD crab will use an HTTP accept() filter
  which has basically the same effect but requires no configuration.

gwc_lock_time (optional)

  The default is 600 (10 minutes). This the is the time in seconds an
  IP address stays locked after making 3 requests. You should not set
  this higher than 3600 (1 hour) for the Gnutella network. You can save
  a lot of memory by reducing this value but it will allow higher request
  rates and may cause more traffic. Setting it to zero will disable
  locking altogether.

url_check_delay (optional)

  In order to prevent a flood of connection attempts (possibly to the same
  host each time) for URL verifications, each attempt is delayed by a number
  of seconds. The default value is 30.

url_check_max_size (optional)

  This limits the number of bytes read from a server when verifying an URL.
  The default value is 4096.

url_check_strict (optional)

  The default is true which means a GWebCache must report a minimum
  amount of known good URLs and not too many known bad URLs to be considered
  good itself. If set to false, a single valid URL is sufficient to mark an URL
  as good.

url_check_allow_dupes (optional)

  If set to false, duplicate URLs returned by other GWebCaches are
  tolerated. By default returning a duplicate (usually several variants of
  the same URL) will cause the URL to be marked as bad. If GWebCaches return
  duplicates (especially variants), much more clients might connect to
  the given URL and more frequently which might overload that server.

The next options are mostly for testing or debugging purposes.

allow_anonymous (not recommend)

  If you set this option to true, clients do not need to send
  a client ID in requests. While this might be useful for testing purposes,
  it's usually badly written software or a hostile party that does not
  send such an ID. Such requests are logged to the log_alert file.

daemonize (debug)

  GhostWhiteCrab is usally run as a daemon i.e., it forks itself and
  disconnects from the terminal etc. If this not desired, this option
  can be set to true to disable that behaviour.

pause_on_crash (debug)

  Normally, a process that crashes is terminated. If this option is set
  to true, the process will be stopped in case of a fatal signal
  so that you can attach a debugger to it.

http_dump_headers (debug)

  When set to true, all HTTP headers of requests are dumped to
  log_main.

UDP Hostcache Options

  GhostWhiteCrab can also serve as an UDP Hostcache (UHC) for the Gnutella
  network. You can enable UHC support and GWebCache support or both. By default
  GWebCache mode is enabled and UHC mode is disabled. In a nutshell, an
  UDP Hostcache works like a GWebCache but uses UDP instead of TCP and
  Gnutella packets instead of HTTP. Therefore, it uses less resources and
  traffic. Further, an UHC doesn't depend on updates by Gnutella peers but
  discovers peers itself. See the
  specifications for details.

  If you want to run an UDP Hostcache only but no GWebCache, set
  support_gwc to false.

support_uhc

  UHC support is enabled by setting support_uhc to true. If
  you enable the UDP Hostcache support, the option network_id must be
  either be unset or set to gnutella as this a very Gnutella-specific
  feature. The default is false.

uhc_port

  This option configures the port to be used for the UDP socket. Make sure
  this UDP port is not blocked by your firewall. The port must be above
  1023 whether the process runs as root or not.

uhc_hostname (recommended)

  If you have assigned a public DNS name to the server, you can use this
  option to tell the clients about it. This allows clients to contact your
  UHC by hostname instead of an IP address.

uhc_bind_address (optional)

  By default one UDP socket will be bound to the IPv4 address "0.0.0.0"
  If you want to restrict access to a specific network interface, set this
  to the appropriate IP address. If "uhc_bind6_address" is specified, no
  UDP socket is bound to "0.0.0.0" by default.

uhc_bind6_address (optional)

  By default one UDP socket will be bound to the IPv6 address "::". If
  you want to restrict access to a specific network interface, set this
  to the appropriate IPv6 address. If this option is used, you might have
  to set "uhc_bind_address" explicitely to an IPv4 address too.

uhc_peers_per_pong (optional)

  This limits the number of peer addresses that will put into a pong. The
  current default is 50. Keep in mind that UDP packets larger than about
  500 bytes can be problematic due to fragmentation. A single peer address
  is 6 bytes large.

uhc_pongs_per_sec (optional)

  This limits the overall amount of pongs that will be sent per second. The
  current default is 10.

uhc_pong_timeout_msec (optional)

  The amount of time in milliseconds to wait for a pong reply. Replies to
  pings after this timeout are discarded. The current default is 60000,
  thus one minute.

uhc_lock_time (optional)

  The default is 600 (10 minutes). This the is the time in seconds an
  IP address stays locked after making 3 requests.  You can save
  memory by reducing this value but it will allow higher request rates
  and may cause more traffic. Setting it to zero will disable locking
  altogether.

uhc_rcvbuf_size (optional)

  If set to a non-zero value, the UDP socket will initialized using the
  socket option SO_RCVBUF. Normally, the default value used by your
  operating system should be fine. However if you experience packet loss due
  to overflowing buffers, increasing this value might help. See also the
  manpage for setsockopt(2).

uhc_sndbuf_size (optional)

  If set to a non-zero value, the UDP socket will initialized using the
  socket option SO_SNDBUF. This is the analogous of
  uhc_rcvbuf_size but for the send buffer.

Security

  Make sure that the gwc user cannot write to the configuration file, 
  the templates, the address filter or the directories in which these files
  are. gwc should only be able to write to the log and the cache
  files. This is easy to accomplish and absolutely necessary for basic
  security.

  The support for running under a different UID, GID and chroot()ing
  to a specified directory is present but not thoroughly
  tested yet. Use it with extreme caution!
  It should be unnecessary in almost all cases. You can use a packet filter, a
  firewall or a NAT server to redirect ports below 1024 to another port above
  so that you don't have to run gwc with privileges. See also
  listen_port.

  Never ever set the set-UID-bit for gwc! A set-GID-bit shouldn't be
  necessary in any case either but Crab won't complain about this.

  It's recommended to compile gwc statically to make it immune against
  potential exploits based on dynamic linking i.e., certain race-conditions,
  LD_LIBRARY_PATH etc. However, depending on your operating system
  static linking might not be possible.

  Use a dedicated account - if possible on its own partition - for
  gwc, I mean that!

  Use a compiler which checks the stack for overflows e.g., 

  GCC-SSP which is a modified GCC with stack-smashing protection.

  Use systrace, a
  FreeBSD jail or other security tools
  to limit the potential damage which could be caused by bugs. Such tools are
  also useful to discover bugs which would not be found easily otherwise.

Templates

  There are currently two templates supported base_template and
  data_template. The first is used for requests to the GWC URI
  without any query. The second is used for data requests i.e.,
  if the query contains ?data=key whereas key must match the
  configured data_key. If data_key is not set (this is the
  default), the key is ignored and all data requests are served.
  The template format is simple:

  HTTP response code and message
  HTTP headers
  One empty line
  The document data

  The HTTP response line and the HTTP headers are optional. You probably
  want to use a Content-Type header if the document data is anything else
  but text/plain with ASCII or ISO-8859-1 encoded data. See the
  examples directory for ready-to-use templates. Note that you
  can use templates to redirect requests to a different URL:

  HTTP/1.1 302 Moved Temporarily
  Location: http://www.example.org/some/path/

  The response line and the headers are not strictly checked. Thus, it's
  your responsibility to use valid HTTP. However, you don't have to terminate
  lines with CRLF, that is \r or \n are sufficient as well. Spaces will be
  stripped from the end of the line and a single \n will be replaced by \r\n
  when sending the response.

  There are several private entities which will be replaced by the actual
  contents when sending the document. For example, you can add the version
  information to your document by using the entity
  crab.user.agent;. This is mostly interesting for customizing
  a status page. Whether you use XHTML, HTML, plain text or anything else
  is completely up to. Just make sure you use an appropriate Content-Type
  header. The default is text/plain. See src/template.c
  or the examples for available entities. Their names should be more or
  less self-explanatory. You can also rather easily extend the set of
  entities (if you have moderate C skills that is). Templates are only read
  at startup time. The entities are replaced with their actual values at
  run-time so that the processing overhead is pretty low.

  Note: You cannot use entities in the HTTP headers or the response
  line as of yet. Consider using a HTTP redirect to a different
  web host with static data in the base_template if you simply want
  a fancy web site for human visitors.

Setup

  It is highly recommended to create a dedicated user crab along with
  a dedicated group crab. The user crab should be the only
  user in this group and it shouldn't be in any other group.

  The following shows a typical simple setup. At first, the directory/file
  structure:

  mode        owner group pathname

  drwxr-x--T  root  crab  /home/crab
  drwxrwx--T  root  crab  /home/crab/cores
  -rw-r-----  root  crab  /home/crab/crab.conf
  -rw-r-----  root  crab  /home/crab/hostiles.txt

  drwxrwx--T  root  crab  /home/crab/db
  -rw-r-----  crab  crab  /home/crab/db/peer_cache
  -rw-r-----  crab  crab  /home/crab/db/urls.bad
  -rw-r-----  crab  crab  /home/crab/db/urls.good

  drwxrwx--T  root  crab  /home/crab/log
  -rw-r-----  crab  crab  /home/crab/log/access.log
  -rw-r-----  crab  crab  /home/crab/log/alert.log
  -rw-r-----  crab  crab  /home/crab/log/checks.log
  -rw-r-----  crab  crab  /home/crab/log/dns.log
  -rw-r-----  crab  crab  /home/crab/log/main.log
  -rw-r-----  crab  crab  /home/crab/log/uhc.log

  drwxr-x--T  root  crab  /home/crab/templates
  -r--r-----  root  crab  /home/crab/templates/base.template
  -r--r-----  root  crab  /home/crab/templates/data.template

  In the example above, you can actually replace root by any other user.
  However it is best if Crab cannot modify any files or directories
  that it is not supposed to. This is simply a defense in the unfortunate case
  of exploitable bugs. The sticky bit is set just in case as
  well. Note that the user crab has no write-access to its home
  directory.

  To use the above layout, the corresponding options would be configured as
  shown here:

  log_access  /home/crab/log/access.log
  log_alert   /home/crab/log/alert.log
  log_checks  /home/crab/log/checks.log
  log_dns     /home/crab/log/dns.log
  log_main    /home/crab/log/main.log
  log_uhc     /home/crab/log/uhc.log

  If you are not interested in some of those logs, you can configure /dev/null
  as so that no diskspace gets wasted e.g.:

  log_dns     /dev/null

  Note that all paths must point to different files. You may set all of them
  to /dev/null, though. The log files will be generated by crab if
  they don't exist. Thus you don't need to generate them in advance.

  If you have to start Crab as root - because you want to use the chroot
  feature or because you want to use a privileged port (below 1024), you must
  also add these options:

  user        crab
  group       crab

  Otherwise, Crab will terminate after reading the options file. The option
  group is actually redundant if crab is the primary and only group
  the user crab belongs to.

  Further you probably want to set up a cron job to start Crab automagically
  after a reboot and hourly just in case it crashed. The TCP port should be
  sufficient as lock to prevent running multiple Crabs accidently. As the
  log files grow indefinitely and can become quite large, you should also add
  a cron job to remove or archive them on a daily basis. Crab will reopen all
  log files if it receives a SIGHUP signal. Use this after (re)moving the log
  files.

  The templates are not necessary but they are useful to get some information
  about the current status of Crab or to provide an informational page possibly
  with contact information so that people can notify you if they notice any
  problems with your cache. The example templates are ready to use. Just copy
  them to their target location and configure the proper paths:

  data_template   ~crab/db/data.template
  base_template   ~crab/db/base.template

  If you want to prevent that everyone can see the status information using
  the data request, you can set data_key to a secret string. Keep
  in mind that all transmissions are unencrypted, so that everyone who can read
  the traffic will see this key.

Signals

SIGHUP

  Causes gwc to re-open the log file assigned to stderr.
  This allows to archive the log files without having to restart
  gwc. For example, like this:

  stamp="`date '+%Y-%m-%d'`"
  mv access.log "access-${stamp}.log"
  mv gwc.log "gwc-${stamp}.log"
  mv dns.log "dns-${stamp}.log"
  mv checks.log "checks-${stamp}.log"
  pkill -HUP -u gwc gwc

  The signal will not cause the process to re-read
  any configuration or status files.

Files

  The following files are used by gwc. There are no default paths or
  filenames, they have to be configured. If you really don't care about any of
  those, set the path to /dev/null or comment them out if they're
  optional.

  First, the log files. Note that only log_alert and
  log_access contain backslash escaped data. Other log files may
  contain any possible characters and you should be careful to not send the
  contents straight to your terminal but use a filter such as less
  or more.

log_main (optional)

  Log messages from the main process. These are mostly debug messages.
  The default is "/dev/null".

log_access (optional)

  HTTP access log messages using the Combined Log Format
  of Apache. A typical message looks
  like this:

  127.0.0.1 - - [11/Nov/2004:18:04:20 +0000] "GET / HTTP/1.1" 200 304 - "Mozilla/5.0"

  The first token is the address of the remote client. The next two tokens are
  never set exist only for compatibility reasons. Third comes the timestamp in
  brackets; the timestamp is hardcoded to GMT. The fifth token is the received
  request, followed by the returned HTTP response code, the content-length of
  the reply, the HTTP Referer header. The last token is the HTTP
  User-Agent header as sent by the client. The data sent by the client
  is backslash escaped if necessary and truncated if the internal limit is
  exceeded.

log_alert (optional)

  Logs diverse alert messages. Each message consists of four
  tokens. The IP address of the remote client, a timestamp, the client
  agent ID and the alert message. The alert message is either Hostile,
  Scan, Trash or the GWebCache error message that was returned
  to the client. Hostile refers to connection attempts from address
  that are listed in address_filter. Scan means the remote
  client connected but send no data at all - not a single byte. Trash
  means the client send something but it did not look like a HTTP request.
  The GWebCache error messages are hopefully self-explanatory. If
  any of the tokens is empty, a single dash will be printed instead. The
  client agent ID is backslash escaped if it contains any strange
  characters.

log_checks (optional)

  Log messages regarding checks of other GWebCaches. This is
  merely a raw dump of connection attempts to GWebCaches and their replies.

log_dns (optional)

  Log messages from the hostname resolver. The default is "/dev/null".

log_uhc (optional)

  This is similar to log_access but concerns the UDP hostcache. Incoming
  UDP PING and PONG messages are logged here. This log file can get pretty
  huge very quickly.

  Second, the files that represent the database to preserve the state
  between restarts.

peer_cache

  All currently known peers; re-written every ~15 min.

bad_url_cache (GWebCache)

  All currently known bad URLs; re-written every ~15 min.

good_url_cache (GWebCache)

  All currently known good URLs; re-written every ~15 min.

  Last, the files that contains static data and are only read but never
  written by Crab:

base_template (optional; GWebCache)

  The template which is used for GWC URI when no query was
  provided. If this option isn't used an empty document is returned.

data_template (optional; GWebCache)

  The template to be used for data requests. If this
  option isn't used an empty document is returned.

address_filter (optional)

  A file with IPv4 addresses respectively address ranges to
  block. Valid formats are:

    address             # single host e.g., 192.0.2.33
    address/netmask     # a network e.g., 192.0.2.0/255.255.255.0
    address/prefixlen   # a network CIDR notation e.g., 192.0.2.0/24

  It's usually better to block access from/to addresses with a firewall or
  packet filter. In any case, it is highly recommended to block hostile
  parties. If all GWebCaches block them, they'll have a hard time to get
  connected. Further hostile parties often aggressively poll GWebCaches for
  fresh addresses and therefore seem to be ubiquitous.

Dependencies

  There are not supposed to be any dependencies except a more or less
  POSIX-compliant
  operating system with installed system C header files, a C compiler and the
  make tool. config.sh requires a Bourne Shell but the contents of config.h can
  be configured by hand if absolutely necessary. config.sh utilizes a few
  standard Unix tools e.g., sed.
  Future versions might require zlib.
  The UHC support does not strictly require zlib but it's recommended
  to save some traffic and for full compatibility.

Appendix

  External resources:

  Gnutella Web Caching System

    GWC v1.0 specifications
  [local copy]

    GWC v2.0 specifications
  [local copy]

    GWC v3.0 specifications [draft]
  [local copy]

    Jon Atkins' GWebCache Scan Report

  Author: Christian Biere christianbiere at gmx dot de
  Last-Edited: 2007-01-14

