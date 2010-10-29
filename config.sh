#! /bin/sh
#
# Copyright (c) 2005
#    Christian Biere <christianbiere@gmx.de> All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

# Note: This script is supposed to work with cross-compilers. Thus, no
#       custom programs are run, only compiling and linking is used.
#
# Set DEBUG_CONFIG_SH to 1 to see all source code
# unset DEBUG_CONFIG_SH
debug_config_sh=1

# assert_fail is used to force the a compiler error
assert_fail='switch (0) { case 0: case (sizeof(char[-23]) == 333): break; }'
assert_work='switch (0) { case 0: case (sizeof(char[333]) == 333): break; }'

die () {
  # print the first parameter to stdout and exit with an error
  echo 'config.sh:' $1
  echo '***'
  echo '***  See config_test.log for details.'
  echo '***'
  exit 1
}	

msg () {
  # echo all parameters to stderr and stdout
  echo ${1+"$@"} >&2
}

msg_printf() {
  # printf all parameters to stderr and stdout
  printf ${1+"$@"} >&2
}

msg_yes () {
  # print 'yes' to stderr and stdout
  msg 'yes'
  return 0
}

msg_no () {
  # print 'no' to stderr and stdout
  msg 'no'
  return 1
}

msg_yes_no () {
  # print 'yes' on previous success or no on previous failure
  # to stderr and stdout. The exit code is preserved.
  
  if [ $1 -eq 0 ]; then
    msg_yes
    return 0 
  else
    msg_no
    return 1
  fi
}

config_debug_log_source () {
  test "x${debug_config_sh}" != x || return
    
  { echo; cat config_test.c; echo; } >> config_test.log
}

clear_var() {
  eval $1=1
  eval unset $1
}

config_test_c_compile () {
  config_debug_log_source 
    
  ${CC} ${CPPFLAGS} ${CFLAGS} -c config_test.c >> config_test.log 2>&1
  if [ $? -eq 0 ]; then
    test $# -gt 0 && eval $1=1
    return 0
  fi
  
  test $# -gt 0 && clear_var $1
  return 1
}

# config_test_c_create (line_1 ... line_n)
#
# This function creates config_test.c from line_1 (and optionally more lines)
# as part of the main() funtion.
#
config_test_c_create () {
  test $# -gt 0 || die 'Too few arguments to "config_test_c_create"!'
  {
    echo '#include "config_test.h"'
    printf 'int main(void)\n{\n'
    while [ $# -gt 0 ]; do
      printf "%s\n" "$1"
      shift
    done
    printf '  return 0;\n}\n'
  } > config_test.c
}

config_test_compile_lines () {
  test $# -gt 0 || die 'Too few arguments to "config_test_compile_lines"!'
  config_test_c_create ${1+"$@"}
  config_test_c_compile
}

config_var() {
  if [ $2 -ne 0 ]; then
    clear_var $1
    return 1
  fi
  eval $1=1 
  return 0
}

config_test_compile () {
  test $# -gt 1 || die 'Too few arguments to "config_test_compile"!'
  clear_var $1
  eval ret=$1
  shift
  config_test_compile_lines ${1+"$@"}
  config_var $ret $?
  return $?
}

config_test_compile_and_link () {
  test $# -gt 0 || die 'Too few arguments to "config_test_compile_and_link"!'
  clear_var $1
  eval ret=$1

  shift
  test $# -gt 0 && config_test_c_create ${1+"$@"}

  config_test_c_compile || return 1

  for lib in '' ${try_libs}; do
    if [ "x${lib}" != x ]; then
      lib="-l`echo "$lib"| sed 's/:/ -l/g'`"
    fi
    
    ${CC} ${CPPFLAGS} ${CFLAGS} \
      -o config_test config_test.o ${LDFLAGS} ${lib} \
      >> config_test.log 2>&1
    if [ $? -eq 0 ]; then
      if [ "x${lib}" != x ]; then
        LDFLAGS="${LDFLAGS:+$LDFLAGS }${lib}"
      fi
      config_var $ret 0
      return 0
    fi
  done
  
  config_var $ret 1
  return 1
}

invert_result() {
  test $1 -eq 0 && return 1
  return 0
}

check_compile_time_assert () {
  msg_printf 'Looking whether compile-time assertions work... '

  config_test_compile_lines "${assert_work}" || { msg_no; return 1; }
  config_test_compile_lines "${assert_fail}"
  invert_result $?
  msg_yes_no $?
  return $?
}

check_std_header () {
  test $# -gt 1 || die 'Too few arguments to "check_std_header"!'
  msg_printf 'Looking for <'"$2"'>... '
  
cat > config_test.c <<EOF
#include "config_test.h"
#include <$2>
int main(void)
{
  return 0;
}
EOF

  config_test_c_compile
  msg_yes_no $?
  config_var $1 $?
  return $?
}

#
# check_type_size (result, type, hint)
#
# hint is optional. It'll be checked first to speed up the detection.
#
check_type_size () {

  printf 'Looking for sizeof('"$2"')... ' >&2
  
  test $# -gt 1 || die 'Too few arguments to "check_type_size"!'
  clear_var $1
    
  # some shells can't calculate with $((expr)), so check common sizes only
  for i in $3 1 2 4 8 16 32 64 128 256; do
    config_test_compile_lines \
      'static char x[sizeof('"$2"') == ('"$i"') ? 1 : -23];' \
      'switch (0) { case 0: case (sizeof(x) == 1): break; }'
    if [ $? -eq 0 ]; then
      msg "$i"
      eval $1="$i"
      return 0
    fi
  done

  msg 'failure'
  return 1
}

#
# check_have_type (result, type)
#
check_have_type() {
  msg_printf 'Looking for type '"$2"'... '
  test $# -gt 1 || die 'Too few arguments to "check_have_type"!'
  
  config_test_compile_lines "$2"' x; (void) x;'
  msg_yes_no $?
  if [ $? -eq 0 ]; then
    eval $1=1
    return 0
  else 
    clear_var $1
    return 1
  fi
}

config_h_prolog() {
  {
    echo '#ifndef CONFIG_HEADER_FILE'
    echo '#define CONFIG_HEADER_FILE'
    echo
    compiler_specifics
  } >> config.h
}

config_h_epilog() {
  {
    echo
    echo '#endif /* CONFIG_HEADER_FILE */'
  } >> config.h
}

config_h_def() {
  eval val=\$$1
  {
    if [ "x$val" != x ]; then
      echo '#define '"$1" "$val"
    else
      echo '#undef '"$1"
    fi
  } >> config.h
}

config_test_h_def() {
  eval val=\$$1
  {
    if [ "x$val" != x ]; then
      echo '#define '"$1" "$val"
    else
      echo '#undef '"$1"
    fi
  } >> config_test.h
}

config_make_def() {
  eval val=\$$1
  {
    if [ "x$val" != x ]; then
      echo "$1"'='"$val"
    fi
  }
}

compiler_specifics() {
  echo '#ifdef __TenDRA__'
  echo '#pragma TenDRA longlong type allow'
  echo '#endif /* __TenDRA__ */'
}

compiler_flags() {
  
  msg_printf 'Looking whether this is TenDRA CC... '
  config_test_compile_lines \
    '#if defined(__TenDRA__)' \
    '/* Looks like TenDRA CC */' \
    '#else' \
    "${assert_fail}" \
    '#endif'
  msg_yes_no $?
  
  if [ $? -eq 0 ]; then
    CFLAGS='-Xa -O2'
    export CFLAGS
    return
  fi

  msg_printf 'Looking whether this is Tiny CC... '
  config_test_compile_lines \
    '#if defined(__TINYC__)' \
    '/* Looks like Tiny CC */' \
    '#else' \
    "${assert_fail}" \
    '#endif'
  msg_yes_no $?
  
  if [ $? -eq 0 ]; then
    CFLAGS='-Wall -O2'
    export CFLAGS
    return
  fi

  msg_printf 'Looking whether this is GNU CC... '
  config_test_compile_lines \
    '#if defined(__GNUC__) && defined(__GNUC_MINOR__)' \
    '#if ((__GNUC__ > 0) && (__GNUC_MINOR__ >= 0))' \
    '/* Looks like GCC */' \
    '#else' \
    "${assert_fail}" \
    '#endif' \
    '#else' \
    "${assert_fail}" \
    '#endif'
  msg_yes_no $?

  if [ $? -eq 0 ]; then
    msg_printf 'Looking for stack smashing protection... '
    CFLAGS='-fstack-protector'
    config_test_compile_and_link 'no_such_variable' ''
    msg_yes_no $?

    if [ $? -ne 0 ]; then
      unset CFLAGS
      msg '***'
      msg '*** You might want to have a look at this:'
      msg '***'
      msg '***    http://www.trl.ibm.com/projects/security/ssp/'
      msg '***'
    fi
    
    CFLAGS="${CFLAGS}"' -W -Wall -Wformat=2 -Wshadow -g -O2'
    export CFLAGS
  fi

}

create_makefile() {
  test $# -eq 1 || die 'Wrong number of arguments for "create_makefile()"!'
  dir="$1"
  depfile="${dir}/Makefile.dep"
  
  if [ -f "${depfile}" ]; then
    touch "${depfile}"
    cp config.h "${dir}" || exit
  else
    msg 'Creating "'"${depfile}"'" ...'
    touch "${depfile}" || exit
    (  
       cp config.h "${dir}" || exit
       cd "${dir}" || exit
       ${CC} -MM *.c || exit
    ) > "${depfile}"
  fi

  (
    if [ "x${prefix}" = x ]; then
      prefix='/usr/local'
    fi
    if [ "x${bin_dir}" = x ]; then
      bin_dir="${prefix}/bin"
    fi
    if [ "x${library_dir}" = x ]; then
      library_dir="${prefix}/lib"
    fi
    if [ "x${header_dir}" = x ]; then
      header_dir="${prefix}/include"
    fi

    echo '# Environment variables'
    config_make_def 'CC' 
    config_make_def 'CPP' 
    config_make_def 'CFLAGS' 
    config_make_def 'CPPFLAGS' 
    config_make_def 'LDFLAGS' 
    config_make_def 'prefix' 
    config_make_def 'bin_dir' 
    config_make_def 'library_dir' 
    config_make_def 'header_dir' 
    config_make_def 'link_libdl'
    config_make_def 'link_rpath'
    echo

    cat "${dir}/Makefile.template" "${dir}/Makefile.dep" || exit

  ) | cat > "${dir}/Makefile"
}

show_help() {
  msg 'The following environment variables are honored:'
  msg 'CC, CPP, CFLAGS, CPPFLAGS, LDFLAGS, PREFIX'
  msg
  msg 'The following switches are available:'
  if [ "x${prefix}" != x ]; then
    msg '  --prefix=PATH        Path prefix used for installing files.'
  fi
  if [ "x${bin_dir}" != x ]; then
    msg '  --bin-dir=PATH       Directory used for installing executables.'
  fi
  if [ "x${library_dir}" != x ]; then
    msg '  --library-dir=PATH   Directory used for installing libraries.'
  fi
  if [ "x${header_dir}" != x ]; then
    msg '  --header-dir=PATH    Directory used for installing header files.'
  fi
  if [ "x${use_ipv6}" != x ]; then
    msg '  --disable-ipv6       Do not use IPv6 even if supported.'
  fi
  if [ "x${use_zlib}" != x ]; then
    msg '  --disable-zlib       Do not use zlib even if available.'
  fi
  if [ "x${use_socker}" != x ]; then
    msg '  --disable-socker     Do not use socker even if available.'
  fi
  if [ "x${use_large_files}" != x ]; then
    msg '  --disable-large-files  Disable explicit large file support.'
  fi
  if [ "x${use_poll}" != x ]; then
    msg '  --use-poll           Use poll() instead of kqueue() or epoll().'
  fi
  if [ "x${use_threads}" != x ]; then
    msg '  --use-threads        Use POSIX threads (if available).'
  fi
  if [ "x${use_gethostbyname}" != x ]; then
    msg '  --use-gethostbyname  Use gethostbyname() instead of getaddrinfo().'
  fi
  if [ "x${use_sha1}" != x ]; then
    msg '  --use-sha1  Use SHA-1 calculation routines.'
  fi
  if [ "x${use_sqlite3}" != x ]; then
    msg '  --use-sqlite3  Use SQLite3.'
  fi
  msg
}

handle_vars() {
  var_list="\
    bin_dir \
    header_dir \
    library_dir \
    prefix \
    use_gethostbyname \
    use_ipv6 \
    use_poll \
    use_sha1 \
    use_socker \
    use_sqlite3 \
    use_threads \
    use_zlib \
  "

  for var in $var_list; do
    eval val=\$$var
    if [ "x${val}" = xauto ]; then
      unset ${var}
    fi
  done
}

set_var_from_arg() {
    test $# -eq 2 || die 'Wrong number of arguments for "set_var_from_arg()"!'
    eval $1=`echo "x$2" | sed 's,^x[^=]*=,,'`
}

handle_args() {

  while [ $# -gt 0 ]; do
    case $1 in
      --help|-h)
        show_help
        exit
      ;;
      --prefix=*)
        set_var_from_arg 'prefix' "$1"
      ;;
      --bin-dir=*)
        set_var_from_arg 'bin_dir' "$1"
      ;;
      --library-dir=*)
        set_var_from_arg 'library_dir' "$1"
      ;;
      --header-dir=*)
        set_var_from_arg 'header_dir' "$1"
      ;;
       --disable-ipv6)
        unset use_ipv6
      ;;
      --disable-zlib)
        unset use_zlib
      ;;
      --disable-large-files)
        unset use_large_files
      ;;
      --use-gethostbyname)
        use_gethostbyname=1
      ;;
      --use-poll)
        use_poll=1
      ;;
      --use-threads)
        use_threads=1
      ;;
      --disable-socker)
        unset use_socker
      ;;
      --use-socker)
        use_socker=1
      ;;
      --disable-sha1)
        unset use_sha1
      ;;
      --use-sha1)
        use_sha1=1
      ;;
      --disable-sqlite3)
        unset use_sqlite3
      ;;
      --use-sqlite3)
        use_sqlite3=1
      ;;
      *)
        die 'Unsupported argument: "'"$1"'"'
      ;;
    esac
    shift
  done

  handle_vars
}

#
# Here starts the config.sh main routine
#

# Load settings and defaults
. ./config.conf

# Handle arguments
handle_args ${1+"$@"}
  
uid=`id -u || unknown`
if [ "x$uid" = x0 ]; then
  msg 'There is no reason to run this as root.'
  echo '***'
  echo '*** JUU KYUU HACHI NANA ROKU GO YON SAN NI ICHI ZERO!'
  echo '***'
fi

rm -f config_test.h || die 'Could not remove config_test.h'
touch config_test.h || die 'Could not create config_test.h'
rm -f config_test.log || die 'Could not remove config_test.log'

compiler_specifics >> config_test.h

msg_printf 'Looking for whether $(CC) is set... '
if [ "x$CC" = x ]; then
  msg_yes_no $?
  msg_printf 'Looking for C compiler (cc)... '
  CC=`command -v cc || command -v gcc || echo cc`
fi
msg "$CC"

msg_printf 'Looking whether the compiler works... '
config_test_compile_and_link 'no_such_variable' ''
if [ $? -ne 0 ]; then
  msg_no
  die 'Cannot continue without a working compiler'
else
  msg_yes $?
fi
  
check_compile_time_assert || die 'Cannot continue'

if [ "x${CFLAGS}" = x ]; then
  compiler_flags
fi

check_std_header 'HAVE_SYS_TYPES_H' 'sys/types.h' && \
  echo '#include <sys/types.h>' >> config_test.h 
config_test_h_def 'HAVE_SYS_TYPES_H'

check_std_header 'HAVE_INTTYPES_H' 'inttypes.h' && \
  echo '#include <inttypes.h>' >> config_test.h 
config_test_h_def 'HAVE_INTTYPES_H'

check_std_header 'HAVE_STDBOOL_H' 'stdbool.h' && \
  echo '#include <stdbool.h>' >> config_test.h
config_test_h_def 'HAVE_STDBOOL_H'

check_std_header 'HAVE_STDLIB_H' 'stdlib.h' && \
  echo '#include <stdlib.h>' >> config_test.h
config_test_h_def 'HAVE_STDLIB_H'

check_std_header 'HAVE_SYS_PARAM_H' 'sys/param.h' && \
  echo '#include <sys/param.h>' >> config_test.h
config_test_h_def 'HAVE_SYS_PARAM_H'

check_std_header 'HAVE_SYS_ENDIAN_H' 'sys/endian.h' && \
  echo '#include <sys/endian.h>' >> config_test.h
config_test_h_def 'HAVE_SYS_ENDIAN_H'

check_std_header 'HAVE_SYS_SOCKET_H' 'sys/socket.h' && \
  echo '#include <sys/socket.h>' >> config_test.h
config_test_h_def 'HAVE_SYS_SOCKET_H'

check_std_header 'HAVE_SYS_EVENT_H' 'sys/event.h' && \
  echo '#include <sys/event.h>' >> config_test.h
config_test_h_def 'HAVE_SYS_EVENT_H'

check_std_header 'HAVE_SYS_TIME_H' 'sys/time.h' && \
  echo '#include <sys/time.h>' >> config_test.h
config_test_h_def 'HAVE_SYS_TIME_H'

check_std_header 'HAVE_SYS_UN_H' 'sys/un.h' && \
  echo '#include <sys/un.h>' >> config_test.h
config_test_h_def 'HAVE_SYS_UN_H'

check_std_header 'HAVE_NETINET_IN_H' 'netinet/in.h' && \
  echo '#include <netinet/in.h>' >> config_test.h
config_test_h_def 'HAVE_NETINET_IN_H'

check_std_header 'HAVE_ARPA_INET_H' 'arpa/inet.h' && \
  echo '#include <arpa/inet.h>' >> config_test.h
config_test_h_def 'HAVE_ARPA_INET_H'

if [ "x${use_threads}" != x ]; then
  check_std_header 'HAVE_PTHREAD_H' 'pthread.h' && \
    echo '#include <pthread.h>' >> config_test.h
  config_test_h_def 'HAVE_PTHREAD_H'
else
  clear_var HAVE_PTHREAD_H
fi

msg_printf 'Looking for SHUT_RD... '
config_test_compile 'HAVE_SHUT_RD' 'shutdown(1, SHUT_RD);'
msg_yes_no $?

msg_printf 'Looking for SHUT_WR... '
config_test_compile 'HAVE_SHUT_WR' 'shutdown(1, SHUT_WR);'
msg_yes_no $?

msg_printf 'Looking for SHUT_RDWR... '
config_test_compile 'HAVE_SHUT_RDWR' 'shutdown(1, SHUT_RDWR);'
msg_yes_no $?

check_std_header 'HAVE_NETDB_H' 'netdb.h' && \
  echo '#include <netdb.h>' >> config_test.h
config_test_h_def 'HAVE_NETDB_H'

check_std_header 'HAVE_FEATURES_H' 'features.h'
config_test_h_def 'HAVE_FEATURES_H'

check_have_type 'HAVE_INT8_T' 'int8_t'
config_test_h_def 'HAVE_INT8_T'

check_have_type 'HAVE_UINT8_T' 'uint8_t'
config_test_h_def 'HAVE_UINT8_T'

check_have_type 'HAVE_INT16_T' 'int16_t'
config_test_h_def 'HAVE_INT16_T'

check_have_type 'HAVE_UINT16_T' 'uint16_t'
config_test_h_def 'HAVE_UINT16_T'

check_have_type 'HAVE_INT32_T' 'int32_t' 
config_test_h_def 'HAVE_INT32_T'

check_have_type 'HAVE_UINT32_T' 'uint32_t' 
config_test_h_def 'HAVE_UINT32_T'

check_have_type 'HAVE_INT64_T' 'int64_t'
config_test_h_def 'HAVE_INT64_T'

check_have_type 'HAVE_UINT64_T' 'uint64_t'
config_test_h_def 'HAVE_UINT64_T'

check_have_type 'HAVE_INTMAX_T' 'intmax_t'
config_test_h_def 'HAVE_INTMAX_T'

check_have_type 'HAVE_UINTMAX_T' 'uintmax_t'
config_test_h_def 'HAVE_UINTMAX_T'

check_have_type 'HAVE_INTPTR_T' 'intptr_t'
config_test_h_def 'HAVE_INTPTR_T'

check_have_type 'HAVE_UINTPTR_T' 'uintptr_t'
config_test_h_def 'HAVE_UINTPTR_T'

check_have_type 'HAVE_SOCKLEN_T' 'socklen_t'
config_test_h_def 'HAVE_SOCKLEN_T'

check_have_type 'HAVE_IN_ADDR_T' 'in_addr_t'
config_test_h_def 'HAVE_IN_ADDR_T'

check_have_type 'HAVE_IN_PORT_T' 'in_port_t'
config_test_h_def 'HAVE_PORT_T'

check_type_size 'SIZEOF_CHAR' 'char'
config_test_h_def 'SIZEOF_CHAR'

check_type_size 'SIZEOF_SHORT' 'short' 2
config_test_h_def 'SIZEOF_SHORT'

check_type_size 'SIZEOF_INT' 'int' 4
config_test_h_def 'SIZEOF_INT'
 
check_type_size 'SIZEOF_LONG' 'long' 4
config_test_h_def 'SIZEOF_LONG'
  
check_type_size 'SIZEOF_LONG_LONG' 'long long' 8
config_test_h_def 'SIZEOF_LONG_LONG'

check_type_size 'SIZEOF_UINTMAX_T' 'uintmax_t' 8
config_test_h_def 'SIZEOF_UINTMAX_T'

check_type_size 'SIZEOF_UINTPTR_T' 'uintptr_t' 4 
config_test_h_def 'SIZEOF_UINTPTR_T'

check_type_size 'SIZEOF_VOID_PTR' 'void *' 4 
config_test_h_def 'SIZEOF_VOID_PTR'

check_type_size 'SIZEOF_BOOL' 'bool' 4
config_test_h_def 'SIZEOF_BOOL'

check_type_size 'SIZEOF_SIZE_T' 'size_t' 4
config_test_h_def 'SIZEOF_SIZE_T'

check_type_size 'SIZEOF_OFF_T' 'off_t' 4
config_test_h_def 'SIZEOF_OFF_T'

msg_printf 'Looking for C99 __func__ ... '
config_test_compile_and_link 'HAVE_C99_func' \
                               'const char *s = __func__; (void) s;'
msg_yes_no $?
config_test_h_def 'HAVE_C99_func'

msg_printf 'Looking for C99 inline support... '
cat > config_test.c <<EOF
#include "config_test.h"
static inline int
my_function(int i)
{
  return i;
}
int main(int argc, char *argv[])
{
  (void) argv;
  return 0 != my_function(argc);
}
EOF

config_test_c_compile 'HAVE_C99_inline'
msg_yes_no $?

msg_printf 'Looking for __inline support... '
cat > config_test.c <<EOF
#include "config_test.h"
static __inline int
my_function(int i)
{
  return i;
}
int main(int argc, char *argv[])
{
  (void) argv;
  return 0 != my_function(argc);
}
EOF

config_test_c_compile 'HAVE___inline'
msg_yes_no $?
 
msg_printf 'Looking for C99 variadic macro support... '
cat > config_test.c <<EOF
#include "config_test.h"
int
my_function(int i, ...)
{
  return i;
}
#define MY_MACRO(...) my_function(1, ## __VA_ARGS__)
int main(void)
{
  MY_MACRO(1, 2);
  return 0;
}
EOF

config_test_c_compile  'HAVE_C99_VARIADIC_MACROS'
msg_yes_no $?


if [ "x${use_large_files}" != x ]; then
  msg_printf 'Looking for large file support... '
  cat > config_test.c <<EOF
#include "config_test.h"

#define STATIC_ASSERT(x) \
  do { switch (0) { case 0: case ((x) ? 1 : 0): break; } } while(0)
  
#define MAX_INT_VAL(t) \
	(((t) 1 << (CHAR_BIT * sizeof(t) - 1 - ((t) -1 < 0))) \
   	- 1 + ((t) 1 << (CHAR_BIT * sizeof(t) - 1 - ((t) -1 < 0))))

int
main(void)
{
  STATIC_ASSERT(MAX_INT_VAL(off_t) > 0x7fffffffL);
  return 0;
}
EOF
  config_test_compile_and_link 'HAVE_LARGE_FILE_SUPPORT'
  if [ "x${HAVE_LARGE_FILE_SUPPORT}" != x ]; then
    msg_yes
  else
    saved_cflags=${CFLAGS} 
    CFLAGS="${CFLAGS} -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE" 
    config_test_compile_and_link 'HAVE_LARGE_FILE_SUPPORT'
    if [ "x${HAVE_LARGE_FILE_SUPPORT}" != x ]; then
    msg_yes
    else
    CFLAGS=${saved_cflags}
    fi
  fi
fi

 
msg_printf 'Looking for gethostbyname()... '
# Solaris needs libnsl for gethostbyname()
try_libs='nsl'
config_test_compile_and_link 'HAVE_GETHOSTBYNAME' \
  'struct hostent *he = gethostbyname("localhost"); if (!he) return 1;'
msg_yes_no $?
unset try_libs

msg_printf 'Looking for herror()... '
# Solaris needs libresolv, libnsl and libsocket for herror()
try_libs='socket nsl resolv socket:nsl socket:nsl:resolv'
config_test_compile_and_link 'HAVE_HERROR' 'char *s = "blah"; herror(s);'
msg_yes_no $?
unset try_libs

msg_printf 'Looking for hstrerror()... '
# Solaris needs libresolv, libnsl and libsocket for hstrerror()
try_libs='socket nsl resolv socket:nsl socket:nsl:resolv'
config_test_compile_and_link 'HAVE_HSTRERROR' \
  'int i = 1; const char *s = hstrerror(i); if (!s) return 1;'
msg_yes_no $?
unset try_libs

if [ "x${use_gethostbyname}" != x ]; then
  clear_var HAVE_GETADDRINFO
  clear_var HAVE_FREEADDRINFO
  clear_var HAVE_GAI_STRERROR
else
  msg_printf 'Looking for getaddrinfo()... '
  # Solaris needs libsocket and libnsl for getaddrinfo()
  try_libs='socket nsl socket:nsl'
  cat > config_test.c <<EOF
#include "config_test.h"
int
main(void) {
  static int ret;
  struct addrinfo hints;
  struct addrinfo *res;
  hints.ai_flags = 1;
  hints.ai_family = 1;
  hints.ai_socktype = 1;
  hints.ai_protocol = 1;
  hints.ai_addrlen = (socklen_t) 1;
  hints.ai_canonname = "canonname";
  hints.ai_addr = (struct sockaddr *) 0;
  hints.ai_next = (struct addrinfo *) 0;
  ret |= getaddrinfo("localhost", "www", &hints, &res);
  return 0 != ret;
}
EOF
  config_test_compile_and_link 'HAVE_GETADDRINFO'
  msg_yes_no $?
  unset try_libs
  
  msg_printf 'Looking for freeaddrinfo()... '
  # Solaris needs libsocket and libnsl for freeaddrinfo() 
  try_libs='socket nsl socket:nsl'
  config_test_compile_and_link 'HAVE_FREEADDRINFO' \
    'struct addrinfo *ai = (struct addrinfo *) 0; freeaddrinfo(ai);'
  msg_yes_no $?
  unset try_libs

  msg_printf 'Looking for gai_strerror()... '
  # Solaris needs libsocket and libnsl for gai_strerror() 
  try_libs='socket nsl socket:nsl'
  config_test_compile_and_link 'HAVE_GAI_STRERROR' \
    'int i = 1; const char *s = gai_strerror(i); if (!s) return 1;'
  msg_yes_no $?
  unset try_libs
fi

if [ "x${use_ipv6}" != x ]; then
  msg_printf 'Looking for IPv6 support... '
  cat > config_test.c <<EOF
#include "config_test.h"
/*
 * <sys/socket.h>,
 * <netinet/in.h>,
 * <arpa/inet.h>,
 * <netdb.h> are included by config_test.h
 */

#define STATIC_ASSERT(x) \
  do { switch (0) { case 0: case ((x) ? 1 : 0): break; } } while(0)

int
main(void) {
  static struct sockaddr_storage ss;
  static struct sockaddr_in6 sin6;
  static struct in6_addr in6;

  ss.ss_family |= PF_INET6;

  sin6.sin6_family |= AF_INET6;
  sin6.sin6_port |= 6346;
  sin6.sin6_flowinfo |= 23UL;
  sin6.sin6_scope_id |= 42UL;
  sin6.sin6_addr = in6;
  sin6.sin6_addr.s6_addr[0] = in6.s6_addr[0];

  STATIC_ASSERT(AF_INET6 == PF_INET6);
  STATIC_ASSERT(sizeof in6 == sizeof sin6.sin6_addr);
  STATIC_ASSERT(16 == sizeof sin6.sin6_addr.s6_addr);
  STATIC_ASSERT(2 == sizeof sin6.sin6_port);
  STATIC_ASSERT(4 == sizeof sin6.sin6_flowinfo);
  STATIC_ASSERT(4 == sizeof sin6.sin6_scope_id);

  (void) sin6;
  (void) in6;

  return 0;
}
EOF
  config_test_compile_and_link 'HAVE_IPV6_SUPPORT'
  msg_yes_no $?
else
  clear_var HAVE_IPV6_SUPPORT
fi

msg_printf 'Looking for setproctitle()... '
config_test_compile_and_link 'HAVE_SETPROCTITLE' 'setproctitle("blah");'
msg_yes_no $?

msg_printf 'Looking for fchroot()... '
echo '#include <unistd.h>' >> config_test.h 
config_test_compile_and_link \
  'HAVE_FCHROOT' 'int fd = 1; int ret; ret = fchroot(fd);'
msg_yes_no $?

msg_printf 'Looking for SA_INTERRUPT... '
echo '#include <signal.h>' >> config_test.h 
config_test_compile_and_link 'HAVE_SA_INTERRUPT' 'int x; x = SA_INTERRUPT;'
msg_yes_no $?

msg_printf 'Looking for SIGBUS... '
config_test_compile_and_link 'HAVE_SIGBUS' 'int x; x = SIGBUS;'
msg_yes_no $?

msg_printf 'Looking for SIGSYS... '
config_test_compile_and_link 'HAVE_SYSBUS' 'int x; x = SIGSYS;'
msg_yes_no $?


msg_printf 'Looking for clock_gettime()... '
cat > config_test.c <<EOF
#include "config_test.h"
#include <time.h>
int
main(void) {
  static struct timespec ts;
  static clockid_t id;
  static int ret;
  ts.tv_sec |= 1;
  ts.tv_nsec |= 1;
  id |= CLOCK_REALTIME;
  ret |= clock_gettime(id, &ts);
  return 0 != ret;
}
EOF
try_libs='rt'
config_test_compile_and_link 'HAVE_CLOCK_GETTIME'
msg_yes_no $?
unset try_libs


msg_printf 'Looking for uname()... '
echo '#include <sys/utsname.h>' >> config_test.h 
cat > config_test.c <<EOF
#include "config_test.h"
int
main(void) {
  struct utsname n;
  static char c;
  static int ret;
  ret |= uname(&n);
  c |= *n.sysname;
  c |= *n.nodename;
  c |= *n.release;
  c |= *n.machine;
  return 0 != ret;
}
EOF
config_test_compile_and_link 'HAVE_UNAME'
msg_yes_no $?

msg_printf 'Looking for getrusage()... '
echo '#include <sys/resource.h>' >> config_test.h 
cat > config_test.c <<EOF
#include "config_test.h"
int
main(void) {
  struct rusage ru;
  struct timeval tv;
  static int ret;
  ret |= getrusage(RUSAGE_SELF, &ru);
  tv = ru.ru_utime;
  ru.ru_stime = tv;
  return 0 != ret;
}
EOF
config_test_compile_and_link 'HAVE_GETRUSAGE'
msg_yes_no $?

msg_printf 'Looking for BSD struct rusage... '
cat > config_test.c <<EOF
#include "config_test.h"
int
main(void) {
  static struct rusage ru;
  ru.ru_maxrss    |= 1L;
  ru.ru_ixrss     |= 1L;
  ru.ru_idrss     |= 1L;
  ru.ru_isrss     |= 1L;
  ru.ru_minflt    |= 1L;
  ru.ru_majflt    |= 1L;
  ru.ru_nswap     |= 1L;
  ru.ru_inblock   |= 1L;
  ru.ru_oublock   |= 1L;
  ru.ru_msgsnd    |= 1L;
  ru.ru_msgrcv    |= 1L;
  ru.ru_nsignals  |= 1L;
  ru.ru_nvcsw     |= 1L;
  ru.ru_nivcsw    |= 1L;
  return 0;
}
EOF
config_test_compile_and_link 'HAVE_BSD_STRUCT_RUSAGE'
msg_yes_no $?

msg_printf 'Looking for valloc()... '
config_test_compile_and_link 'HAVE_VALLOC' \
  'void *p = valloc(1); if (p) return 0;'
msg_yes_no $?

msg_printf 'Looking for getpagesize()... '
config_test_compile_and_link 'HAVE_GETPAGESIZE' \
  'long size = getpagesize(); if (size != 0) return 0;'
msg_yes_no $?

if [ "x${use_poll}" != x ]; then
  clear_var HAVE_KQUEUE
else
  msg_printf 'Looking for kqueue()... '
  cat > config_test.c <<EOF
#include "config_test.h"
int
main(void) {
  static struct kevent changes, events;
  static struct timespec ts;
  static unsigned long filter, flags;
  static int ret, kq, fd;
  filter |= EVFILT_READ;
  filter |= EVFILT_WRITE;
  filter |= EVFILT_TIMER;
  filter |= EVFILT_SIGNAL;
  filter |= EVFILT_PROC;
  filter |= EVFILT_VNODE;
  flags |= EV_ADD;
  flags |= EV_ENABLE;
  flags |= EV_ONESHOT;
  flags |= EV_CLEAR;
  flags |= EV_EOF;
  flags |= EV_ERROR;
  flags |= EV_DISABLE;
  flags |= EV_DELETE;
  EV_SET(&changes, fd, filter, flags, 0, 0, 0);
  kq |= kqueue();
  ret |= kevent(kq, &changes, 1, &events, 1, &ts);
  return 0 != ret;
}
EOF
  config_test_compile_and_link 'HAVE_KQUEUE'
  msg_yes_no $?
fi

if [ "x$HAVE_KQUEUE" != x ]; then
  msg_printf 'Looking whether kevent.udata is an integer ... '
  cat > config_test.c <<EOF
#include "config_test.h"
int
main(void) {
  static struct kevent ev;
  ev.udata |= 1;
  return 0;
}
EOF
  config_test_compile_and_link 'HAVE_KEVENT_INT_UDATA'
  msg_yes_no $?
fi


if [ "x${use_poll}" != x ]; then
  clear_var HAVE_EPOLL
else
  msg_printf 'Looking for epoll... '
  cat > config_test.c <<EOF
#include "config_test.h"
#include <sys/epoll.h>
int
main(void) {
  static struct epoll_event ev;
  static int n, ret, epfd;

  epfd |= epoll_create(n);
  
  ev.events = EPOLLIN; 
  ev.events = EPOLLOUT; 
  ev.events = EPOLLPRI; 
  ev.events = EPOLLERR; 
  ev.events = EPOLLHUP; 
  ev.events = EPOLLET; 
  ev.data.ptr = (void *) 0; 
  ev.data.fd = 1; 
  ev.data.u32 |= 1; 
  ev.data.u64 |= 1; 
  
  ret |= epoll_ctl(epfd, 1, EPOLL_CTL_ADD, &ev);
  ret |= epoll_ctl(epfd, 1, EPOLL_CTL_MOD, &ev);
  ret |= epoll_ctl(epfd, 1, EPOLL_CTL_DEL, &ev);
  
  ret |= epoll_wait(epfd, &ev, n, -1);

  return 0 != ret;
}
EOF
  config_test_compile_and_link 'HAVE_EPOLL'
  msg_yes_no $?
fi


msg_printf 'Looking for MSG_MORE... '
config_test_compile 'HAVE_MSG_MORE' 'send(1, 0, 1, MSG_MORE);'
msg_yes_no $?

if [ "x${use_dbopen}" != x ]; then
msg_printf 'Looking for dbopen() in <db.h> ... '
try_libs='db db2 db3 db4'
  cat > config_test.c <<EOF
#include "config_test.h"
#include <db.h>
int
main(void)
{
  DB *db;
  db = dbopen("/path/to/db", 1, 1, 0, (void *) 0);
  return 0;
}
EOF
config_test_compile_and_link 'HAVE_DBOPEN'
msg_yes_no $?
if [ "x${HAVE_DBOPEN}" != x ]; then
  HAVE_DB_H=1
  config_test_h_def 'HAVE_DB_H'
fi
unset try_libs


if [ "x${HAVE_DBOPEN}" = x ]; then
  msg_printf 'Looking for dbopen() in <db_185.h> ... '
  try_libs='db db2 db3 db4'
  cat > config_test.c <<EOF
#include "config_test.h"
#include <db_185.h>
  int
main(void)
{
  DB *db;
  db = dbopen("/path/to/db", 1, 1, 0, (void *) 0);
  return 0;
}
EOF

  config_test_compile_and_link 'HAVE_DBOPEN'
  msg_yes_no $?
  
  if [ "x${HAVE_DBOPEN}" != x ]; then
    HAVE_DB_185_H=1
    config_test_h_def 'HAVE_DB_185_H'
  fi

  unset try_libs
fi

fi  # use_dbopen


if [ "x${use_zlib}" != x ]; then
  check_std_header 'HAVE_ZLIB_H' 'zlib.h' && \
    echo '#include <zlib.h>' >> config_test.h
  config_test_h_def 'HAVE_ZLIB_H'

  msg_printf 'Looking for zlib support... '
  cat > config_test.c <<EOF
#include "config_test.h"
int
main(void)
{
  const char *ver = zlibVersion();
  static z_stream zs;
  static int ret;
  if (ver) {
    ret |= deflateInit(&zs, Z_DEFAULT_COMPRESSION); 
    ret |= deflate(&zs, Z_SYNC_FLUSH);
    ret |= deflate(&zs, Z_FULL_FLUSH);
    ret |= deflateEnd(&zs);
    ret |= inflateInit(&zs);
    ret |= inflate(&zs, Z_SYNC_FLUSH);
    ret |= inflate(&zs, Z_FINISH);
    ret |= inflateEnd(&zs);
  }
  return 0 != ret;
}
EOF

  try_libs='z'
  config_test_compile_and_link 'HAVE_ZLIB_SUPPORT'
  msg_yes_no $?
  unset try_libs
else
  clear_var HAVE_ZLIB_H
  clear_var HAVE_ZLIB_SUPPORT
fi


if [ "x${use_threads}" != x ]; then
  msg_printf 'Looking for POSIX thread support... '
  cat > config_test.c <<EOF
#include "config_test.h"

static void *
func(void *arg)
{
  return arg;
}

int
main(void)
{
  pthread_t t;
  static int ret;
  
  ret |= pthread_create(&t, NULL, func, NULL);
  return 0 != ret;
}
EOF

  saved_cflags=${CFLAGS}
  saved_ldflags=${LDFLAGS}
  CFLAGS="$CFLAGS -pthread"
  LDFLAGS="$LDFLAGS -pthread"

  config_test_compile_and_link 'HAVE_PTHREAD_SUPPORT'
  if [ $? -eq 0 ]; then
    msg_yes
  else
    CFLAGS="$saved_cflags"
    LDFLAGS="$saved_ldflags"

    try_libs='pthread pthreads'
    config_test_compile_and_link 'HAVE_PTHREAD_SUPPORT'
    msg_yes_no $?
    unset try_libs
  fi
else
  clear_var HAVE_PTHREAD_SUPPORT
fi

if [ "x${use_dlopen}" != x ]; then
  msg_printf 'Looking for dlopen()... '
  cat > config_test.c <<EOF
#include "config_test.h"
#include <dlfcn.h>

int
main(void)
{
  void *handle;

  handle = dlopen("", RTLD_LAZY);
  return 0;
}
EOF

  saved_ldflags="${LDFLAGS}"
  try_libs='dl'
  config_test_compile_and_link 'HAVE_DLOPEN'
  msg_yes_no $?
  unset try_libs
  if [ "x${LDFLAGS}" != "x${saved_ldflags}" ]; then
    LDFLAGS=${saved_ldflags}
    link_libdl='-ldl'
  fi
else
  clear_var HAVE_DLOPEN
fi

msg_printf 'Looking for big-endian... '
cat > config_test.c <<EOF
#include "config_test.h"
int
main(void)
{
#ifdef BYTE_ORDER
#if BYTE_ORDER == BIG_ENDIAN
#else
${assert_fail}
#endif
#endif

#ifdef _BYTE_ORDER
#if _BYTE_ORDER == BIG_ENDIAN
#else
${assert_fail}
#endif
#endif

#if !defined(BYTE_ORDER) && !defined(_BYTE_ORDER)
  switch (0) { case 0: case sizeof (char[htonl(0x11223344) == 0x11223344 ? 1 : -23]): break; }
#endif
  
  return 0;
}
EOF
config_test_c_compile 'HAVE_BIG_ENDIAN'
msg_yes_no $?

msg_printf 'Looking for little-endian... '
cat > config_test.c <<EOF
#include "config_test.h"
int
main(void)
{
#ifdef BYTE_ORDER
#if BYTE_ORDER == LITTLE_ENDIAN
#else
${assert_fail}
#endif
#endif

#ifdef _BYTE_ORDER
#if _BYTE_ORDER == LITTLE_ENDIAN
#else
${assert_fail}
#endif
#endif

#if !defined(BYTE_ORDER) && !defined(_BYTE_ORDER)
  switch (0) { case 0: case sizeof (char[htonl(0x11223344) == 0x44332211 ? 1 : -23]): break; }
#endif
  
  return 0;
}
EOF
config_test_c_compile 'HAVE_LITTLE_ENDIAN'
msg_yes_no $?


msg_printf 'Looking for sockaddr_un.sun_len ... '
cat > config_test.c <<EOF
#include "config_test.h"
int
main(void)
{
  static struct sockaddr_un addr;
  addr.sun_len |= 1;
  return 0;
}
EOF
config_test_c_compile 'HAVE_SOCKADDR_UN_SUN_LEN'
msg_yes_no $?

msg_printf 'Looking for msghdr.msg_accrights ... '
cat > config_test.c <<EOF
#include "config_test.h"
int
main(void)
{
  static struct msghdr msg;
  msg.msg_accrights = (void *) &msg;
  msg.msg_accrightslen |= sizeof msg;
  return 0;
}
EOF
config_test_c_compile 'HAVE_MSGHDR_ACCRIGHTS'
msg_yes_no $?

msg_printf 'Looking for msghdr.msg_control ... '
cat > config_test.c <<EOF
#include "config_test.h"
int
main(void)
{
  static struct msghdr msg;
  static struct cmsghdr cmsg;
  
  msg.msg_control = (void *) &cmsg;
  msg.msg_controllen |= sizeof cmsg;
  return 0;
}
EOF
config_test_c_compile 'HAVE_MSGHDR_CONTROL'
msg_yes_no $?

msg_printf 'Looking for msghdr.msg_flags ... '
cat > config_test.c <<EOF
#include "config_test.h"
int
main(void)
{
  static struct msghdr msg;
  
  msg.msg_flags |= 1;
  return 0;
}
EOF
config_test_c_compile 'HAVE_MSGHDR_CONTROL'
msg_yes_no $?

msg_printf 'Looking for bind() with "struct sockaddr" parameter... '
  cat > config_test.c <<EOF
#include "config_test.h"
int bind(int, const struct sockaddr *, socklen_t);
int
main(void)
{
  return 0;
}
EOF
config_test_compile_and_link 'HAVE_BIND_WITH_STRUCT_SOCKADDR'
msg_yes_no $?


msg_printf 'Looking for RPATH flag... '
saved_ldflags=${LDFLAGS}
for link_rpath in -rpath -R; do
    LDFLAGS="${saved_ldflags} -Wl,${link_rpath}/usr/lib"
    config_test_compile_and_link 'YADDA' ''
    if [ $? -eq 0 ]; then
      break;
    else
      link_rpath=''
    fi
done
LDFLAGS=${saved_ldflags}
unset saved_ldflags

if [ "x${link_rpath}" = x ]; then
  msg 'WARNING: unknown'
else
  msg "${link_rpath}"
fi

if [ "x${use_socker}" != x ]; then

msg_printf 'Looking for socker_get()... '
{
 # Ignore errors from socker-config because the flags can be provided manually
 socker_cflags=`socker-config --cflags`
 socker_ldflags=`socker-config --libs`
} >/dev/null 2>&1
saved_cflags=${CFLAGS}
saved_ldflags=${LDFLAGS}
CFLAGS="${CFLAGS:+$CFLAGS }${socker_cflags}"
LDFLAGS="${LDFLAGS:+$LDFLAGS }${socker_ldflags}"

cat > config_test.c <<EOF
#include "config_test.h"
#include <socker.h>
int
main(void)
{
  static int fd;
  fd |= socker_get(1, 2, 3, "", 5);
  return fd ? 0 : 1;
}
EOF
config_test_compile_and_link 'HAVE_SOCKER_GET'
msg_yes_no $?
if [ "x${HAVE_SOCKER_GET}" = x ]; then
  CFLAGS=${saved_cflags}
  LDFLAGS=${saved_ldflags}
fi
unset saved_cflags
unset saved_ldflags

fi # use_socker

HAVE_SHA1=
HAVE_NETBSD_SHA1=
HAVE_OPENBSD_SHA1=
HAVE_FREEBSD_SHA1=
HAVE_OPENSSL_SHA1=
HAVE_BEECRYPT_SHA1=

if [ "x${use_sha1}" != x ]; then

if [ "x${HAVE_SHA1}" = x ]; then
msg_printf 'Looking for NetBSD SHA-1 functions... '
cat > config_test.c <<EOF
#include "config_test.h"
#include <sha1.h>
int
main(void)
{
  static unsigned char data[100], md[20];
  SHA1_CTX ctx;
  SHA1Init(&ctx);
  SHA1Update(&ctx, data, sizeof data);
  SHA1Final(md, &ctx);
  return 0;
}
EOF
config_test_compile_and_link 'HAVE_SHA1'
msg_yes_no $?
HAVE_NETBSD_SHA1=${HAVE_SHA1}
fi

if [ "x${HAVE_SHA1}" = x ]; then
msg_printf 'Looking for FreeBSD SHA-1 functions... '
cat > config_test.c <<EOF
#include "config_test.h"
#include <sha.h>
int
main(void)
{
  static unsigned char data[100], md[20];
  SHA_CTX ctx;
  SHA1_Init(&ctx);
  SHA1_Update(&ctx, data, sizeof data);
  SHA1_Final(md, &ctx);
  return 0;
}
EOF
try_libs='md'
config_test_compile_and_link 'HAVE_SHA1'
msg_yes_no $?
HAVE_FREEBSD_SHA1=${HAVE_SHA1}
unset try_libs
fi

if [ "x${HAVE_SHA1}" = x ]; then
msg_printf 'Looking for OpenSSL SHA-1 functions... '
cat > config_test.c <<EOF
#include "config_test.h"
#include <openssl/sha.h>
int
main(void)
{
  static unsigned char data[100], md[20];
  SHA_CTX ctx;
  SHA1_Init(&ctx);
  SHA1_Update(&ctx, data, sizeof data);
  SHA1_Final(md, &ctx);
  return 0;
}
EOF
try_libs='crypto'
config_test_compile_and_link 'HAVE_SHA1'
msg_yes_no $?
HAVE_OPENSSL_SHA1=${HAVE_SHA1}
unset try_libs
fi

if [ "x${HAVE_SHA1}" = x ]; then
msg_printf 'Looking for BeeCrypt SHA-1 functions... '
cat > config_test.c <<EOF
#include "config_test.h"
#include <beecrypt/sha1.h>
int
main(void)
{
  static unsigned char data[100], md[20];
  sha1Param ctx;
  sha1Reset(&ctx);
  sha1Update(&ctx, data, sizeof data);
  sha1Digest(&ctx, md);
  return 0;
}
EOF
try_libs='beecrypt'
config_test_compile_and_link 'HAVE_SHA1'
msg_yes_no $?
HAVE_BEECRYPT_SHA1=${HAVE_SHA1}
unset try_libs
fi

fi # use_sha1


if [ "x${use_sqlite3}" != x ]; then

if [ "x${HAVE_SQLITE3}" = x ]; then
msg_printf 'Looking for SQLite3 functions... '
{
 # Ignore errors from sqlite3-config because the flags can be provided manually
 sqlite3_cflags=`pkg-config sqlite3 --cflags`
 sqlite3_ldflags=`pkg-config sqlite3 --libs`
} >/dev/null 2>&1
saved_cflags=${CFLAGS}
saved_ldflags=${LDFLAGS}
CFLAGS="${CFLAGS:+$CFLAGS }${sqlite3_cflags}"
LDFLAGS="${LDFLAGS:+$LDFLAGS }${sqlite3_ldflags}"

cat > config_test.c <<EOF
#include "config_test.h"
#include <sqlite3.h>
int
main(void)
{
  static sqlite3 *db;
  static int ret;
  char *errmsg;

  ret |= sqlite3_open("database", &db);
  ret |= sqlite3_exec(db, "BEGIN", (sqlite3_callback) 0, (void *) 0, &errmsg);
  
  return 0;
}
EOF

try_libs='sqlite3'
config_test_compile_and_link 'HAVE_SQLITE3'
msg_yes_no $?
unset try_libs

if [ "x${HAVE_SQLITE3}" = x ]; then
  CFLAGS=${saved_cflags}
  LDFLAGS=${saved_ldflags}
fi
unset saved_cflags
unset saved_ldflags

fi

fi # use_sqlite3


#
# Save the results to config.h
#

rm -f config.h
config_h_prolog

# Header files
config_h_def 'HAVE_INTTYPES_H'
config_h_def 'HAVE_STDBOOL_H'
config_h_def 'HAVE_STDLIB_H'
config_h_def 'HAVE_SYS_PARAM_H'
config_h_def 'HAVE_SYS_SOCKET_H'
config_h_def 'HAVE_SYS_EVENT_H'
config_h_def 'HAVE_SYS_TIME_H'
config_h_def 'HAVE_SYS_UN_H'
config_h_def 'HAVE_NETINET_IN_H'
config_h_def 'HAVE_ARPA_INET_H'
config_h_def 'HAVE_NETDB_H'
config_h_def 'HAVE_FEATURES_H'
config_h_def 'HAVE_PTHREAD_H'
config_h_def 'HAVE_PTHREAD_SUPPORT'

# Types
config_h_def 'HAVE_INT8_T'
config_h_def 'HAVE_INT16_T'
config_h_def 'HAVE_INT32_T'
config_h_def 'HAVE_INT64_T'
config_h_def 'HAVE_INTMAX_T'
config_h_def 'HAVE_INTPTR_T'
config_h_def 'HAVE_IN_ADDR_T'
config_h_def 'HAVE_IN_PORT_T'
config_h_def 'HAVE_SOCKLEN_T'
config_h_def 'HAVE_UINT8_T'
config_h_def 'HAVE_UINT16_T'
config_h_def 'HAVE_UINT32_T'
config_h_def 'HAVE_UINT64_T'
config_h_def 'HAVE_UINTMAX_T'
config_h_def 'HAVE_UINTPTR_T'

# Size of types
config_h_def 'SIZEOF_BOOL'
config_h_def 'SIZEOF_CHAR'
config_h_def 'SIZEOF_INT'
config_h_def 'SIZEOF_LONG'
config_h_def 'SIZEOF_LONG_LONG'
config_h_def 'SIZEOF_OFF_T'
config_h_def 'SIZEOF_SHORT'
config_h_def 'SIZEOF_SIZE_T'
config_h_def 'SIZEOF_UINTMAX_T'
config_h_def 'SIZEOF_UINTPTR_T'
config_h_def 'SIZEOF_VOID_PTR'

# C99 stuff
config_h_def 'HAVE_C99_VARIADIC_MACROS'
config_h_def 'HAVE_C99_func'
config_h_def 'HAVE_C99_inline'
config_h_def 'HAVE___inline'

# Functions
config_h_def 'HAVE_BEECRYPT_SHA1'
config_h_def 'HAVE_BIND_WITH_STRUCT_SOCKADDR'
config_h_def 'HAVE_BSD_STRUCT_RUSAGE'
config_h_def 'HAVE_CLOCK_GETTIME'
config_h_def 'HAVE_DBOPEN'
config_h_def 'HAVE_EPOLL'
config_h_def 'HAVE_FCHROOT'
config_h_def 'HAVE_FREEADDRINFO'
config_h_def 'HAVE_FREEBSD_SHA1'
config_h_def 'HAVE_GAI_STRERROR'
config_h_def 'HAVE_GETADDRINFO'
config_h_def 'HAVE_GETHOSTBYNAME'
config_h_def 'HAVE_GETPAGESIZE'
config_h_def 'HAVE_GETRUSAGE'
config_h_def 'HAVE_HERROR'
config_h_def 'HAVE_HSTRERROR'
config_h_def 'HAVE_KEVENT_INT_UDATA'
config_h_def 'HAVE_KQUEUE'
config_h_def 'HAVE_NETBSD_SHA1'
config_h_def 'HAVE_OPENSSL_SHA1'
config_h_def 'HAVE_SETPROCTITLE'
config_h_def 'HAVE_SHA1'
config_h_def 'HAVE_SOCKER_GET'
config_h_def 'HAVE_SQLITE3'
config_h_def 'HAVE_UNAME'

# Definitions and enums
config_h_def 'HAVE_BIG_ENDIAN'
config_h_def 'HAVE_LITTLE_ENDIAN'
config_h_def 'HAVE_MSG_MORE'
config_h_def 'HAVE_SHUT_RD'
config_h_def 'HAVE_SHUT_RDWR'
config_h_def 'HAVE_SHUT_WR'

# Structures
config_h_def 'HAVE_MSGHDR_ACCRIGHTS'
config_h_def 'HAVE_MSGHDR_CONTROL'
config_h_def 'HAVE_MSGHDR_FLAGS'
config_h_def 'HAVE_SOCKADDR_UN_SUN_LEN'

# Libraries
config_h_def 'HAVE_DB_185_H'
config_h_def 'HAVE_DB_H'
config_h_def 'HAVE_IPV6_SUPPORT'
config_h_def 'HAVE_SQLITE3'
config_h_def 'HAVE_ZLIB_H'
config_h_def 'HAVE_ZLIB_SUPPORT'

config_h_epilog

msg_printf '\nFinished, ready to build\n'

create_makefile 'src/lib'
create_makefile 'src'

exit
# vi: set ai et sts=2 sw=2 cindent: #
