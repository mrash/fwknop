dnl Fwknop AutoConf script...
dnl =========================
dnl
dnl Created by Damien Stuart
dnl
dnl Inspiration from RRDtool configure.ac, the AutoConf Archive
dnl (http://www.nongnu.org/autoconf-archive/), and other examples.

dnl Minimum Autoconf version required.
AC_PREREQ([2.62])

dnl Define our name, version and email.
m4_define(my_package,   [fwknop])
m4_define(my_version,   [2.6.11])
m4_define(my_bug_email, [dstuart@dstuart.org])

AC_INIT([my_package],[my_version],[my_bug_email])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR(config)

AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([subdir-objects])

dnl AM_MAINTAINER_MODE

AC_CONFIG_HEADERS([config.h])

dnl The top of our header
dnl
AH_TOP([
#ifndef FWKNOP_CONFIG_H
#define FWKNOP_CONFIG_H
])

dnl The bottom of our header file
dnl
AH_BOTTOM([
#endif /* FWKNOP_CONFIG_H */
])

dnl FKO_CHECK_COMPILER_ARG([COMPILER FLAG])
dnl
dnl Macro to check compiler support for the given compiler option.
dnl Adds to CFLAGS and LDFLAGS if supported.
dnl
dnl The structure of this macro was adapted from OpenSSH.
dnl
AC_DEFUN([FKO_CHECK_COMPILER_ARG], [
    saved_CFLAGS="$CFLAGS"
    saved_LDFLAGS="$LDFLAGS"
    CFLAGS="$CFLAGS $1 -Werror"
    LDFLAGS="$LDFLAGS $1 -Werror"
    AC_MSG_CHECKING([if $CC supports $1])
    AC_LINK_IFELSE(
        [AC_LANG_SOURCE([
#include <stdio.h>
int main(void){char x[[256]]; snprintf(x, sizeof(x), "NNN"); return 0;}
        ])],
        [
            CFLAGS="$saved_CFLAGS $1"
            LDFLAGS="$saved_LDFLAGS $1"
            AC_RUN_IFELSE(
                [AC_LANG_SOURCE([
#include <stdio.h>
int main(void){char x[[256]]; snprintf(x, sizeof(x), "NNN"); return 0;}
                ])],
                [AC_MSG_RESULT(yes)],
                [AC_MSG_RESULT(no)
                    CFLAGS="$saved_CFLAGS"
                    LDFLAGS="$saved_LDFLAGS"],
                [AC_MSG_WARN([cross compiling: cannot test])])
        ],
        [AC_MSG_RESULT(no)
            CFLAGS="$saved_CFLAGS"
            LDFLAGS="$saved_LDFLAGS"]
    )])dnl

dnl FKO_CHECK_COMPILER_ARG_LDFLAGS_ONLY([COMPILER FLAG])
dnl
dnl Macro to check compiler support for the given compiler option.
dnl Adds to LDFLAGS only if supported.
dnl
AC_DEFUN([FKO_CHECK_COMPILER_ARG_LDFLAGS_ONLY], [
    saved_LDFLAGS="$LDFLAGS"
    LDFLAGS="$LDFLAGS $1 -Werror"
    AC_MSG_CHECKING([if $CC supports $1])
    AC_LINK_IFELSE(
        [AC_LANG_SOURCE([
#include <stdio.h>
int main(void){char x[[256]]; snprintf(x, sizeof(x), "NNN"); return 0;}
        ])],
        [
            LDFLAGS="$saved_LDFLAGS $1"
            AC_RUN_IFELSE(
                [AC_LANG_SOURCE([
#include <stdio.h>
int main(void){char x[[256]]; snprintf(x, sizeof(x), "NNN"); return 0;}
                ])],
                [AC_MSG_RESULT(yes)],
                [AC_MSG_RESULT(no)
                    LDFLAGS="$saved_LDFLAGS"],
                [AC_MSG_WARN([cross compiling: cannot test])])
        ],
        [AC_MSG_RESULT(no)
            LDFLAGS="$saved_LDFLAGS"]
    )])dnl

AC_USE_SYSTEM_EXTENSIONS

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_AWK
AC_PROG_SED
AC_PROG_GREP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
LT_INIT

dnl Detect if we are on and Apple platform
dnl
AM_CONDITIONAL([APPLE_PLATFORM], [test `uname -s` = Darwin])

dnl Decide whether or not to build binaries with profiling coverage support
dnl
want_profile_coverage=no
AC_ARG_ENABLE([profile-coverage],
  [AS_HELP_STRING([--enable-profile-coverage],
    [Build fwknop binaries with profile coverage support @<:@default is to disable@:>@])],
  [want_profile_coverage=$enableval],
  [])

if test "x$want_profile_coverage" = "xyes"; then
    FKO_CHECK_COMPILER_ARG([-fprofile-arcs -ftest-coverage -fno-inline])
    FKO_CHECK_COMPILER_ARG([-g])
    FKO_CHECK_COMPILER_ARG_LDFLAGS_ONLY([-lgcov])
    AC_DEFINE([CODE_COVERAGE], [1], [Define for code coverage support])
fi

dnl Decide whether or not to build binaries with fault injection support
dnl provided by libfiu (see: http://blitiri.com.ar/p/libfiu/) for fault
dnl testing
dnl
want_libfiu_support=no
AC_ARG_ENABLE([libfiu-support],
  [AS_HELP_STRING([--enable-libfiu-support],
    [Build fwknop binaries with fault injection testing support @<:@default is to disable@:>@])],
  [want_libfiu_support=$enableval],
  [])

if test "x$want_libfiu_support" = "xyes"; then
    AC_DEFINE([HAVE_LIBFIU], [1], [Define for fault injection testing support])
    FKO_CHECK_COMPILER_ARG([-DFIU_ENABLE])
    FKO_CHECK_COMPILER_ARG_LDFLAGS_ONLY([-lfiu])
fi

AM_CONDITIONAL([WANT_LIBFIU_SUPPORT], [test "$want_libfiu_support" = yes])

dnl Decide whether or not to enable C unit testing
dnl
want_c_unit_tests=no
AC_ARG_ENABLE([c-unit-tests],
  [AS_HELP_STRING([--enable-c-unit-tests],
    [Enable C unit testing with libcunit support @<:@default is to disable@:>@])],
  [want_c_unit_tests=$enableval],
  [])

if test "x$want_c_unit_tests" = "xyes"; then
    AC_DEFINE([HAVE_C_UNIT_TESTS], [1], [Define for C unit testing support])
    FKO_CHECK_COMPILER_ARG([-DHAVE_C_UNIT_TESTS])
    FKO_CHECK_COMPILER_ARG_LDFLAGS_ONLY([-lcunit])
fi

AM_CONDITIONAL([WANT_C_UNIT_TESTS], [test "$want_c_unit_tests" = yes])

dnl Decide whether or not to enable address sanitizer support
dnl
want_asan_support=no
AC_ARG_ENABLE([asan-support],
  [AS_HELP_STRING([--enable-asan-support],
    [Build fwknop binaries with AddressSanitizer support @<:@default is to disable@:>@])],
  [want_asan_support=$enableval],
  [])

if test "x$want_asan_support" = "xyes"; then
    FKO_CHECK_COMPILER_ARG([-fsanitize=address -fno-omit-frame-pointer])
fi

dnl Decide whether or not to enable UndefineSanitizer support
dnl
want_ubsan_support=no
AC_ARG_ENABLE([ubsan-support],
  [AS_HELP_STRING([--enable-ubsan-support],
    [Build fwknop binaries with UndefinedBehaviorSanitizer support @<:@default is to disable@:>@])],
  [want_ubsan_support=$enableval],
  [])

if test "x$want_ubsan_support" = "xyes"; then
    FKO_CHECK_COMPILER_ARG([-fsanitize=undefined])
fi

dnl Decide whether or not to enable MemorySanitizer support
dnl
want_memsan_support=no
AC_ARG_ENABLE([memsan-support],
  [AS_HELP_STRING([--enable-memsan-support],
    [Build fwknop binaries with MemorySanitizer support @<:@default is to disable@:>@])],
  [want_memsan_support=$enableval],
  [])

if test "x$want_memsan_support" = "xyes"; then
    FKO_CHECK_COMPILER_ARG([-fsanitize=memory -fsanitize-memory-track-origins=2])
fi

dnl Decide whether or not force 32-bit mode
dnl
want_32bit_mode=no
AC_ARG_ENABLE([32bit-mode],
  [AS_HELP_STRING([--enable-32bit-mode],
    [Build 32-bit fwknop binaries @<:@default is to disable@:>@])],
  [want_32bit_mode=$enableval],
  [])

if test "x$want_32bit_mode" = "xyes"; then
    FKO_CHECK_COMPILER_ARG([-m32])
fi

dnl Decide whether or not to compile in certain features that enable fuzzing
dnl of fwknop code - this is for testing purposes only.
dnl
want_fuzzing_interfaces=no
AC_ARG_ENABLE([fuzzing-interfaces],
  [AS_HELP_STRING([--enable-fuzzing-interfaces],
    [Build fwknop binaries with support for fuzzing interfaces @<:@default is to disable@:>@])],
  [want_fuzzing_interfaces=$enableval],
  [])

if test "x$want_fuzzing_interfaces" = "xyes"; then
    AC_DEFINE([FUZZING_INTERFACES], [1], [Define for fuzzing interfaces support])
fi

dnl Decide whether or not to compile in support for the 'American Fuzzy Lop'
dnl fuzzer from Michal Zalewski - this is for testing purposes only
dnl
want_afl_fuzzing_support=no
AC_ARG_ENABLE([afl-fuzzing],
  [AS_HELP_STRING([--enable-afl-fuzzing],
    [Build fwknop binaries with support for the American Fuzzy Lop fuzzer @<:@default is to disable@:>@])],
  [want_afl_fuzzing_support=$enableval],
  [])

if test "x$want_afl_fuzzing_support" = "xyes"; then
    AC_DEFINE([AFL_FUZZING], [1], [Define for AFL fuzzing support])
    AC_DEFINE([FUZZING_INTERFACES], [1], [Define for fuzzing interfaces support])
fi

dnl Decide whether or not to enable UDP server mode (no libpcap dependency)
dnl
want_udp_server=no
AC_ARG_ENABLE([udp-server],
  [AS_HELP_STRING([--enable-udp-server],
    [Enable UDP server mode for no libpcap dependency @<:@default is to disable@:>@])],
  [want_udp_server=$enableval],
  [])
AM_CONDITIONAL([UDP_SERVER], [test "$want_udp_server" = yes])

dnl Decide whether or not to enable UDP server mode (no libpcap dependency)
dnl
want_nfq_capture=no
AC_ARG_ENABLE([nfq-capture],
  [AS_HELP_STRING([--enable-nfq-capture],
    [Enable NF_QUEUE server mode for no libpcap dependency @<:@default is to disable@:>@])],
  [want_nfq_capture=$enableval],
  [])
AM_CONDITIONAL([NFQ_CAPTURE], [test "$want_nfq_capture" = yes])

dnl Decide whether or not to enable all warnings with -Wall
dnl
use_wall=yes
AC_ARG_ENABLE([wall],
  [AS_HELP_STRING([--disable-wall],
    [Do not enable warnings via -Wall -Wformat -Wformat-security @<:@default is on@:>@])],
  [use_wall=$enableval],
  [])

if test "x$use_wall" = "xyes"; then
    FKO_CHECK_COMPILER_ARG([-Wall -Wformat -Wformat-security])
fi

dnl Check for security features offered by the compiler

dnl -fstack-protector-all doesn't always work for some GCC versions
dnl and/or platforms, so we test if we can.  If it's not supported
dnl on a given platform gcc will emit a warning so we use -Werror.
dnl
dnl Decide whether or not to enable -fstack-protector
dnl
use_stack_protector=yes
AC_ARG_ENABLE([stack-protector],
  [AS_HELP_STRING([--disable-stack-protector],
    [Do not enable -fstack-protector @<:@default is on@:>@])],
  [use_stack_protector=$enableval],
  [])

if test "x$use_stack_protector" = "xyes"; then
    FKO_CHECK_COMPILER_ARG([-fstack-protector-all -fstack-protector])
fi

dnl Decide whether or not to enable Position Independent Executable (PIE)
dnl support
dnl
use_pie=yes
AC_ARG_ENABLE([pie],
  [AS_HELP_STRING([--disable-pie],
    [Do not enable Position Independent Executable support @<:@default is on@:>@])],
  [use_pie=$enableval],
  [])

if test "x$use_pie" = "xyes"; then
    FKO_CHECK_COMPILER_ARG([-fPIE -fPIC])
    FKO_CHECK_COMPILER_ARG_LDFLAGS_ONLY([-pie -fPIC])
fi

dnl Decide whether or not to enable -D_FORTIFY_SOURCE support
dnl
use_fortify_source=yes
AC_ARG_ENABLE([fortify-source],
  [AS_HELP_STRING([--disable-fortify-source],
    [Do not enable -D_FORTIFY_SOURCE support @<:@default is on@:>@])],
  [use_fortify_source=$enableval],
  [])

if test "x$use_fortify_source" = "xyes"; then
    FKO_CHECK_COMPILER_ARG([-D_FORTIFY_SOURCE=2])
fi

dnl Decide whether or not to use read-only relocations protection
dnl
use_ro_relocations=yes
AC_ARG_ENABLE([ro-relocations],
  [AS_HELP_STRING([--disable-ro-relocations],
    [Do not enable read-only relocations protection @<:@default is on@:>@])],
  [use_ro_relocations=$enableval],
  [])

if test "x$use_ro_relocations" = "xyes"; then
    FKO_CHECK_COMPILER_ARG_LDFLAGS_ONLY([-Wl,-z,relro])
fi

dnl Decide whether or not to use immediate binding protection
dnl
use_immediate_binding=yes
AC_ARG_ENABLE([immediate-binding],
  [AS_HELP_STRING([--disable-immediate-binding],
    [Do not enable immediate binding protection @<:@default is on@:>@])],
  [use_immediate_binding=$enableval],
  [])

if test "x$use_immediate_binding" = "xyes"; then
    FKO_CHECK_COMPILER_ARG_LDFLAGS_ONLY([-Wl,-z,now])
fi

# Checks for header files.
#

AC_HEADER_RESOLV

AC_CHECK_HEADERS([arpa/inet.h ctype.h endian.h errno.h locale.h netdb.h net/ethernet.h netinet/in.h stdint.h stdlib.h string.h strings.h sys/byteorder.h sys/endian.h sys/ethernet.h sys/socket.h sys/stat.h sys/time.h sys/wait.h termios.h time.h unistd.h])

# Type checks.
#
AC_C_CONST
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

AC_CHECK_SIZEOF(unsigned int)
dnl AC_CHECK_TYPES([uint8_t, uint32_t])

AC_C_BIGENDIAN

AC_SYS_LARGEFILE

# Checks for library functions.
#
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STAT

AC_CHECK_FUNCS([bzero fileno gettimeofday memmove memset socket strchr strcspn strdup strncasecmp strndup strrchr strspn strnlen fstat stat lstat chmod chown strlcat strlcpy])

dnl Decide whether or not to check for the execvp() function
dnl
use_execvp=yes
AC_ARG_ENABLE([execvp],
  [AS_HELP_STRING([--disable-execvp],
    [Do not check for the execvp() function for command execution @<:@default is on@:>@])],
  [use_execvp=$enableval],
  [])

if test "x$use_execvp" = "xyes"; then
    AC_CHECK_FUNCS([execvp])
fi

AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([inet_addr], [nsl])

AM_CONDITIONAL(MINGW, false)

use_mingw=no

case "$host" in
*-*-linux*)
    ;;
*-*-netbsd*)
    AC_DEFINE_UNQUOTED([PLATFORM_NETBSD], [1], [Define if you are running on NetBSD])
    ;;
*-*-openbsd*)
    AC_DEFINE_UNQUOTED([PLATFORM_OPENBSD], [1], [Define if you are running on OpenBSD])
    ;;
*-mingw32*)
    AC_DEFINE_UNQUOTED(MINGW,1,[This is a MinGW system])
    use_mingw=yes
    ;;
esac

AM_CONDITIONAL(USE_MINGW, [test x$use_mingw = xyes])

dnl Decide whether or not to build the client
dnl
want_client=yes
AC_ARG_ENABLE([client],
  [AS_HELP_STRING([--disable-client],
    [Do not build the fwknop client @<:@default is to build@:>@])],
  [want_client=$enableval],
  [])
AM_CONDITIONAL([WANT_CLIENT], [test "$want_client" = yes])

dnl Decide whether or not to build the server
dnl
want_server=yes
AC_ARG_ENABLE([server],
  [AS_HELP_STRING([--disable-server],
    [Do not build the fwknop server @<:@default is to build@:>@])],
  [want_server=$enableval],
  [])
AM_CONDITIONAL([WANT_SERVER], [test "$want_server" = yes])

dnl Decide whether or not to enable the digest-cache
dnl
want_digest_cache=yes
AC_ARG_ENABLE([digest-cache],
  [AS_HELP_STRING([--disable-digest-cache],
    [Do not enable the fwknopd digest-cache @<:@default is to build@:>@])],
  [want_digest_cache=$enableval],
  [])
dnl AM_CONDITIONAL([WANT_DIGEST_CACHE], [test "$want_digest_cache" = yes])

dnl Decide whether or not to try to look for gdbm/ndbm (default to just
dnl use a file-based solution - reduces dependencies)
dnl
want_file_cache=yes
AC_ARG_ENABLE([file-cache],
  [AS_HELP_STRING([--disable-file-cache],
    [Replace file cache with gdbm/ndbm @<:@default=no@:>@])],
  [want_file_cache=$enableval],
  [])
AS_IF([test "$want_file_cache" = yes], [
    AC_DEFINE([USE_FILE_CACHE], [1], [Define this to enable non-gdbm/ndbm digest storing (eliminates gdbm/ndbm dependency).])
])

# Check for 3rd-party libs
#
AC_ARG_WITH([gpgme],
  [AS_HELP_STRING([--with-gpgme],
    [support for gpg encryption using libgpgme @<:@default=check@:>@])],
  [],
  [with_gpgme=check])

have_gpgme=yes
AS_IF([test "x$with_gpgme" != xno],
  [AM_PATH_GPGME([],
    [AC_DEFINE([HAVE_LIBGPGME], [1], [Define if you have libgpgme])],
    [if test "x$with_gpgme" != xcheck; then
       AC_MSG_FAILURE(
         [--with-gpgme was given, but test for gpgme failed])
     else
       have_gpgme=no
     fi
    ], [have_gpgme=no])], [have_gpgme=no])

dnl Add various common way to sbin dir to the path (just in case)
  APP_PATH=$PATH$PATH_SEPARATOR/sbin$PATH_SEPARATOR/usr/sbin$PATH_SEPARATOR/usr/local/sbin

dnl Check for gpg (not gpg2)
dnl
AC_ARG_WITH([gpg],
  [AS_HELP_STRING([--with-gpg=/path/to/gpg],
    [Specify path to the gpg executable that gpgme will use @<:@default=check path@:>@])],
  [
      AS_IF([ test "x$withval" = x -o "x$withval" = xyes -o "x$withval" = xno ],
        [AC_MSG_ERROR([--with-gpg requires an argument specifying a path to gpg])],
        [ GPG_EXE=$withval ]
      )
  ],
  [
      AC_PATH_PROG(GPG_EXE, [gpg], [], [$APP_PATH])
  ]
)
AS_IF([test "x$GPG_EXE" != x],
  [
    AC_DEFINE_UNQUOTED([GPG_EXE], ["$GPG_EXE"], [Path to gpg executable])
    gpg_exe=$GPG_EXE
  ], [ gpg_exe="(not found)"]
)

if [test "$have_gpgme" = "yes" ]; then
case "$host" in
*-*-linux*)
    ;;
*-*-freebsd*)
    if [ test "x$CPPFLAGS" = "x" ] ; then
        CPPFLAGS="-I/usr/local/include -I/usr/local/include/gpgme"
    fi
    if [ test "x$LDFLAGS" = "x" ] ; then
        LDFLAGS="-L/usr/local/lib"
    fi
    ;;
esac
fi

dnl Check for wget (used by the fwknop client for SSL external IP resolution)
dnl
AC_ARG_WITH([wget],
  [AS_HELP_STRING([--with-wget=/path/to/wget],
    [Specify path to the wget executable @<:@default=check path@:>@])],
  [
      AS_IF([ test "x$withval" = x -o "x$withval" = xyes -o "x$withval" = xno ],
        [AC_MSG_ERROR([--with-wget requires an argument specifying a path to wget])],
        [ WGET_EXE=$withval ]
      )
  ],
  [
      AC_PATH_PROG(WGET_EXE, [wget], [], [$APP_PATH])
  ]
)
AS_IF([test "x$WGET_EXE" != x],
  [
    AC_DEFINE_UNQUOTED([WGET_EXE], ["$WGET_EXE"], [Path to wget executable])
    wget_exe=$WGET_EXE
  ], [ wget_exe="(not found)"]
)

dnl Check for libpcap, gdbm (or ndbm) if we are building the server component
dnl
AS_IF([test "$want_server" = yes], [

  AS_IF([test "$want_udp_server" = no -a "$want_nfq_capture" = no], [
    # Looking for libpcap
    #
    AC_CHECK_LIB([pcap],[pcap_open_live],
      [ AC_DEFINE([USE_LIBPCAP], [1], [Define if you have libpcap]) ],
      [ AC_MSG_ERROR([fwknopd needs libpcap])]
    )
  ])

  AS_IF([test "$want_nfq_capture" = yes], [
    # Check for libnetfilter_queue
    #
    AC_CHECK_LIB([netfilter_queue],[nfq_open],
      [ AC_DEFINE([USE_LIBNETFILTER_QUEUE], [1], [Define if you have libnetfilter_queue]) ],
      [ AC_MSG_ERROR([fwknopd needs libnetfilter_queue])]
    )
  ])

  AS_IF([test "$want_digest_cache" = yes], [
    use_ndbm=no
    have_digest_cache=yes

    AS_IF([test "$want_file_cache" = no], [

      # Looking for gdbm or fallback to ndbm or bail
      #
      AC_CHECK_LIB([gdbm],[gdbm_open],
          [
              AC_DEFINE([HAVE_LIBGDBM], [1], [Define if you have libgdbm])
          ],
          [ AC_CHECK_LIB([ndbm],[dbm_open],
              [
                  AC_DEFINE([HAVE_LIBNDBM], [1], [Define if you have libndbm])
                  use_ndbm=yes
              ],
              [ AC_CHECK_HEADER([ndbm.h],
                  [ AC_CHECK_FUNC([dbm_open],
                      [ AC_DEFINE([HAVE_LIBNDBM], [1], [Define if you have libndbm])],
                      [
                          AC_DEFINE([NO_DIGEST_CACHE], [1], [Define this to disable the digest cache for replay detection - not recommended.])
                          AC_MSG_WARN([No DBM implementation found. Replay detection will be disabled.])
                          have_digest_cache=no
                      ]
                  )]
              )]
          )]
      )]
    )],
    [
        AC_DEFINE([NO_DIGEST_CACHE], [1], [Define this to disable the digest cache for replay detection - not recommended.])
        have_digest_cache=no
    ]
  )

  AM_CONDITIONAL([USE_NDBM], [test x$use_ndbm = xyes])
  AM_CONDITIONAL([CONFIG_FILE_CACHE], [test x$want_file_cache = xyes])

dnl Check for firewalld
dnl
  AC_ARG_WITH([firewall-cmd],
    [AS_HELP_STRING([--with-firewall-cmd=/path/to/firewall-cmd],
      [Specify path to the firewall-cmd executable @<:@default=check path@:>@])],
    [
      AS_IF([ test "x$withval" = xno ], [],
        AS_IF([ test "x$withval" = x -o "x$withval" = xyes ],
          [AC_MSG_ERROR([--with-firewall-cmd requires an argument specifying a path to firewall-cmd])],
          [ FORCE_FIREWALLD_EXE=$withval ]
        )
      )
    ],
    [
      AC_PATH_PROG(FIREWALLD_EXE, [firewall-cmd], [], [$APP_PATH])
    ]
  )

  AC_ARG_WITH([firewalld],
    [AS_HELP_STRING([--with-firewalld=/path/to/firewall-cmd],
      [Synonym for --with-firewall-cmd, specify path to the firewall-cmd executable @<:@default=check path@:>@])],
    [
      AS_IF([ test "x$withval" = xno ], [],
        AS_IF([ test "x$withval" = x -o "x$withval" = xyes ],
          [AC_MSG_ERROR([--with-firewalld requires an argument specifying a path to firewall-cmd])],
          [ FORCE_FIREWALLD_EXE=$withval ]
        )
      )
    ],
    [
     AC_PATH_PROG(FIREWALLD_EXE, [firewalld], [], [$APP_PATH])
    ]
  )

dnl Check for iptables
dnl
  AC_ARG_WITH([iptables],
    [AS_HELP_STRING([--with-iptables=/path/to/iptables],
      [Specify path to the iptables executable @<:@default=check path@:>@])],
    [
      AS_IF([ test "x$withval" = xno ], [],
        AS_IF([ test "x$withval" = x -o "x$withval" = xyes ],
          [AC_MSG_ERROR([--with-iptables requires an argument specifying a path to iptables])],
          [ FORCE_IPTABLES_EXE=$withval ]
        )
      )
    ],
    [
      AC_PATH_PROG(IPTABLES_EXE, [iptables], [], [$APP_PATH])
    ]
  )

dnl Check for ipfw
dnl
  AC_ARG_WITH([ipfw],
    [AS_HELP_STRING([--with-ipfw=/path/to/ipfw],
      [Specify path to the ipfw executable @<:@default=check path@:>@])],
    [
      AS_IF([ test "x$withval" = xno ], [],
        AS_IF([ test "x$withval" = x -o "x$withval" = xyes ],
          [AC_MSG_ERROR([--with-ipfw requires an argument specifying a path to ipfw])],
          [ FORCE_IPFW_EXE=$withval ]
        )
      )
    ],
    [
      AC_PATH_PROG(IPFW_EXE, [ipfw], [], [$APP_PATH])
    ]
  )

dnl Check for pf from OpenBSD
dnl
  AC_ARG_WITH([pf],
    [AS_HELP_STRING([--with-pf=/path/to/pfctl],
      [Specify path to the pf executable @<:@default=check path@:>@])],
    [
      AS_IF([ test "x$withval" = xno ], [],
        AS_IF([ test "x$withval" = x -o "x$withval" = xyes ],
          [AC_MSG_ERROR([--with-pf requires an argument specifying a path to pf])],
          [ FORCE_PF_EXE=$withval ]
        )
      )
    ],
    [
      AC_PATH_PROG(PF_EXE, [pfctl], [], [$APP_PATH])
    ]
  )

dnl Check for ipf (ipfilter)
dnl
  AC_ARG_WITH([ipf],
    [AS_HELP_STRING([--with-ipf=/path/to/ipf],
      [Specify path to the ipf executable @<:@default=check path@:>@])],
    [
      AS_IF([ test "x$withval" = xno ], [],
        AS_IF([ test "x$withval" = x -o "x$withval" = xyes ],
          [AC_MSG_ERROR([--with-ipf requires an argument specifying a path to ipf])],
          [ FORCE_IPF_EXE=$withval ]
        )
      )
    ],
    [
      AC_PATH_PROG(IPF_EXE, [ipf], [], [$APP_PATH])
    ]
  )

dnl If a firewall was forced. set the appropriate _EXE var and clear the others.
dnl
  AS_IF([test "x$FORCE_FIREWALLD_EXE" != x], [
    FIREWALLD_EXE="$FORCE_FIREWALLD_EXE"
  ],[
    AS_IF([test "x$FORCE_IPTABLES_EXE" != x], [
      IPTABLES_EXE="$FORCE_IPTABLES_EXE"
      FIREWALLD_EXE=""
    ],[
      AS_IF([test "x$FORCE_IPFW_EXE" != x], [
        IPFW_EXE="$FORCE_IPFW_EXE"
        IPTABLES_EXE=""
        FIREWALLD_EXE=""
      ],[
        AS_IF([test "x$FORCE_PF_EXE" != x], [
          PF_EXE="$FORCE_PF_EXE"
          IPFW_EXE=""
          IPTABLES_EXE=""
          FIREWALLD_EXE=""
        ],[
          AS_IF([test "x$FORCE_IPF_EXE" != x], [
            IPF_EXE="$FORCE_IPF_EXE"
            PF_EXE=""
            IPFW_EXE=""
            IPTABLES_EXE=""
            FIREWALLD_EXE=""
          ],[:]
        ]
      ]
    ]
  ]
  )))))

dnl Determine which firewall exe we use (if we have one).
dnl If firewalld was found or specified, it wins, then we fallback to iptables,
dnl then ipfw, pf, and otherwise we try ipf.
dnl
  AS_IF([test "x$FIREWALLD_EXE" != x], [
      FW_DEF="FW_FIREWALLD"
      FIREWALL_TYPE="firewalld"
      FIREWALL_EXE=$FIREWALLD_EXE
      AC_DEFINE_UNQUOTED([FIREWALL_FIREWALLD], [1], [The firewall type: firewalld.])
  ],[
    AS_IF([test "x$IPTABLES_EXE" != x], [
        FW_DEF="FW_IPTABLES"
        FIREWALL_TYPE="iptables"
        FIREWALL_EXE=$IPTABLES_EXE
        AC_DEFINE_UNQUOTED([FIREWALL_IPTABLES], [1], [The firewall type: iptables.])
    ],[
      AS_IF([test "x$IPFW_EXE" != x], [
          FW_DEF="FW_IPFW"
          FIREWALL_TYPE="ipfw"
          FIREWALL_EXE=$IPFW_EXE
          AC_DEFINE_UNQUOTED([FIREWALL_IPFW], [1], [The firewall type: ipfw.])
      ],[
          AS_IF([test "x$PF_EXE" != x], [
              FW_DEF="FW_PF"
              FIREWALL_TYPE="pf"
              FIREWALL_EXE=$PF_EXE
              AC_DEFINE_UNQUOTED([FIREWALL_PF], [1], [The firewall type: pf.])
          ],[
              AS_IF([test "x$IPF_EXE" != x], [
                AC_MSG_ERROR([Sorry - ipf was specified or the only one found, however, it is not supported yet.])
                FIREWALL_TYPE="ipf"
                FIREWALL_EXE=$IPF_EXE
                AC_DEFINE_UNQUOTED([FIREWALL_IPF], [1], [The firewall type: ipf.])
            ], [AC_MSG_ERROR([No firewall program was found or specified.]) ]
          ]
      ]
    ]
  ]
  )))))

  AC_DEFINE_UNQUOTED([FIREWALL_EXE], ["$FIREWALL_EXE"],
    [Path to firewall command executable (it should match the firewall type).])

  ],
  [test "$want_server" = no], [
    use_ndbm=no
    AM_CONDITIONAL([USE_NDBM], [test x$use_ndbm = xno])
    AM_CONDITIONAL([CONFIG_FILE_CACHE], [test x$use_ndbm = xno])
  ]
)

AC_CONFIG_FILES([Makefile
                 lib/Makefile
                 client/Makefile
                 server/Makefile
                 common/Makefile
                 doc/Makefile])

AC_OUTPUT

if [test "$have_gpgme" = "yes" ]; then
    have_gpgme="$have_gpgme
                  Gpgme engine:     $GPG_EXE"
fi

echo "
    $PACKAGE_NAME-$PACKAGE_VERSION configuration.
    ==========================================================
        Client build:               $want_client
        Server build:               $want_server
        GPG encryption support:     $have_gpgme

        Installation prefix:        $prefix
"
if [test "$want_server" = "yes" ]; then
  echo "    Server support:
        firewall type:              $FIREWALL_TYPE
        firewall program path:      $FIREWALL_EXE
"
if [test "$want_udp_server" = "yes" ]; then
  echo "    UDP server mode enabled, no libpcap dependency
"
    fi
if [test "$want_nfq_capture" = "yes" ]; then
  echo "    Netfilter Queue server mode enabled, no libpcap dependency
"
    fi

    if [test "$want_digest_cache" = "no" ]; then
        echo "    *WARNING*
        The digest-cache functionality is not enabled.  This
        could leave the fwknopd server open to replay attacks!
"
    fi
fi
