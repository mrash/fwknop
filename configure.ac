dnl Fwknop AutoConf script...
dnl =========================
dnl
dnl Created by Damien Stuart
dnl
dnl Inspiration from RRDtool configure.ac, the AutoConf Archive
dnl (http://www.nongnu.org/autoconf-archive/), and other examples.

dnl Minimum Autoconf version required.
AC_PREREQ(2.61)

dnl Define our name, version and email.
m4_define(my_package,   [fwknop])
m4_define(my_version,   [2.0.0-beta-rc1])
m4_define(my_bug_email, [dstuart@dstuart.org])

AC_INIT(my_package, my_version, my_bug_email)

AC_CONFIG_AUX_DIR(config)

AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([tar-ustar -Wall -Werror foreign])

dnl AM_MAINTAINER_MODE

AC_CONFIG_HEADER([config.h])

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

AC_GNU_SOURCE

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_AWK
AC_PROG_SED
AC_PROG_GREP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_PROG_LIBTOOL

# Checks for header files.
#
AC_HEADER_STDC
AC_HEADER_TIME
AC_HEADER_RESOLV

AC_CHECK_HEADERS([ctype.h endian.h errno.h locale.h netdb.h net/ethernet.h netinet/ether.h netinet/ip_icmp.h netinet/in.h netinet/ip.h netinet/tcp.h netinet/udp.h stdint.h stdlib.h string.h strings.h sys/byteorder.h sys/endian.h sys/ethernet.h sys/socket.h sys/stat.h sys/time.h termios.h unistd.h])

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

# Checks for library functions.
#
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STAT

AC_CHECK_FUNCS([bzero gettimeofday memmove memset socket strchr strcspn strdup strncasecmp strndup strrchr strspn])

AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([inet_addr], [nsl])

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

dnl Check for libpcap, gdbm (or ndbm) if we are building the server component
dnl
AS_IF([test "$want_server" = yes], [
  # Looking for libpcap
  #
  AC_CHECK_LIB([pcap],[pcap_open_live], [],
    [ AC_MSG_ERROR([fwknopd needs libpcap])]
  )

  # Looking for gdbm or fallback to ndbm or bail
  #
  AC_CHECK_LIB([gdbm],[gdbm_open], [], 
    [ AC_CHECK_LIB([ndbm],[dbm_open], [],
        [ AC_MSG_ERROR([fwknopd needs either gdbm or ndbm])]
    )]
  )

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
          [
            AC_CHECK_FILE([$withval], [], [
              AC_MSG_WARN([Specified path to gpg does not exist on this system])
              gpg_exe_warn="*not found*"
            ])
            GPG_EXE=$withval
          ]
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


dnl Check for iptables
dnl
  AC_ARG_WITH([iptables],
    [AS_HELP_STRING([--with-iptables=/path/to/iptables],
      [Specify path to the iptables executable @<:@default=check path@:>@])],
    [
        AS_IF([ test "x$withval" = x -o "x$withval" = xyes -o "x$withval" = xno ],
          [AC_MSG_ERROR([--with-iptables requires an argument specifying a path to iptables])],
          [
            AC_CHECK_FILE([$withval], [], [
              AC_MSG_WARN([Specified path to iptables does not exist on this system])
              iptables_exe_warn="*not found*"
            ])
            IPTABLES_EXE=$withval
          ]
        )
    ],
    [
        AC_PATH_PROG(IPTABLES_EXE, [iptables], [], [$APP_PATH])
    ]
  )
  AS_IF([test "x$IPTABLES_EXE" != x],
    [
      AC_DEFINE_UNQUOTED([IPTABLES_EXE], ["$IPTABLES_EXE"], [Path to iptables executable])
      iptables_exe=$IPTABLES_EXE
    ], [ iptables_exe="(not found)"]
  )

dnl Check for ipfw
dnl
  AC_ARG_WITH([ipfw],
    [AS_HELP_STRING([--with-ipfw=/path/to/ipfw],
      [Specify path to the ipfw executable @<:@default=check path@:>@])],
    [
        AS_IF([ test "x$withval" = x -o "x$withval" = xyes -o "x$withval" = xno ],
          [AC_MSG_ERROR([--with-ipfw requires an argument specifying a path to ipfw])],
          [
            AC_CHECK_FILE([$withval], [], [
              AC_MSG_WARN([Specified path to ipfw does not exist on this system])
              ipfw_exe_warn="*not found*"
            ])
            IPFW_EXE=$withval
          ]
        )
    ],
    [
        AC_PATH_PROG(IPFW_EXE, [ipfw], [], [$APP_PATH])
    ]
  )
  AS_IF([test "x$IPFW_EXE" != x],
    [
      AC_DEFINE_UNQUOTED([IPFW_EXE], ["$IPFW_EXE"], [Path to ipfw executable])
      ipfw_exe=$IPFW_EXE
    ], [ ipfw_exe="(not found)"]
  )

dnl Check for sendmail
dnl
dnl  AC_ARG_WITH([sendmail],
dnl    [AS_HELP_STRING([--with-sendmail=/path/to/sendmail],
dnl      [Specify path to the sendmail executable @<:@default=check path@:>@])],
dnl    [
dnl        AS_IF([ test "x$withval" = x -o "x$withval" = xyes -o "x$withval" = xno ],
dnl          [AC_MSG_ERROR([--with-sendmail requires an argument specifying a path to sendmail])],
dnl          [
dnl            AC_CHECK_FILE([$withval], [], [
dnl              AC_MSG_WARN([Specified path to sendmail does not exist on this system])
dnl              sendmail_exe_warn="*not found*"
dnl            ])
dnl            SENDMAIL_EXE=$withval
dnl          ]
dnl        )
dnl    ],
dnl    [
dnl        AC_PATH_PROG(SENDMAIL_EXE, [sendmail], [], [$APP_PATH])
dnl    ]
dnl  )
dnl  AS_IF([test "x$SENDMAIL_EXE" != x],
dnl    [
dnl      AC_DEFINE_UNQUOTED([SENDMAIL_EXE], ["$SENDMAIL_EXE"], [Path to sendmail executable])
dnl      sendmail_exe=$SENDMAIL_EXE
dnl    ], [ sendmail_exe="(not found)"]
dnl  )

dnl Check for mail
dnl
dnl  AC_ARG_WITH([mail],
dnl    [AS_HELP_STRING([--with-mail=/path/to/mail],
dnl      [Specify path to the mail executable @<:@default=check path@:>@])],
dnl    [
dnl        AS_IF([ test "x$withval" = x -o "x$withval" = xyes -o "x$withval" = xno ],
dnl          [AC_MSG_ERROR([--with-mail requires an argument specifying a path to mail])],
dnl          [
dnl            AC_CHECK_FILE([$withval], [], [
dnl              AC_MSG_WARN([Specified path to mail does not exist on this system])
dnl              mail_exe_warn="*not found*"
dnl            ])
dnl            MAIL_EXE=$withval
dnl          ]
dnl        )
dnl    ],
dnl    [
dnl        AC_PATH_PROG(MAIL_EXE, [mail], [], [$APP_PATH])
dnl    ]
dnl  )
dnl  AS_IF([test "x$MAIL_EXE" != x],
dnl    [
dnl      AC_DEFINE_UNQUOTED([MAIL_EXE], ["$MAIL_EXE"], [Path to mail executable])
dnl      mail_exe=$MAIL_EXE
dnl    ], [ mail_exe="(not found)"]
dnl  )

dnl Check for sh
dnl
  AC_ARG_WITH([sh],
    [AS_HELP_STRING([--with-sh=/path/to/sh],
      [Specify path to the sh executable @<:@default=check path@:>@])],
    [
        AS_IF([ test "x$withval" = x -o "x$withval" = xyes -o "x$withval" = xno ],
          [AC_MSG_ERROR([--with-sh requires an argument specifying a path to sh])],
          [
            AC_CHECK_FILE([$withval], [], [
              AC_MSG_WARN([Specified path to sh does not exist on this system])
              sh_exe_warn="*not found*"
            ])
            SH_EXE=$withval
          ]
        )
    ],
    [
        AC_PATH_PROG(SH_EXE, [sh], [], [$APP_PATH])
    ]
  )
  AS_IF([test "x$SH_EXE" != x],
    [
      AC_DEFINE_UNQUOTED([SH_EXE], ["$SH_EXE"], [Path to sh executable])
      sh_exe=$SH_EXE
    ], [ sh_exe="(not found)"]
  )
])

AC_CONFIG_FILES([Makefile
                 lib/Makefile
                 client/Makefile
                 server/Makefile
                 common/Makefile
                 doc/Makefile])

AC_OUTPUT

if [test $have_gpgme = "yes" ]; then
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
if [test $want_server = "yes" ]; then
  echo "    Server support programs:
        iptables:                   $iptables_exe $iptables_exe_warn
        ipfw:                       $ipfw_exe $ipfw_exe_warn
        sh:                         $sh_exe $sh_exe_warn
"
fi

