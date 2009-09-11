dnl Process thie file with autoconf to produce the configure script

AC_PREREQ(2.61)

m4_define(my_package, [fwknop])
m4_define(my_version, [2.0.0-alpha])
m4_define(my_bug_email, [dstuart@dstuart.org])

AC_INIT(my_package, my_version, my_bug_email)

AC_CONFIG_AUX_DIR(config)

AM_INIT_AUTOMAKE([tar-ustar -Wall -Werror foreign])

dnl AM_MAINTAINER_MODE

AC_CONFIG_HEADER([config.h])

AC_GNU_SOURCE

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_AWK
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

AC_CHECK_HEADERS([ctype.h endian.h netdb.h netinet/in.h stdint.h stdlib.h string.h strings.h sys/byteorder.h sys/endian.h sys/socket.h sys/stat.h sys/time.h termios.h unistd.h])

# Type checks.
#
AC_C_CONST
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_TYPES([uint8_t, uint32_t])

AC_C_BIGENDIAN

# Checks for library functions.
#
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STAT

AC_CHECK_FUNCS([bzero gettimeofday memmove memset socket strchr strcspn strdup strncasecmp strndup strrchr strspn])

AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([inet_addr], [nsl])

dnl For finding and checking gpgme (taken from the gpgme.m4 file that
dnl  comes with gpgme)
dnl
AC_DEFUN([_AM_PATH_GPGME_CONFIG],
[ AC_ARG_WITH(gpgme-prefix,
            AC_HELP_STRING([--with-gpgme-prefix=PFX],
                           [prefix where GPGME is installed (optional)]),
     gpgme_config_prefix="$withval", gpgme_config_prefix="")
  if test "x$gpgme_config_prefix" != x ; then
      GPGME_CONFIG="$gpgme_config_prefix/bin/gpgme-config"
  fi
  AC_PATH_PROG(GPGME_CONFIG, gpgme-config, no)

  if test "$GPGME_CONFIG" != "no" ; then
    gpgme_version=`$GPGME_CONFIG --version`
  fi
  gpgme_version_major=`echo $gpgme_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
  gpgme_version_minor=`echo $gpgme_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
  gpgme_version_micro=`echo $gpgme_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\3/'`
])

dnl AM_PATH_GPGME([MINIMUM-VERSION,
dnl               [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libgpgme and define GPGME_CFLAGS and GPGME_LIBS.
dnl
AC_DEFUN([AM_PATH_GPGME],
[ AC_REQUIRE([_AM_PATH_GPGME_CONFIG])dnl
  tmp=ifelse([$1], ,1:0.4.2,$1)
  if echo "$tmp" | grep ':' >/dev/null 2>/dev/null ; then
     req_gpgme_api=`echo "$tmp"     | sed 's/\(.*\):\(.*\)/\1/'`
     min_gpgme_version=`echo "$tmp" | sed 's/\(.*\):\(.*\)/\2/'`
  else
     req_gpgme_api=0
     min_gpgme_version="$tmp"
  fi

  AC_MSG_CHECKING(for GPGME - version >= $min_gpgme_version)
  ok=no
  if test "$GPGME_CONFIG" != "no" ; then
    req_major=`echo $min_gpgme_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
    req_minor=`echo $min_gpgme_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
    req_micro=`echo $min_gpgme_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`
    if test "$gpgme_version_major" -gt "$req_major"; then
        ok=yes
    else 
        if test "$gpgme_version_major" -eq "$req_major"; then
            if test "$gpgme_version_minor" -gt "$req_minor"; then
               ok=yes
            else
               if test "$gpgme_version_minor" -eq "$req_minor"; then
                   if test "$gpgme_version_micro" -ge "$req_micro"; then
                     ok=yes
                   fi
               fi
            fi
        fi
    fi
  fi
  if test $ok = yes; then
     # If we have a recent GPGME, we should also check that the
     # API is compatible.
     if test "$req_gpgme_api" -gt 0 ; then
        tmp=`$GPGME_CONFIG --api-version 2>/dev/null || echo 0`
        if test "$tmp" -gt 0 ; then
           if test "$req_gpgme_api" -ne "$tmp" ; then
             ok=no
           fi
        fi
     fi
  fi
  if test $ok = yes; then
    GPGME_CFLAGS=`$GPGME_CONFIG --cflags`
    GPGME_LIBS=`$GPGME_CONFIG --libs`
    AC_MSG_RESULT(yes)
    ifelse([$2], , :, [$2])
  else
    GPGME_CFLAGS=""
    GPGME_LIBS=""
    AC_MSG_RESULT(no)
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(GPGME_CFLAGS)
  AC_SUBST(GPGME_LIBS)
])

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

dnl Check for libpcap if we are building the server component
dnl
have_pcap=yes
AS_IF([test "$want_server" = yes],
  AC_CHECK_LIB([pcap],[pcap_open_live],
    AC_DEFINE([HAVE_LIBPCAP], [1], [Define if you have libpcap]), [have_pcap=no]
  )
)
AM_CONDITIONAL([HAVE_LIBPCAP],[test "$have_pcap" = yes])

AC_CONFIG_FILES([Makefile
                 lib/Makefile
                 client/Makefile
                 server/Makefile
                 common/Makefile
                 doc/Makefile])

AC_OUTPUT

echo "
    libfko v${VERSION} has been configured.
    ============================================
        Client build:               $want_client
        Server build:               $want_server
         - with libpcap:            $have_pcap
        GPG encryption support:     $have_gpgme
"
