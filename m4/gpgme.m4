# gpgme.m4 - autoconf macro to detect GPGME.
# Copyright (C) 2002, 2003, 2004, 2014, 2018, 2022 g10 Code GmbH
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# Last-changed: 2024-05-16


dnl
dnl Find gpgrt-config, which uses .pc file
dnl (minimum pkg-config functionality, supporting cross build)
dnl
dnl _AM_PATH_GPGRT_CONFIG
AC_DEFUN([_AM_PATH_GPGRT_CONFIG],[dnl
  AC_PATH_PROG(GPGRT_CONFIG, gpgrt-config, no, [$prefix/bin:$PATH])
  if test "$GPGRT_CONFIG" != "no"; then
    # Determine gpgrt_libdir
    #
    # Get the prefix of gpgrt-config assuming it's something like:
    #   <PREFIX>/bin/gpgrt-config
    gpgrt_prefix=${GPGRT_CONFIG%/*/*}
    possible_libdir1=${gpgrt_prefix}/lib
    # Determine by using system libdir-format with CC, it's like:
    #   Normal style: /usr/lib
    #   GNU cross style: /usr/<triplet>/lib
    #   Debian style: /usr/lib/<multiarch-name>
    #   Fedora/openSUSE style: /usr/lib, /usr/lib32 or /usr/lib64
    # It is assumed that CC is specified to the one of host on cross build.
    if libdir_candidates=$(${CC:-cc} -print-search-dirs | \
          sed -n -e "/^libraries/{s/libraries: =//;s/:/\\
/g;p;}"); then
      # From the output of -print-search-dirs, select valid pkgconfig dirs.
      libdir_candidates=$(for dir in $libdir_candidates; do
        if p=$(cd $dir 2>/dev/null && pwd); then
          test -d "$p/pkgconfig" && echo $p;
        fi
      done)

      for possible_libdir0 in $libdir_candidates; do
        # possible_libdir0:
        #   Fallback candidate, the one of system-installed (by $CC)
        #   (/usr/<triplet>/lib, /usr/lib/<multiarch-name> or /usr/lib32)
        # possible_libdir1:
        #   Another candidate, user-locally-installed
        #   (<gpgrt_prefix>/lib)
        # possible_libdir2
        #   Most preferred
        #   (<gpgrt_prefix>/<triplet>/lib,
        #    <gpgrt_prefix>/lib/<multiarch-name> or <gpgrt_prefix>/lib32)
        if test "${possible_libdir0##*/}" = "lib"; then
          possible_prefix0=${possible_libdir0%/lib}
          possible_prefix0_triplet=${possible_prefix0##*/}
          if test -z "$possible_prefix0_triplet"; then
            continue
          fi
          possible_libdir2=${gpgrt_prefix}/$possible_prefix0_triplet/lib
        else
          possible_prefix0=${possible_libdir0%%/lib*}
          possible_libdir2=${gpgrt_prefix}${possible_libdir0#$possible_prefix0}
        fi
        if test -f ${possible_libdir2}/pkgconfig/gpg-error.pc; then
          gpgrt_libdir=${possible_libdir2}
        elif test -f ${possible_libdir1}/pkgconfig/gpg-error.pc; then
          gpgrt_libdir=${possible_libdir1}
        elif test -f ${possible_libdir0}/pkgconfig/gpg-error.pc; then
          gpgrt_libdir=${possible_libdir0}
        fi
        if test -n "$gpgrt_libdir"; then break; fi
      done
    fi
    if test -z "$gpgrt_libdir"; then
      # No valid pkgconfig dir in any of the system directories, fallback
      gpgrt_libdir=${possible_libdir1}
    fi
  else
    unset GPGRT_CONFIG
  fi

  if test -n "$gpgrt_libdir"; then
    # Add the --libdir option to GPGRT_CONFIG
    GPGRT_CONFIG="$GPGRT_CONFIG --libdir=$gpgrt_libdir"
    # Make sure if gpgrt-config really works, by testing config gpg-error
    if ! $GPGRT_CONFIG gpg-error --exists; then
      # If it doesn't work, clear the GPGRT_CONFIG variable.
      unset GPGRT_CONFIG
    fi
  else
    # GPGRT_CONFIG found but no suitable dir for --libdir found.
    # This is a failure.  Clear the GPGRT_CONFIG variable.
    unset GPGRT_CONFIG
  fi
])

AC_DEFUN([_AM_PATH_GPGME_CONFIG],[dnl
AC_REQUIRE([_AM_PATH_GPGRT_CONFIG])dnl
  AC_ARG_WITH(gpgme-prefix,
              AS_HELP_STRING([--with-gpgme-prefix=PFX],
                             [prefix where GPGME is installed (optional)]),
     gpgme_config_prefix="$withval", gpgme_config_prefix="")
  if test x"${GPGME_CONFIG}" = x ; then
     if test x"${gpgme_config_prefix}" != x ; then
        GPGME_CONFIG="${gpgme_config_prefix}/bin/gpgme-config"
     else
       case "${SYSROOT}" in
         /*)
           if test -x "${SYSROOT}/bin/gpgme-config" ; then
             GPGME_CONFIG="${SYSROOT}/bin/gpgme-config"
           fi
           ;;
         '')
           ;;
          *)
           AC_MSG_WARN([Ignoring \$SYSROOT as it is not an absolute path.])
           ;;
       esac
     fi
  fi

  use_gpgrt_config=""
  if test x"$GPGRT_CONFIG" != x -a "$GPGRT_CONFIG" != "no"; then
    if $GPGRT_CONFIG gpgme --exists; then
      GPGME_CONFIG="$GPGRT_CONFIG gpgme"
      AC_MSG_NOTICE([Use gpgrt-config as gpgme-config])
      use_gpgrt_config=yes
    fi
  fi
  if test -z "$use_gpgrt_config"; then
    AC_PATH_PROG(GPGME_CONFIG, gpgme-config, no)
  fi

  if test "$GPGME_CONFIG" != "no" ; then
    if test -z "$use_gpgrt_config"; then
      gpgme_version=`$GPGME_CONFIG --version`
    else
      gpgme_version=`$GPGME_CONFIG --modversion`
    fi
  fi
  gpgme_version_major=`echo $gpgme_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
  gpgme_version_minor=`echo $gpgme_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
  gpgme_version_micro=`echo $gpgme_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\3/'`
])


AC_DEFUN([_AM_PATH_GPGME_CONFIG_HOST_CHECK],
[
    if test -z "$use_gpgrt_config"; then
      gpgme_config_host=`$GPGME_CONFIG --host 2>/dev/null || echo none`
    else
      gpgme_config_host=`$GPGME_CONFIG --variable=host 2>/dev/null || echo none`
    fi
    if test x"$gpgme_config_host" != xnone ; then
      if test x"$gpgme_config_host" != x"$host" ; then
  AC_MSG_WARN([[
***
*** The config script "$GPGME_CONFIG" was
*** built for $gpgme_config_host and thus may not match the
*** used host $host.
*** You may want to use the configure option --with-gpgme-prefix
*** to specify a matching config script or use \$SYSROOT.
***]])
        gpg_config_script_warn="$gpg_config_script_warn gpgme"
      fi
    fi
])


dnl AM_PATH_GPGME([MINIMUM-VERSION,
dnl               [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libgpgme and define GPGME_CFLAGS and GPGME_LIBS.
dnl
dnl If a prefix option is not used, the config script is first
dnl searched in $SYSROOT/bin and then along $PATH.  If the used
dnl config script does not match the host specification the script
dnl is added to the gpg_config_script_warn variable.
dnl
AC_DEFUN([AM_PATH_GPGME],
[ AC_REQUIRE([AC_CANONICAL_HOST])dnl
  AC_REQUIRE([_AM_PATH_GPGME_CONFIG])dnl
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
        if test -z "$use_gpgrt_config"; then
          tmp=`$GPGME_CONFIG --api-version 2>/dev/null || echo 0`
        else
          tmp=`$GPGME_CONFIG --variable=api_version 2>/dev/null || echo 0`
        fi
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
    _AM_PATH_GPGME_CONFIG_HOST_CHECK
  else
    GPGME_CFLAGS=""
    GPGME_LIBS=""
    AC_MSG_RESULT(no)
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(GPGME_CFLAGS)
  AC_SUBST(GPGME_LIBS)
])

dnl AM_PATH_GPGME_PTHREAD([MINIMUM-VERSION,
dnl                       [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libgpgme and define GPGME_PTHREAD_CFLAGS
dnl  and GPGME_PTHREAD_LIBS.
dnl
AC_DEFUN([AM_PATH_GPGME_PTHREAD],[
  AC_OBSOLETE([$0], [; use AM_PATH_GPGME instead to use GPGME_CFLAGS and GPGME_LIBS])dnl
  AC_REQUIRE([_AM_PATH_GPGME_CONFIG])dnl
  tmp=ifelse([$1], ,1:0.4.2,$1)
  if echo "$tmp" | grep ':' >/dev/null 2>/dev/null ; then
     req_gpgme_api=`echo "$tmp"     | sed 's/\(.*\):\(.*\)/\1/'`
     min_gpgme_version=`echo "$tmp" | sed 's/\(.*\):\(.*\)/\2/'`
  else
     req_gpgme_api=0
     min_gpgme_version="$tmp"
  fi

  AC_MSG_CHECKING(for GPGME pthread - version >= $min_gpgme_version)
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
        if test -z "$use_gpgrt_config"; then
          tmp=`$GPGME_CONFIG --api-version 2>/dev/null || echo 0`
        else
          tmp=`$GPGME_CONFIG --variable=api_version 2>/dev/null || echo 0`
        fi
        if test "$tmp" -gt 0 ; then
           if test "$req_gpgme_api" -ne "$tmp" ; then
             ok=no
           fi
        fi
     fi
  fi
  if test $ok = yes; then
    GPGME_PTHREAD_CFLAGS=`$GPGME_CONFIG --cflags`
    GPGME_PTHREAD_LIBS=`$GPGME_CONFIG --libs`
    AC_MSG_RESULT(yes)
    ifelse([$2], , :, [$2])
    _AM_PATH_GPGME_CONFIG_HOST_CHECK
  else
    GPGME_PTHREAD_CFLAGS=""
    GPGME_PTHREAD_LIBS=""
    AC_MSG_RESULT(no)
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(GPGME_PTHREAD_CFLAGS)
  AC_SUBST(GPGME_PTHREAD_LIBS)
])


dnl AM_PATH_GPGME_GLIB([MINIMUM-VERSION,
dnl               [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libgpgme-glib and define GPGME_GLIB_CFLAGS and GPGME_GLIB_LIBS.
dnl
AC_DEFUN([AM_PATH_GPGME_GLIB],
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
        if test -z "$use_gpgrt_config"; then
          tmp=`$GPGME_CONFIG --api-version 2>/dev/null || echo 0`
        else
          tmp=`$GPGME_CONFIG --variable=api_version 2>/dev/null || echo 0`
        fi
        if test "$tmp" -gt 0 ; then
           if test "$req_gpgme_api" -ne "$tmp" ; then
             ok=no
           fi
        fi
     fi
  fi
  if test $ok = yes; then
    if test -z "$use_gpgrt_config"; then
      GPGME_GLIB_CFLAGS=`$GPGME_CONFIG --glib --cflags`
      GPGME_GLIB_LIBS=`$GPGME_CONFIG --glib --libs`
    else
      if $GPGRT_CONFIG gpgme-glib --exists; then
        GPGME_CONFIG="$GPGRT_CONFIG gpgme-glib"
        GPGME_GLIB_CFLAGS=`$GPGME_CONFIG --cflags`
        GPGME_GLIB_LIBS=`$GPGME_CONFIG --libs`
      else
        ok = no
      fi
    fi
  fi
  if test $ok = yes; then
    AC_MSG_RESULT(yes)
    ifelse([$2], , :, [$2])
    _AM_PATH_GPGME_CONFIG_HOST_CHECK
  else
    GPGME_GLIB_CFLAGS=""
    GPGME_GLIB_LIBS=""
    AC_MSG_RESULT(no)
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(GPGME_GLIB_CFLAGS)
  AC_SUBST(GPGME_GLIB_LIBS)
])
