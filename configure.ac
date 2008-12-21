dnl Process thie file with autoconf to produce teh configure script

AC_PREREQ(2.53)

m4_define(my_package, [fwknop])
m4_define(my_version, [2.0.0])

AC_INIT(my_package, my_version)
AM_INIT_AUTOMAKE(my_package, my_version)

AC_GNU_SOURCE
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_RANLIB

# Type checks.
AC_C_INLINE
AC_CHECK_SIZEOF(unsigned int)
AC_TYPE_OFF_T

# Network library fun.
AC_CHECK_FUNC(gethostbyname, , AC_CHECK_LIB(nsl, gethostbyname,
        [NETLIBS="-lnsl $NETLIBS"]))
AC_CHECK_FUNC(setsockopt, , AC_CHECK_LIB(socket, setsockopt,
        [NETLIBS="-lsocket $NETLIBS"]))
AC_SUBST(NETLIBS)

dnl # Checking for libgpg-error.
dnl AM_PATH_GPG_ERROR(1.4,, AC_MSG_ERROR([libgpg-error was not found]))
dnl AC_DEFINE(GPG_ERR_SOURCE_DEFAULT, GPG_ERR_SOURCE_GPGME,
dnl          [The default error source for GPGME.])

dnl # GPGME
dnl AM_PATH_GPGME


AC_OUTPUT(lib/Makefile client/Makefile server/Makefile Makefile)
