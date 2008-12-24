dnl Process thie file with autoconf to produce teh configure script

AC_PREREQ(2.53)

m4_define(my_package, [fwknop])
m4_define(my_version, [2.0.0-alpha])
m4_define(my_bug_email, [dstuart@dstuart.org])

AC_INIT(my_package, my_version, my_bug_email)
AM_INIT_AUTOMAKE(my_package, my_version)

dnl AM_MAINTAINER_MODE

AC_CONFIG_HEADER([config.h])

AC_GNU_SOURCE

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_RANLIB
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

# Checks for header files.
#
AC_HEADER_STDC
AC_CHECK_HEADERS([locale.h stdlib.h string.h sys/time.h unistd.h])

# Type checks.
#
AC_C_INLINE
AC_CHECK_SIZEOF(unsigned int)
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_C_CONST

# Checks for library functions.
#
AC_CHECK_FUNCS([gettimeofday memmove memset setlocale strchr])


# Generate the Makefiles
#
AC_OUTPUT(lib/Makefile src/Makefile Makefile)
