/*
 *****************************************************************************
 *
 * File:    fko_common.h
 *
 * Purpose: Common header for libfko source files.
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2014 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *****************************************************************************
*/
#ifndef FKO_COMMON_H
#define FKO_COMMON_H 1

#define HAVE_CONFIG_H 1

#if HAVE_CONFIG_H
  #include "config.h"
#endif

#include <stdio.h>
#include <sys/types.h>

#if STDC_HEADERS
  #include <stdlib.h>
  #include <string.h>
#elif HAVE_STRINGS_H
  #include <strings.h>
#endif /*STDC_HEADERS*/

#if HAVE_UNISTD_H
  #include <unistd.h>
#endif

#if HAVE_CTYPE_H
  #include <ctype.h> /* Using this for isdigit() */
#else
  /* Fall-back does not account for locale */
  #define isdigit(c) (c >= 48 && c <= 57)
#endif

#ifdef IPHONE
typedef u_int8_t uint8_t;
typedef u_int16_t uint16_t;
typedef u_int32_t uint32_t;
#endif

#ifdef WIN32
  /* These are needed for the digest code under windows.
  */
  typedef unsigned __int8   uint8_t;
  typedef unsigned __int32	uint32_t;
  typedef unsigned __int64	uint64_t;

  #define strdup _strdup
#else
  #if HAVE_STDINT_H
    #include <stdint.h>
  #endif
#endif

/* Work out endianness
*/
#if HAVE_ENDIAN_H       /* Should cover most Linux systems */
  #include <endian.h>
  #define BYTEORDER __BYTE_ORDER
#elif HAVE_SYS_ENDIAN_H /* FreeBSD has a sys/endian.h */
  #include <sys/endian.h>
  #define BYTEORDER _BYTE_ORDER
#elif HAVE_SYS_BYTEORDER_H /* Solaris (v10 at least) seems to have this */
  #include <sys/byteorder.h>
  #if defined(_BIG_ENDIAN)
    #define BYTEORDER 4321
  #elif defined(_LITTLE_ENDIAN)
    #define BYTEORDER 1234
  #else
    #error unable to determine BYTEORDER
  #endif
#endif

#ifdef WIN32
  #include <time.h>
#else
  #ifdef HAVE_SYS_TIME_H
    #include <sys/time.h>
    #ifdef TIME_WITH_SYS_TIME
      #include <time.h>
    #endif
  #endif
#endif

/* Convenient macros for wrapping sections in 'extern "C" {' constructs.
*/
#ifdef __cplusplus
  #define BEGIN_C_DECLS extern "C" {
  #define END_C_DECLS   }
#else /* !__cplusplus */
  #define BEGIN_C_DECLS
  #define END_C_DECLS
#endif /* __cplusplus */

/* Pull in gpgme.h if we have it.
*/
#if HAVE_LIBGPGME
  #include <gpgme.h>
#endif

#include "fko_util.h"
#include "fko_limits.h"
#include "fko_state.h"
#include "fko_context.h"

/* Try to cover for those that do not have bzero.
*/
#if !HAVE_BZERO && HAVE_MEMSET
# define bzero(buf, bytes)      ((void) memset (buf, 0, bytes))
#endif

#endif /* FKO_COMMON_H */

/***EOF***/
