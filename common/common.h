/*
 ******************************************************************************
 *
 * File:    common.h
 *
 * Author:  Damien Stuart
 *
 * Purpose: Common header file for fwknop client and server programs.
 *
 * Copyright 2010 Damien Stuart (dstuart@dstuart.org)
 *
 *  License (GNU Public License):
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
 ******************************************************************************
*/
#ifndef _COMMON_H
#define _COMMON_H

/* Common includes for our other fwknop client and server source files.
*/
#if HAVE_CONFIG_H
  #include "config.h"
#endif

#include <stdio.h>

#if HAVE_SYS_TYPES_H
  #include <sys/types.h>
#endif

#if HAVE_ERRNO_H
  #include <errno.h>
#endif

#if STDC_HEADERS
  #include <stdlib.h>
  #include <string.h>
#elif HAVE_STRINGS_H
  #include <strings.h>
#endif /* STDC_HEADERS*/

#if HAVE_UNISTD_H
  #include <unistd.h>
#endif

#ifdef HAVE_SYS_STAT_H
  #include <sys/stat.h>
#endif

#if HAVE_NETINET_IN_H
  #include <netinet/in.h>
#endif

#if HAVE_CTYPE_H
  #include <ctype.h>
#endif

#if HAVE_TIME_H
  #include <time.h>
#endif

/* Some hoops for accommodating Windows
*/
#ifdef WIN32
  #include <io.h>
  #define strcasecmp	_stricmp
  #define strncasecmp	_strnicmp
  #define snprintf		_snprintf
  #define unlink		_unlink
  #define open			_open
  #define close			_close
  #define write			_write
  #define O_WRONLY		_O_WRONLY
  #define O_RDONLY		_O_RDONLY
  #define O_RDWR		_O_RDWR
  #define O_CREAT		_O_CREAT 
  #define O_EXCL		_O_EXCL
  #define S_IRUSR		_S_IREAD
  #define S_IWUSR		_S_IWRITE
  #define PATH_SEP      '\\'
  // --DSS needed for VS versions before 2010
  typedef __int8 int8_t;
  typedef unsigned __int8 uint8_t;
  typedef __int16 int16_t;
  typedef unsigned __int16 uint16_t;
  typedef __int32 int32_t;
  typedef unsigned __int32 uint32_t;
  typedef __int64 int64_t;
  typedef unsigned __int64 uint64_t;

#else
  #include <signal.h>
  #define PATH_SEP      '/'
#endif

#include "fko.h"
#include "fko_limits.h"
#include "fko_util.h"

/* Get our program version from VERSION (defined in config.h).
*/
#define MY_VERSION VERSION

enum {
    FKO_PROTO_UDP,
    FKO_PROTO_UDP_RAW,
    FKO_PROTO_TCP,
    FKO_PROTO_TCP_RAW,
    FKO_PROTO_ICMP,
    FKO_PROTO_HTTP,
};

/* Other common defines
*/
#define FKO_DEFAULT_PROTO   FKO_PROTO_UDP
#define FKO_DEFAULT_PORT    62201
#define DEFAULT_NAT_PORT    55000
#define MIN_HIGH_PORT       10000  /* sensible minimum for SPA dest port */
#define MAX_PORT            65535
#define MAX_SERVER_STR_LEN  50
#define MAX_ICMP_TYPE       40
#define MAX_ICMP_CODE       15
#define RAW_SPA_TTL         255

#define MAX_LINE_LEN        1024
#define MAX_PATH_LEN        1024
#define MAX_GPG_KEY_ID      128
#define MAX_USERNAME_LEN    30

/* Some convenience macros */

/* Get the number of elements of an array
 */
#define ARRAY_SIZE(t)   (sizeof(t) / sizeof(t[0]))

/* Characters allowed between a config parameter and its value.
*/
#define IS_CONFIG_PARAM_DELIMITER(x) (x == ' ' || x == '\t' || x == '=');

/* End of line characters.
*/
#define IS_LINE_END(x) (x == '\n' || x == '\r' || x == ';');

/* Characters in the first position of a line that make it considered
 * empty or otherwise non-interesting (like a comment).
*/
#define IS_EMPTY_LINE(x) ( \
    x == '#' || x == '\n' || x == '\r' || x == ';' || x == '\0' \
)

/* Work-around for not having strnlen
*/
#if !HAVE_STRNLEN
  #define strnlen(s, l) (strlen(s) < l ? strlen(s) : l)
#endif

#endif /* _COMMON_H */

/***EOF***/
