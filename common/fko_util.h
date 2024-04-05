/**
 * \file common/fko_util.h
 *
 * \brief Header for utility functions used by libfko
 */

/*  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
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
#ifndef FKO_UTIL_H
#define FKO_UTIL_H 1

#include "fko.h"

#define MAX_CMDLINE_ARGS   30    /*!< should be way more than enough */
#define MAX_ARGS_LINE_LEN  1024
#define MAX_HOSTNAME_LEN    70

/* Function prototypes
*/
int     is_valid_encoded_msg_len(const int len);
int     is_valid_pt_msg_len(const int len);
int     is_valid_ip_addr(const char * const ip_str, const int len, const int family);
int     is_valid_hostname(const char * const hostname_str, const int len);
int     is_base64(const unsigned char * const buf, const unsigned short int len);
void    hex_dump(const unsigned char *data, const int size);
int     enc_mode_strtoint(const char *enc_mode_str);
short   enc_mode_inttostr(int enc_mode, char* enc_mode_str, size_t enc_mode_size);
int     strtol_wrapper(const char * const str, const int min,
            const int max, const int exit_upon_err, int *is_err);
short   digest_strtoint(const char *dt_str);
short   digest_inttostr(int digest, char* digest_str, size_t digest_size);
short   hmac_digest_strtoint(const char *dt_str);
short   hmac_digest_inttostr(int digest, char* digest_str, size_t digest_size);
int     constant_runtime_cmp(const char *a, const char *b, int len);
void    chop_whitespace(char *buf);
int     zero_free(char *buf, int len);
int     zero_buf(char *buf, int len);

const char * enc_type_inttostr(const int type);
const char * msg_type_inttostr(const int type);

void  chop_newline(char *str);
void  chop_char(char *str, const char chop);
void  chop_spaces(char *str);

/**
 *
 * \brief counts the occurrences of a character
 *
 * \return returns the number of chars found
 */
int   count_characters(const char *str, const char match, int len);

int   strtoargv(const char * const args_str, char **argv_new, int *argc_new);
void  free_argv(char **argv_new, int *argc_new);

int   ip_resolve(const char *dns_str, char *ip_str, int family);
#if !HAVE_STRLCAT
size_t  strlcat(char *dst, const char *src, size_t siz);
#endif

#if !HAVE_STRLCPY
size_t  strlcpy(char *dst, const char *src, size_t siz);
#endif

#if defined(WIN32) || !defined(HAVE_STRNDUP)
char * strndup( const char * s, size_t len );
#endif

int     dump_ctx_to_buffer(fko_ctx_t ctx, char *dump_buf, size_t dump_buf_len);

#include <sys/types.h>
#ifdef WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #if HAVE_SYS_SOCKET_H
    #include <sys/socket.h>
  #endif
  #include <netdb.h>
#endif

#endif /* FKO_UTIL_H */

/***EOF***/
