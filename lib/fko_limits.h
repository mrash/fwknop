/**
 * \file lib/fko_limits.h
 *
 * \brief #defines for libfko limits
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
#ifndef FKO_LIMITS_H
#define FKO_LIMITS_H 1

/* How much space we allow for the fko context error message buffer.
*/
#define MAX_FKO_ERR_MSG_SIZE        128

/* Define some limits (--DSS XXX: These sizes need to be reviewed)
*/
#define MAX_SPA_ENCRYPTED_SIZE     1500
#define MAX_SPA_CMD_LEN            1400
#define MAX_SPA_USERNAME_SIZE        64
#define MAX_SPA_MESSAGE_SIZE        256
#define MAX_SPA_NAT_ACCESS_SIZE     128
#define MAX_SPA_SERVER_AUTH_SIZE     64
#define MAX_SPA_TIMESTAMP_SIZE       12
#define MAX_SPA_VERSION_SIZE          8 /* 12.34.56 */
#define MAX_SPA_MESSAGE_TYPE_SIZE     2

#define MIN_SPA_ENCODED_MSG_SIZE     36 /* Somewhat arbitrary */
#define MAX_SPA_ENCODED_MSG_SIZE     MAX_SPA_ENCRYPTED_SIZE

#define MIN_SPA_PLAINTEXT_MSG_SIZE   MIN_SPA_ENCODED_MSG_SIZE
#define MAX_SPA_PLAINTEXT_MSG_SIZE   MAX_SPA_ENCODED_MSG_SIZE

#define MIN_GNUPG_MSG_SIZE          400
#define MIN_SPA_FIELDS                6
#define MAX_SPA_FIELDS                9

#define MAX_IPV4_STR_LEN             16
#define MIN_IPV4_STR_LEN              7

#define MAX_IPV46_STR_LEN            40
#define MIN_IPV46_STR_LEN             3

#define MAX_IPV6_STR_LEN             40
#define MIN_IPV6_STR_LEN              3

#define MAX_PROTO_STR_LEN             4  /* tcp, udp, icmp for now */
#define MAX_PORT_STR_LEN              5
#define MAX_PORT                  65535

/* Misc.
*/
#define FKO_ENCODE_TMP_BUF_SIZE    1024
#define FKO_RAND_VAL_SIZE            16

#endif /* FKO_LIMITS_H */

/***EOF***/
