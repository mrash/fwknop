/*
 *****************************************************************************
 *
 * File:    fwknopd_errors.h
 *
 * Purpose: Header file for fwknopd_errors.c.
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
#ifndef FWKNOPD_ERRORS_H
#define FWKNOPD_ERRORS_H

/* SPA message handling status codes
*/
enum {
    SPA_MSG_SUCCESS = 0,
    SPA_MSG_BAD_DATA = 0x1000,
    SPA_MSG_LEN_TOO_SMALL,
    SPA_MSG_NOT_SPA_DATA,
    SPA_MSG_HTTP_NOT_ENABLED,
    SPA_MSG_FKO_CTX_ERROR,
    SPA_MSG_DIGEST_ERROR,
    SPA_MSG_DIGEST_CACHE_ERROR,
    SPA_MSG_REPLAY,
    SPA_MSG_TOO_OLD,
    SPA_MSG_ACCESS_DENIED,
    SPA_MSG_COMMAND_ERROR,
    SPA_MSG_NOT_SUPPORTED,
    SPA_MSG_NAT_NOT_ENABLED,
    SPA_MSG_ERROR
};

/* Firewall rule processing error codes
*/
enum {
    FW_RULE_SUCCESS = 0,
    FW_RULE_ADD_ERROR = 0x2000,
    FW_RULE_DELETE_ERROR,
    FW_RULE_UNKNOWN_ERROR
};

/* Macro for determining if an error code is a spa_msg handler error
 * and/or a firewall rule processing error.
*/
#define IS_SPA_MSG_ERROR(x) (x & 0x1000)
#define IS_FW_RULE_ERROR(x) (x & 0x2000)
#define IS_FWKNOPD_ERROR(x) (IS_SPA_MSG_ERROR(x) | IS_FW_RULE_ERROR(x))

/* Function prototypes
*/
const char* get_errstr(const int err_code);

#endif /* FWKNOPD_ERRORS_H */

/***EOF***/
