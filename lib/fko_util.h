/*
 *****************************************************************************
 *
 * File:    fko_util.h
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Header for utility functions used by libfko
 *
 * Copyright 2009-2010 Damien Stuart (dstuart@dstuart.org)
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
 *****************************************************************************
*/
#ifndef FKO_UTIL_H
#define FKO_UTIL_H 1

/* Function prototypes
*/
int is_valid_encoded_msg_len(const int len);
int is_valid_pt_msg_len(const int len);
int is_valid_digest_len(const int len);
int enc_mode_strtoint(const char *enc_mode_str);
int strtol_wrapper(const char * const str, const int min,
    const int max, const int exit_upon_err, int *is_err);

size_t strlcat(char *dst, const char *src, size_t siz);
size_t strlcpy(char *dst, const char *src, size_t siz);

#endif /* FKO_UTIL_H */

/***EOF***/
