/**
 * \file lib/hmac.h
 *
 * \brief Provide HMAC support for SPA communications
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
#ifndef HMAC_H
#define HMAC_H 1

#include "digest.h"

#define MAX_DIGEST_BLOCK_LEN    SHA3_256_BLOCK_LEN
/**
 * \brief Generate MD5 based HMAC
 *
 * This function generates an HMAC verification hash, based on MD5
 *
 * \param msg Pointer to the message to be signed
 * \param msg_len size of the message string
 * \param hmac Pointer to the hmac buffer, where the final hmac will be stored
 * \param hmac_key Pointer to the key to be used for generating the hmac
 * \param hmac_key_len Size of the hmac key
 *
 */
void hmac_md5(const char *msg, const unsigned int msg_len,
        unsigned char *hmac, const char *hmac_key, const int hmac_key_len);
void hmac_sha1(const char *msg, const unsigned int msg_len,
        unsigned char *hmac, const char *hmac_key, const int hmac_key_len);
void hmac_sha256(const char *msg, const unsigned int msg_len,
        unsigned char *hmac, const char *hmac_key, const int hmac_key_len);
void hmac_sha384(const char *msg, const unsigned int msg_len,
        unsigned char *hmac, const char *hmac_key, const int hmac_key_len);
void hmac_sha512(const char *msg, const unsigned int msg_len,
        unsigned char *hmac, const char *hmac_key, const int hmac_key_len);
void hmac_sha3_256(const char *msg, const unsigned int msg_len,
        unsigned char *hmac, const char *hmac_key, const int hmac_key_len);
void hmac_sha3_512(const char *msg, const unsigned int msg_len,
        unsigned char *hmac, const char *hmac_key, const int hmac_key_len);

#endif /* HMAC_H */

/***EOF***/
