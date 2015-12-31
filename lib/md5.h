/**
 * \file lib/md5.h
 *
 * \brief Header for the fwknop md5.c.
 */

/* MD5 Message Digest Algorithm (RFC1321).
 *
 * Derived from cryptoapi implementation, originally based on the
 * public domain implementation written by Colin Plumb in 1993.
 *
 * Copyright (c) Cryptoapi developers.
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
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
#ifndef MD5_H
#define MD5_H 1

#include "common.h"

#define MD5_BLOCK_LEN       64
#define MD5_DIGEST_LEN      16
#define MD5_DIGEST_STR_LEN  (MD5_DIGEST_LEN * 2 + 1)
#define MD5_B64_LEN         22

typedef struct _MD5Context {
        uint32_t buf[4];
        uint32_t bits[2];
        unsigned char in[64];
} MD5Context;

void MD5Init(MD5Context*);
void MD5Update(MD5Context *ctx, unsigned char *buf, unsigned len);
void MD5Final(unsigned char digest[16], MD5Context *ctx);
void MD5Transform(uint32_t buf[4], uint32_t in[16]);

#endif /* MD5_H */

/***EOF***/
