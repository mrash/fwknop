/* $Id$
 *****************************************************************************
 *
 * File:    sha256.h
 *
 * Purpose: Header for sha256.c
 *
 * sha - An implementation of the NIST SHA 256/384/512 Message Digest
 *       algorithm.
 *
 * Copyright (C) 2001 Rafael R. Sevilla <sevillar@team.ph.inter.net>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *****************************************************************************
*/
#ifndef _SHA256_H_
#define _SHA256_H_

#include <stdio.h>
#include <string.h>         /* for memcpy */
#include <endian.h>

#include "types.h"

/* This should be fine for most systems (hopefully).
*/
#define BYTEORDER __BYTE_ORDER

#define SHA_BLOCKSIZE       64
#define SHA256_DIGESTSIZE   32

typedef struct {
    uint32  digest[8];
    uint32  count_lo, count_hi;
    uint8   data[SHA_BLOCKSIZE];
    int     local;
} SHA256_INFO;

void sha256(char *in, char *digest, int in_len);
void sha256_init(SHA256_INFO *sha256_info);
void sha256_update(SHA256_INFO *sha256_info, uint8 *buffer, int count);
void sha256_final(SHA256_INFO *sha256_info);
void sha256_unpackdigest(uint8 digest[32], SHA256_INFO *sha256_info);

#endif /* _SHA256_H_ */
