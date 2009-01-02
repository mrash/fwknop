/* $Id$
 *****************************************************************************
 *
 * File:    sha.h
 *
 * Purpose: Header for sha.c
 *
 * sha - An implementation of the NIST SHA Message Digest
 *       algorithm. This header covers SHA1 and SHA256
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
#ifndef SHA_H
#define SHA_H 1

#include <endian.h>
#include "fko_common.h"

/* Truncate to 32 bits -- should be a null op on 32-bit machines
*/
#ifndef TRUNC32
  #define TRUNC32(x)  ((x) & 0xffffffffL)
#endif

/* This should be fine for most systems (hopefully).
*/
#define BYTEORDER __BYTE_ORDER

#define SHA_BLOCKSIZE       64
#define SHA1_DIGESTSIZE     20
#define SHA256_DIGESTSIZE   32

typedef struct {
    uint32  digest[8];
    uint32  count_lo, count_hi;
    uint8   data[SHA_BLOCKSIZE];
    int     local;
} SHA_INFO;

/* SHA1 prototypes.
*/
void sha1_init(SHA_INFO *sha_info);
void sha1_update(SHA_INFO *sha_info, uint8 *buffer, int count);
void sha1_final(uint8 digest[SHA1_DIGESTSIZE], SHA_INFO *sha_info);

/* SHA256 prototypes.
*/
void sha256_init(SHA_INFO *sha_info);
void sha256_update(SHA_INFO *sha_info, uint8 *buffer, int count);
void sha256_final(SHA_INFO *sha_info);
void sha256_unpackdigest(uint8 digest[SHA256_DIGESTSIZE], SHA_INFO *sha_info);

#endif /* SHA_H */
