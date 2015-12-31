/**
 * \file lib/sha1.h
 *
 * \brief Header for sha1.c
 */

/* sha - An implementation of the NIST SHA1 Message Digest
 *       algorithm.
 *
 * Copyright (C) 2001 Rafael R. Sevilla <sevillar@team.ph.inter.net>
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
#ifndef SHA1_H
#define SHA1_H 1

#include "common.h"

#ifdef WIN32
  #define BYTEORDER 1234
#endif

/* Truncate to 32 bits -- should be a null op on 32-bit machines
*/
#ifndef TRUNC32
  #define TRUNC32(x)  ((x) & 0xffffffffL)
#endif

#define SHA1_BLOCKSIZE      64
#define SHA1_BLOCK_LEN      SHA1_BLOCKSIZE
#define SHA1_DIGEST_LEN     20
#define SHA1_DIGEST_STR_LEN (SHA1_DIGEST_LEN * 2 + 1)
#define SHA1_B64_LEN        27

typedef struct {
    uint32_t    digest[8];
    uint32_t    count_lo, count_hi;
    uint8_t     data[SHA1_BLOCKSIZE];
    int         local;
} SHA1_INFO;

/* SHA1 prototypes.
*/
void sha1_init(SHA1_INFO *sha1_info);
void sha1_update(SHA1_INFO *sha1_info, uint8_t *buffer, int count);
void sha1_final(uint8_t digest[SHA1_DIGEST_LEN], SHA1_INFO *sha1_info);

#endif /* SHA1_H */
