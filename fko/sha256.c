/* $Id$
 *****************************************************************************
 *
 * File:    sha256.c
 *
 * Purpose: Implementation of the SHA256 message-digest algorithm for
 *          libfwknop.
 *
 *
 * Copyright (C) 2001 Rafael R. Sevilla <sevillar@team.ph.inter.net>
 *
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
#include "sha.h"

/* 32-bit rotate to the RIGHT
*/
#define ROT32(x,n)  TRUNC32(((x >> n) | (x << (32 - n))))

#define CH(x, y, z) (((x) & (y))^(~(x) & (z)))
#define MAJ(x, y, z)(((x) & (y))^((x) & (z))^((y) & (z)))

/* Upper-case sigma functions in SHA spec
*/
#define USIG0(x) (ROT32(x, 2)^ROT32(x, 13)^ROT32(x, 22))
#define USIG1(x) (ROT32(x, 6)^ROT32(x, 11)^ROT32(x, 25))

/* Lower-case sigma functions in SHA spec
*/
#define LSIG0(x) (ROT32(x, 7)^ROT32(x, 18)^TRUNC32(x >> 3))
#define LSIG1(x) (ROT32(x, 17)^ROT32(x, 19)^TRUNC32(x >> 10))

/* SHA256 constants
*/
static uint32_t K[64] = {
    0x428a2f98L, 0x71374491L, 0xb5c0fbcfL, 0xe9b5dba5L,
    0x3956c25bL, 0x59f111f1L, 0x923f82a4L, 0xab1c5ed5L,
    0xd807aa98L, 0x12835b01L, 0x243185beL, 0x550c7dc3L,
    0x72be5d74L, 0x80deb1feL, 0x9bdc06a7L, 0xc19bf174L,
    0xe49b69c1L, 0xefbe4786L, 0x0fc19dc6L, 0x240ca1ccL,
    0x2de92c6fL, 0x4a7484aaL, 0x5cb0a9dcL, 0x76f988daL,
    0x983e5152L, 0xa831c66dL, 0xb00327c8L, 0xbf597fc7L,
    0xc6e00bf3L, 0xd5a79147L, 0x06ca6351L, 0x14292967L,
    0x27b70a85L, 0x2e1b2138L, 0x4d2c6dfcL, 0x53380d13L,
    0x650a7354L, 0x766a0abbL, 0x81c2c92eL, 0x92722c85L,
    0xa2bfe8a1L, 0xa81a664bL, 0xc24b8b70L, 0xc76c51a3L,
    0xd192e819L, 0xd6990624L, 0xf40e3585L, 0x106aa070L,
    0x19a4c116L, 0x1e376c08L, 0x2748774cL, 0x34b0bcb5L,
    0x391c0cb3L, 0x4ed8aa4aL, 0x5b9cca4fL, 0x682e6ff3L,
    0x748f82eeL, 0x78a5636fL, 0x84c87814L, 0x8cc70208L,
    0x90befffaL, 0xa4506cebL, 0xbef9a3f7L, 0xc67178f2L
};

static void
sha256_transform(SHA_INFO *sha_info)
{
    int i, j;
    uint8_t *dp;
    uint32_t T, T1, T2, A, B, C, D, E, F, G, H, W[64];

    dp = sha_info->data;

#undef SWAP_DONE

#if BYTEORDER == 1234
#define SWAP_DONE
    for (i = 0; i < 16; ++i) {
        T = *((uint32_t *) dp);
        dp += 4;
        W[i] = 
            ((T << 24) & 0xff000000) |
            ((T <<  8) & 0x00ff0000) |
            ((T >>  8) & 0x0000ff00) | ((T >> 24) & 0x000000ff);
    }
#endif

#if BYTEORDER == 4321
#define SWAP_DONE
    for (i = 0; i < 16; ++i) {
        T = *((uint32_t *) dp);
        dp += 4;
        W[i] = TRUNC32(T);
    }
#endif

#if BYTEORDER == 12345678
#define SWAP_DONE
    for (i = 0; i < 16; i += 2) {
        T = *((uint32_t *) dp);
        dp += 8;
        W[i] =  ((T << 24) & 0xff000000) | ((T <<  8) & 0x00ff0000) |
            ((T >>  8) & 0x0000ff00) | ((T >> 24) & 0x000000ff);
        T >>= 32;
        W[i+1] = ((T << 24) & 0xff000000) | ((T <<  8) & 0x00ff0000) |
            ((T >>  8) & 0x0000ff00) | ((T >> 24) & 0x000000ff);
    }
#endif

#if BYTEORDER == 87654321
#define SWAP_DONE
    for (i = 0; i < 16; i += 2) {
        T = *((uint32_t *) dp);
        dp += 8;
        W[i] = TRUNC32(T >> 32);
        W[i+1] = TRUNC32(T);
    }
#endif

#ifndef SWAP_DONE
#define SWAP_DONE
    for (i = 0; i < 16; ++i) {
        T = *((uint32_t *) dp);
        dp += 4;
        W[i] = TRUNC32(T);
    }
  #ifndef WIN32
    #warning Undetermined or unsupported Byte Order... We will try LITTLE_ENDIAN
  #endif
#endif /* SWAP_DONE */

    A = sha_info->digest[0];
    B = sha_info->digest[1];
    C = sha_info->digest[2];
    D = sha_info->digest[3];
    E = sha_info->digest[4];
    F = sha_info->digest[5];
    G = sha_info->digest[6];
    H = sha_info->digest[7];

    for (i=16; i<64; i++)
        W[i] = TRUNC32(LSIG1(W[i-2]) + W[i-7] + LSIG0(W[i-15]) + W[i-16]);

    for (j=0; j<64; j++) {
        T1 = TRUNC32(H + USIG1(E) + CH(E, F, G) + K[j] + W[j]);
        T2 = TRUNC32(USIG0(A) + MAJ(A, B, C));
        H = G;
        G = F;
        F = E;
        E = TRUNC32(D + T1);
        D = C;
        C = B;
        B = A;
        A = TRUNC32(T1 + T2);
    }

    sha_info->digest[0] = TRUNC32(sha_info->digest[0] + A);
    sha_info->digest[1] = TRUNC32(sha_info->digest[1] + B);
    sha_info->digest[2] = TRUNC32(sha_info->digest[2] + C);
    sha_info->digest[3] = TRUNC32(sha_info->digest[3] + D);
    sha_info->digest[4] = TRUNC32(sha_info->digest[4] + E);
    sha_info->digest[5] = TRUNC32(sha_info->digest[5] + F);
    sha_info->digest[6] = TRUNC32(sha_info->digest[6] + G);
    sha_info->digest[7] = TRUNC32(sha_info->digest[7] + H);
}

void
sha256_init(SHA_INFO *sha_info)
{
    sha_info->digest[0] = 0x6a09e667L;
    sha_info->digest[1] = 0xbb67ae85L;
    sha_info->digest[2] = 0x3c6ef372L;
    sha_info->digest[3] = 0xa54ff53aL;
    sha_info->digest[4] = 0x510e527fL;
    sha_info->digest[5] = 0x9b05688cL;
    sha_info->digest[6] = 0x1f83d9abL;
    sha_info->digest[7] = 0x5be0cd19L;
    sha_info->count_lo = 0L;
    sha_info->count_hi = 0L;
    sha_info->local = 0;
    memset((uint8_t *)sha_info->data, 0, SHA_BLOCKSIZE);
}

/* Update the SHA digest
*/
void
sha256_update(SHA_INFO *sha_info, uint8_t *buffer, int count)
{
    int i;
    uint32_t clo;

    clo = TRUNC32(sha_info->count_lo + ((uint8_t) count << 3));
    if (clo < sha_info->count_lo) {
        sha_info->count_hi++;
    }
    sha_info->count_lo = clo;
    sha_info->count_hi += (uint32_t) count >> 29;
    if (sha_info->local) {
        i = SHA_BLOCKSIZE - sha_info->local;
        if (i > count) {
            i = count;
        }
        memcpy(((uint8_t *) sha_info->data) + sha_info->local, buffer, i);
        count -= i;
        buffer += i;
        sha_info->local += i;
        if (sha_info->local == SHA_BLOCKSIZE) {
            sha256_transform(sha_info);
        } else {
            return;
        }
    }
    while (count >= SHA_BLOCKSIZE) {
        memcpy(sha_info->data, buffer, SHA_BLOCKSIZE);
        buffer += SHA_BLOCKSIZE;
        count -= SHA_BLOCKSIZE;
        sha256_transform(sha_info);
    }
    memcpy(sha_info->data, buffer, count);
    sha_info->local = count;
}

/* Finish computing the SHA digest
*/
void
sha256_final(SHA_INFO *sha_info)
{
    int count;
    uint32_t lo_bit_count, hi_bit_count;

    lo_bit_count = sha_info->count_lo;
    hi_bit_count = sha_info->count_hi;
    count = (int) ((lo_bit_count >> 3) & 0x3f);
    ((uint8_t *) sha_info->data)[count++] = 0x80;
    if (count > SHA_BLOCKSIZE - 8) {
        memset(((uint8_t *) sha_info->data) + count, 0, SHA_BLOCKSIZE - count);
        sha256_transform(sha_info);
        memset((uint8_t *) sha_info->data, 0, SHA_BLOCKSIZE - 8);
    } else {
        memset(((uint8_t *) sha_info->data) + count, 0,
                SHA_BLOCKSIZE - 8 - count);
    }
    sha_info->data[56] = (hi_bit_count >> 24) & 0xff;
    sha_info->data[57] = (hi_bit_count >> 16) & 0xff;
    sha_info->data[58] = (hi_bit_count >>  8) & 0xff;
    sha_info->data[59] = (hi_bit_count >>  0) & 0xff;
    sha_info->data[60] = (lo_bit_count >> 24) & 0xff;
    sha_info->data[61] = (lo_bit_count >> 16) & 0xff;
    sha_info->data[62] = (lo_bit_count >>  8) & 0xff;
    sha_info->data[63] = (lo_bit_count >>  0) & 0xff;
    sha256_transform(sha_info);
}

void
sha256_unpackdigest(uint8_t digest[32], SHA_INFO *sha_info)
{
    digest[ 0] = (unsigned char) ((sha_info->digest[0] >> 24) & 0xff);
    digest[ 1] = (unsigned char) ((sha_info->digest[0] >> 16) & 0xff);
    digest[ 2] = (unsigned char) ((sha_info->digest[0] >>  8) & 0xff);
    digest[ 3] = (unsigned char) ((sha_info->digest[0]      ) & 0xff);
    digest[ 4] = (unsigned char) ((sha_info->digest[1] >> 24) & 0xff);
    digest[ 5] = (unsigned char) ((sha_info->digest[1] >> 16) & 0xff);
    digest[ 6] = (unsigned char) ((sha_info->digest[1] >>  8) & 0xff);
    digest[ 7] = (unsigned char) ((sha_info->digest[1]      ) & 0xff);
    digest[ 8] = (unsigned char) ((sha_info->digest[2] >> 24) & 0xff);
    digest[ 9] = (unsigned char) ((sha_info->digest[2] >> 16) & 0xff);
    digest[10] = (unsigned char) ((sha_info->digest[2] >>  8) & 0xff);
    digest[11] = (unsigned char) ((sha_info->digest[2]      ) & 0xff);
    digest[12] = (unsigned char) ((sha_info->digest[3] >> 24) & 0xff);
    digest[13] = (unsigned char) ((sha_info->digest[3] >> 16) & 0xff);
    digest[14] = (unsigned char) ((sha_info->digest[3] >>  8) & 0xff);
    digest[15] = (unsigned char) ((sha_info->digest[3]      ) & 0xff);
    digest[16] = (unsigned char) ((sha_info->digest[4] >> 24) & 0xff);
    digest[17] = (unsigned char) ((sha_info->digest[4] >> 16) & 0xff);
    digest[18] = (unsigned char) ((sha_info->digest[4] >>  8) & 0xff);
    digest[19] = (unsigned char) ((sha_info->digest[4]      ) & 0xff);
    digest[20] = (unsigned char) ((sha_info->digest[5] >> 24) & 0xff);
    digest[21] = (unsigned char) ((sha_info->digest[5] >> 16) & 0xff);
    digest[22] = (unsigned char) ((sha_info->digest[5] >>  8) & 0xff);
    digest[23] = (unsigned char) ((sha_info->digest[5]      ) & 0xff);
    digest[24] = (unsigned char) ((sha_info->digest[6] >> 24) & 0xff);
    digest[25] = (unsigned char) ((sha_info->digest[6] >> 16) & 0xff);
    digest[26] = (unsigned char) ((sha_info->digest[6] >>  8) & 0xff);
    digest[27] = (unsigned char) ((sha_info->digest[6]      ) & 0xff);
    digest[28] = (unsigned char) ((sha_info->digest[7] >> 24) & 0xff);
    digest[29] = (unsigned char) ((sha_info->digest[7] >> 16) & 0xff);
    digest[30] = (unsigned char) ((sha_info->digest[7] >>  8) & 0xff);
    digest[31] = (unsigned char) ((sha_info->digest[7]      ) & 0xff);
}


/***EOF***/
