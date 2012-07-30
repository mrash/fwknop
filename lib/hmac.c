/*
 *****************************************************************************
 *
 * File:    fko_hmac.c
 *
 * Author:  Michael Rash
 *
 * Purpose: Provide HMAC support to SPA communications
 *
 * Copyright 2012 Michael Rash (mbr@cipherdyne.org)
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

#include "hmac.h"

void hmac_sha256(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key)
{
    hmac_sha256_ctx ctx;

    hmac_sha256_init(&ctx, hmac_key);
    hmac_sha256_update(&ctx, msg, msg_len);
    hmac_sha256_final(&ctx, hmac);

    return;
}

void hmac_sha256_init(hmac_sha256_ctx *ctx, const char *key)
{
    int i = 0;

    for (i=0; i < (int) SHA256_BLOCK_LEN; i++) {
        ctx->block_inner_pad[i] = key[i] ^ 0x36;
        ctx->block_outer_pad[i] = key[i] ^ 0x5c;
    }

    SHA256_Init(&ctx->ctx_inside);
    SHA256_Update(&ctx->ctx_inside, ctx->block_inner_pad, SHA256_BLOCK_LEN);

    SHA256_Init(&ctx->ctx_outside);
    SHA256_Update(&ctx->ctx_outside, ctx->block_outer_pad, SHA256_BLOCK_LEN);

    return;
}

void hmac_sha256_update(hmac_sha256_ctx *ctx, const char *msg,
    unsigned int msg_len)
{
    SHA256_Update(&ctx->ctx_inside, (unsigned char *)msg, msg_len);
    return;
}

void hmac_sha256_final(hmac_sha256_ctx *ctx, unsigned char *hmac)
{
    unsigned char digest_inside[SHA256_DIGEST_LEN];

    SHA256_Final(digest_inside, &ctx->ctx_inside);
    SHA256_Update(&ctx->ctx_outside, digest_inside, SHA256_DIGEST_LEN);
    SHA256_Final(hmac, &ctx->ctx_outside);

    return;
}
