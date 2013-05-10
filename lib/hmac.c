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

typedef struct {
    MD5Context ctx_inside;
    MD5Context ctx_outside;

    unsigned char block_inner_pad[MAX_DIGEST_BLOCK_LEN];
    unsigned char block_outer_pad[MAX_DIGEST_BLOCK_LEN];
} hmac_md5_ctx;

typedef struct {
    SHA1_INFO ctx_inside;
    SHA1_INFO ctx_outside;

    unsigned char block_inner_pad[MAX_DIGEST_BLOCK_LEN];
    unsigned char block_outer_pad[MAX_DIGEST_BLOCK_LEN];
} hmac_sha1_ctx;

typedef struct {
    SHA256_CTX ctx_inside;
    SHA256_CTX ctx_outside;

    unsigned char block_inner_pad[MAX_DIGEST_BLOCK_LEN];
    unsigned char block_outer_pad[MAX_DIGEST_BLOCK_LEN];
} hmac_sha256_ctx;

typedef struct {
    SHA384_CTX ctx_inside;
    SHA384_CTX ctx_outside;

    unsigned char block_inner_pad[MAX_DIGEST_BLOCK_LEN];
    unsigned char block_outer_pad[MAX_DIGEST_BLOCK_LEN];
} hmac_sha384_ctx;

typedef struct {
    SHA512_CTX ctx_inside;
    SHA512_CTX ctx_outside;

    unsigned char block_inner_pad[MAX_DIGEST_BLOCK_LEN];
    unsigned char block_outer_pad[MAX_DIGEST_BLOCK_LEN];
} hmac_sha512_ctx;

static void
pad_init(unsigned char *inner_pad, unsigned char *outer_pad,
        const unsigned char * const key, const int key_len)
{
    int i = 0;

    for (i=0; i < MAX_DIGEST_BLOCK_LEN && i < key_len; i++) {
        inner_pad[i] = key[i] ^ 0x36;
        outer_pad[i] = key[i] ^ 0x5c;
    }

    if(i < MAX_DIGEST_BLOCK_LEN)
    {
        while(i < MAX_DIGEST_BLOCK_LEN)
        {
            inner_pad[i] = 0x36;
            outer_pad[i] = 0x5c;
            i++;
        }
    }
    return;
}

/* Begin MD5 HMAC functions
*/
static void
hmac_md5_init(hmac_md5_ctx *ctx, const char *key, const int key_len)
{
    unsigned char  final_key[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char  init_key[MAX_DIGEST_BLOCK_LEN]  = {0};
    int            final_len = key_len;

    memset(final_key, 0x00, MAX_DIGEST_BLOCK_LEN);
    memset(init_key, 0x00, MAX_DIGEST_BLOCK_LEN);

    if(key_len > MAX_DIGEST_BLOCK_LEN)
        final_len = MAX_DIGEST_BLOCK_LEN;

    memcpy(init_key, key, final_len);

    if(MD5_BLOCK_LEN < final_len)
    {
        /* Calculate the digest of the key
        */
        md5(final_key, init_key, final_len);
    }
    else
    {
        memcpy(final_key, init_key, key_len);
    }

    pad_init(ctx->block_inner_pad, ctx->block_outer_pad, final_key, key_len);

    MD5Init(&ctx->ctx_inside);
    MD5Update(&ctx->ctx_inside, ctx->block_inner_pad, MD5_BLOCK_LEN);

    MD5Init(&ctx->ctx_outside);
    MD5Update(&ctx->ctx_outside, ctx->block_outer_pad, MD5_BLOCK_LEN);

    return;
}

static void
hmac_md5_update(hmac_md5_ctx *ctx, const char *msg,
    unsigned int msg_len)
{
    MD5Update(&ctx->ctx_inside, (unsigned char *)msg, msg_len);
    return;
}

static void
hmac_md5_final(hmac_md5_ctx *ctx, unsigned char *hmac)
{
    unsigned char digest_inside[MD5_DIGEST_LEN];

    MD5Final(digest_inside, &ctx->ctx_inside);
    MD5Update(&ctx->ctx_outside, digest_inside, MD5_DIGEST_LEN);
    MD5Final(hmac, &ctx->ctx_outside);

    return;
}

void
hmac_md5(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key, const int hmac_key_len)
{
    hmac_md5_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));

    hmac_md5_init(&ctx, hmac_key, hmac_key_len);
    hmac_md5_update(&ctx, msg, msg_len);
    hmac_md5_final(&ctx, hmac);

    return;
}

/* Begin SHA1 HMAC functions
*/
static void
hmac_sha1_init(hmac_sha1_ctx *ctx, const char *key, const int key_len)
{
    unsigned char  final_key[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char  init_key[MAX_DIGEST_BLOCK_LEN]  = {0};
    int            final_len = key_len;

    memset(final_key, 0x00, MAX_DIGEST_BLOCK_LEN);
    memset(init_key, 0x00, MAX_DIGEST_BLOCK_LEN);

    if(key_len > MAX_DIGEST_BLOCK_LEN)
        final_len = MAX_DIGEST_BLOCK_LEN;

    memcpy(init_key, key, final_len);

    if(SHA1_BLOCK_LEN < final_len)
    {
        /* Calculate the digest of the key
        */
        sha1(final_key, init_key, final_len);
    }
    else
    {
        memcpy(final_key, init_key, key_len);
    }

    pad_init(ctx->block_inner_pad, ctx->block_outer_pad, final_key, key_len);

    sha1_init(&ctx->ctx_inside);
    sha1_update(&ctx->ctx_inside, ctx->block_inner_pad, SHA1_BLOCK_LEN);

    sha1_init(&ctx->ctx_outside);
    sha1_update(&ctx->ctx_outside, ctx->block_outer_pad, SHA1_BLOCK_LEN);

    return;
}

static void
hmac_sha1_update(hmac_sha1_ctx *ctx, const char *msg,
    unsigned int msg_len)
{
    sha1_update(&ctx->ctx_inside, (unsigned char *)msg, msg_len);
    return;
}

static void
hmac_sha1_final(hmac_sha1_ctx *ctx, unsigned char *hmac)
{
    unsigned char digest_inside[SHA1_DIGEST_LEN];

    sha1_final(digest_inside, &ctx->ctx_inside);
    sha1_update(&ctx->ctx_outside, digest_inside, SHA1_DIGEST_LEN);
    sha1_final(hmac, &ctx->ctx_outside);

    return;
}

void
hmac_sha1(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key, const int hmac_key_len)
{
    hmac_sha1_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));

    hmac_sha1_init(&ctx, hmac_key, hmac_key_len);
    hmac_sha1_update(&ctx, msg, msg_len);
    hmac_sha1_final(&ctx, hmac);

    return;
}

/* Begin SHA256 HMAC functions
*/
static void
hmac_sha256_init(hmac_sha256_ctx *ctx, const char *key, const int key_len)
{
    unsigned char  final_key[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char  init_key[MAX_DIGEST_BLOCK_LEN]  = {0};
    int            final_len = key_len;

    memset(final_key, 0x00, MAX_DIGEST_BLOCK_LEN);
    memset(init_key, 0x00, MAX_DIGEST_BLOCK_LEN);

    if(key_len > MAX_DIGEST_BLOCK_LEN)
        final_len = MAX_DIGEST_BLOCK_LEN;

    memcpy(init_key, key, final_len);

    if(SHA256_BLOCK_LEN < final_len)
    {
        /* Calculate the digest of the key
        */
        sha256(final_key, init_key, final_len);
    }
    else
    {
        memcpy(final_key, init_key, key_len);
    }

    pad_init(ctx->block_inner_pad, ctx->block_outer_pad, final_key, key_len);

    SHA256_Init(&ctx->ctx_inside);
    SHA256_Update(&ctx->ctx_inside, ctx->block_inner_pad, SHA256_BLOCK_LEN);

    SHA256_Init(&ctx->ctx_outside);
    SHA256_Update(&ctx->ctx_outside, ctx->block_outer_pad, SHA256_BLOCK_LEN);

    return;
}

static void
hmac_sha256_update(hmac_sha256_ctx *ctx, const char *msg,
    unsigned int msg_len)
{
    SHA256_Update(&ctx->ctx_inside, (unsigned char *)msg, msg_len);
    return;
}

static void
hmac_sha256_final(hmac_sha256_ctx *ctx, unsigned char *hmac)
{
    unsigned char digest_inside[SHA256_DIGEST_LEN];

    SHA256_Final(digest_inside, &ctx->ctx_inside);
    SHA256_Update(&ctx->ctx_outside, digest_inside, SHA256_DIGEST_LEN);
    SHA256_Final(hmac, &ctx->ctx_outside);

    return;
}

void
hmac_sha256(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key, const int hmac_key_len)
{
    hmac_sha256_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));

    hmac_sha256_init(&ctx, hmac_key, hmac_key_len);
    hmac_sha256_update(&ctx, msg, msg_len);
    hmac_sha256_final(&ctx, hmac);

    return;
}

/* Begin SHA384 HMAC functions
*/
static void
hmac_sha384_init(hmac_sha384_ctx *ctx, const char *key, const int key_len)
{
    unsigned char  final_key[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char  init_key[MAX_DIGEST_BLOCK_LEN]  = {0};
    int            final_len = key_len;

    memset(final_key, 0x00, MAX_DIGEST_BLOCK_LEN);
    memset(init_key, 0x00, MAX_DIGEST_BLOCK_LEN);

    if(key_len > MAX_DIGEST_BLOCK_LEN)
        final_len = MAX_DIGEST_BLOCK_LEN;

    memcpy(init_key, key, final_len);

    if(SHA384_BLOCK_LEN < final_len)
    {
        /* Calculate the digest of the key
        */
        sha384(final_key, init_key, final_len);
    }
    else
    {
        memcpy(final_key, init_key, key_len);
    }

    pad_init(ctx->block_inner_pad, ctx->block_outer_pad, final_key, key_len);

    SHA384_Init(&ctx->ctx_inside);
    SHA384_Update(&ctx->ctx_inside, ctx->block_inner_pad, SHA384_BLOCK_LEN);

    SHA384_Init(&ctx->ctx_outside);
    SHA384_Update(&ctx->ctx_outside, ctx->block_outer_pad, SHA384_BLOCK_LEN);

    return;
}

static void
hmac_sha384_update(hmac_sha384_ctx *ctx, const char *msg,
    unsigned int msg_len)
{
    SHA384_Update(&ctx->ctx_inside, (unsigned char *)msg, msg_len);
    return;
}

static void
hmac_sha384_final(hmac_sha384_ctx *ctx, unsigned char *hmac)
{
    unsigned char digest_inside[SHA384_DIGEST_LEN];

    SHA384_Final(digest_inside, &ctx->ctx_inside);
    SHA384_Update(&ctx->ctx_outside, digest_inside, SHA384_DIGEST_LEN);
    SHA384_Final(hmac, &ctx->ctx_outside);

    return;
}

void
hmac_sha384(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key, const int hmac_key_len)
{
    hmac_sha384_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));

    hmac_sha384_init(&ctx, hmac_key, hmac_key_len);
    hmac_sha384_update(&ctx, msg, msg_len);
    hmac_sha384_final(&ctx, hmac);

    return;
}

/* Begin SHA512 HMAC functions
*/
static void
hmac_sha512_init(hmac_sha512_ctx *ctx, const char *key, const int key_len)
{
    unsigned char  final_key[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char  init_key[MAX_DIGEST_BLOCK_LEN]  = {0};
    int            final_len = key_len;

    memset(final_key, 0x00, MAX_DIGEST_BLOCK_LEN);
    memset(init_key, 0x00, MAX_DIGEST_BLOCK_LEN);

    if(key_len > MAX_DIGEST_BLOCK_LEN)
        final_len = MAX_DIGEST_BLOCK_LEN;

    memcpy(init_key, key, final_len);

    if(SHA512_BLOCK_LEN < final_len)
    {
        /* Calculate the digest of the key
        */
        sha512(final_key, init_key, final_len);
    }
    else
    {
        memcpy(final_key, init_key, key_len);
    }

    pad_init(ctx->block_inner_pad, ctx->block_outer_pad, final_key, key_len);

    SHA512_Init(&ctx->ctx_inside);
    SHA512_Update(&ctx->ctx_inside, ctx->block_inner_pad, SHA512_BLOCK_LEN);

    SHA512_Init(&ctx->ctx_outside);
    SHA512_Update(&ctx->ctx_outside, ctx->block_outer_pad, SHA512_BLOCK_LEN);

    return;
}

static void
hmac_sha512_update(hmac_sha512_ctx *ctx, const char *msg,
    unsigned int msg_len)
{
    SHA512_Update(&ctx->ctx_inside, (unsigned char *)msg, msg_len);
    return;
}

static void
hmac_sha512_final(hmac_sha512_ctx *ctx, unsigned char *hmac)
{
    unsigned char digest_inside[SHA512_DIGEST_LEN];

    SHA512_Final(digest_inside, &ctx->ctx_inside);
    SHA512_Update(&ctx->ctx_outside, digest_inside, SHA512_DIGEST_LEN);
    SHA512_Final(hmac, &ctx->ctx_outside);

    return;
}

void
hmac_sha512(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key, const int hmac_key_len)
{
    hmac_sha512_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));

    hmac_sha512_init(&ctx, hmac_key, hmac_key_len);
    hmac_sha512_update(&ctx, msg, msg_len);
    hmac_sha512_final(&ctx, hmac);

    return;
}
