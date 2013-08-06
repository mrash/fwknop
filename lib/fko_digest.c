/*
 *****************************************************************************
 *
 * File:    fko_digest.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Create the base64-encoded digest for the current spa data. The
 *          digest used is determined by the digest_type setting in the
 *          fko context.
 *
 * Copyright 2009-2013 Damien Stuart (dstuart@dstuart.org)
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
#include "fko_common.h"
#include "fko.h"
#include "digest.h"

/* Set the SPA digest type.
*/
static int
set_spa_digest_type(fko_ctx_t ctx,
    short *digest_type_field, const short digest_type)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(digest_type < 1 || digest_type >= FKO_LAST_DIGEST_TYPE)
        return(FKO_ERROR_INVALID_DATA_ENCODE_DIGEST_VALIDFAIL);

    *digest_type_field = digest_type;

    ctx->state |= FKO_DIGEST_TYPE_MODIFIED;

    return(FKO_SUCCESS);
}

int
fko_set_spa_digest_type(fko_ctx_t ctx, const short digest_type)
{
    return set_spa_digest_type(ctx, &ctx->digest_type, digest_type);
}

int
fko_set_raw_spa_digest_type(fko_ctx_t ctx, const short raw_digest_type)
{
    return set_spa_digest_type(ctx, &ctx->raw_digest_type, raw_digest_type);
}

/* Return the SPA digest type.
*/
int
fko_get_spa_digest_type(fko_ctx_t ctx, short *digest_type)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *digest_type = ctx->digest_type;

    return(FKO_SUCCESS);
}

/* Return the SPA digest type.
*/
int
fko_get_raw_spa_digest_type(fko_ctx_t ctx, short *raw_digest_type)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *raw_digest_type = ctx->raw_digest_type;

    return(FKO_SUCCESS);
}

static int
set_digest(char *data, char **digest, short digest_type, int *digest_len)
{
    char    *md = NULL;
    int     data_len;

    data_len = strnlen(data, MAX_SPA_ENCODED_MSG_SIZE);

    if(data_len == MAX_SPA_ENCODED_MSG_SIZE)
        return(FKO_ERROR_INVALID_DATA_ENCODE_DIGEST_TOOBIG);

    switch(digest_type)
    {
        case FKO_DIGEST_MD5:
            md = malloc(MD_HEX_SIZE(MD5_DIGEST_LEN)+1);
            if(md == NULL)
                return(FKO_ERROR_MEMORY_ALLOCATION);

            md5_base64(md,
                (unsigned char*)data, data_len);
            *digest_len = MD5_B64_LEN;
            break;

        case FKO_DIGEST_SHA1:
            md = malloc(MD_HEX_SIZE(SHA1_DIGEST_LEN)+1);
            if(md == NULL)
                return(FKO_ERROR_MEMORY_ALLOCATION);

            sha1_base64(md,
                (unsigned char*)data, data_len);
            *digest_len = SHA1_B64_LEN;
            break;

        case FKO_DIGEST_SHA256:
            md = malloc(MD_HEX_SIZE(SHA256_DIGEST_LEN)+1);
            if(md == NULL)
                return(FKO_ERROR_MEMORY_ALLOCATION);

            sha256_base64(md,
                (unsigned char*)data, data_len);
            *digest_len = SHA256_B64_LEN;
            break;

        case FKO_DIGEST_SHA384:
            md = malloc(MD_HEX_SIZE(SHA384_DIGEST_LEN)+1);
            if(md == NULL)
                return(FKO_ERROR_MEMORY_ALLOCATION);

            sha384_base64(md,
                (unsigned char*)data, data_len);
            *digest_len = SHA384_B64_LEN;
            break;

        case FKO_DIGEST_SHA512:
            md = malloc(MD_HEX_SIZE(SHA512_DIGEST_LEN)+1);
            if(md == NULL)
                return(FKO_ERROR_MEMORY_ALLOCATION);

            sha512_base64(md,
                (unsigned char*)data, data_len);
            *digest_len = SHA512_B64_LEN;
            break;

        default:
            return(FKO_ERROR_INVALID_DIGEST_TYPE);
    }

    /* Just in case this is a subsquent call to this function.  We
     * do not want to be leaking memory.
    */
    if(*digest != NULL)
        free(*digest);

    *digest = md;

    return(FKO_SUCCESS);
}

int
fko_set_spa_digest(fko_ctx_t ctx)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    /* Must have encoded message data to start with.
    */
    if(ctx->encoded_msg == NULL)
        return(FKO_ERROR_MISSING_ENCODED_DATA);

    return set_digest(ctx->encoded_msg, &ctx->digest,
        ctx->digest_type, &ctx->digest_len);
}

int
fko_set_raw_spa_digest(fko_ctx_t ctx)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    /* Must have encoded message data to start with.
    */
    if(ctx->encrypted_msg == NULL)
        return(FKO_ERROR_MISSING_ENCODED_DATA);

    return set_digest(ctx->encrypted_msg, &ctx->raw_digest,
        ctx->raw_digest_type, &ctx->raw_digest_len);
}

int
fko_get_spa_digest(fko_ctx_t ctx, char **md)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *md = ctx->digest;

    return(FKO_SUCCESS);
}

int
fko_get_raw_spa_digest(fko_ctx_t ctx, char **md)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *md = ctx->raw_digest;

    return(FKO_SUCCESS);
}

/***EOF***/
