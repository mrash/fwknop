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
#include "fko_common.h"
#include "fko.h"
#include "cipher_funcs.h"
#include "hmac.h"
#include "base64.h"

int fko_verify_hmac(fko_ctx_t ctx,
    const char * const hmac_key, const int hmac_key_len)
{
    char    *hmac_digest_from_data = NULL;
    char    *tbuf = NULL;
    int      res = FKO_SUCCESS;
    int      hmac_b64_digest_len = 0;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if (! is_valid_encoded_msg_len(ctx->encrypted_msg_len))
        return(FKO_ERROR_INVALID_DATA);

    if(ctx->hmac_type == FKO_HMAC_MD5)
        hmac_b64_digest_len = MD5_B64_LEN;
    else if(ctx->hmac_type == FKO_HMAC_SHA1)
        hmac_b64_digest_len = SHA1_B64_LEN;
    else if(ctx->hmac_type == FKO_HMAC_SHA256)
        hmac_b64_digest_len = SHA256_B64_LEN;
    else if(ctx->hmac_type == FKO_HMAC_SHA384)
        hmac_b64_digest_len = SHA384_B64_LEN;
    else if(ctx->hmac_type == FKO_HMAC_SHA512)
        hmac_b64_digest_len = SHA512_B64_LEN;
    else
        return(FKO_ERROR_UNSUPPORTED_HMAC_MODE);

    if((ctx->encrypted_msg_len - hmac_b64_digest_len)
            < MIN_SPA_ENCODED_MSG_SIZE)
        return(FKO_ERROR_INVALID_DATA);

    /* Get digest value
    */
    hmac_digest_from_data = strndup((ctx->encrypted_msg
            + ctx->encrypted_msg_len - hmac_b64_digest_len),
            hmac_b64_digest_len);

    if(hmac_digest_from_data == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    /* Now we chop the HMAC digest off of the encrypted msg
    */
    tbuf = strndup(ctx->encrypted_msg,
            ctx->encrypted_msg_len - hmac_b64_digest_len);
    if(tbuf == NULL)
    {
        free(hmac_digest_from_data);
        return(FKO_ERROR_MEMORY_ALLOCATION);
    }

    free(ctx->encrypted_msg);

    ctx->encrypted_msg      = tbuf;
    ctx->encrypted_msg_len -= hmac_b64_digest_len;

    /* See if we need to add the "Salted__" string to the front of the
     * encrypted data.
    */
    if(! ctx->added_salted_str)
        res = add_salted_str(ctx);

    if (res != FKO_SUCCESS)
    {
        free(hmac_digest_from_data);
        return(res);
    }

    /* Calculate the HMAC from the encrypted data and then
     * compare
    */
    res = fko_set_spa_hmac_type(ctx, ctx->hmac_type);
    if(res == FKO_SUCCESS)
    {
        res = fko_calculate_hmac(ctx, hmac_key, hmac_key_len);

        if(res == FKO_SUCCESS)
        {
            if(strncmp(hmac_digest_from_data,
                    ctx->msg_hmac, hmac_b64_digest_len) != 0)
            {
                res = FKO_ERROR_INVALID_DATA;
            }
        }
    }

    free(hmac_digest_from_data);
    return(res);
}

/* Return the fko HMAC data
*/
int
fko_get_hmac_data(fko_ctx_t ctx, char **hmac_data)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *hmac_data = ctx->msg_hmac;

    return(FKO_SUCCESS);
}

/* Set the HMAC type
*/
int
fko_set_spa_hmac_type(fko_ctx_t ctx, const short hmac_type)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(hmac_type < 0 || hmac_type >= FKO_LAST_HMAC_MODE)
        return(FKO_ERROR_INVALID_DATA);

    ctx->hmac_type = hmac_type;

    ctx->state |= FKO_HMAC_MODE_MODIFIED;

    return(FKO_SUCCESS);
}

/* Return the fko HMAC type
*/
int
fko_get_spa_hmac_type(fko_ctx_t ctx, short *hmac_type)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *hmac_type = ctx->hmac_type;

    return(FKO_SUCCESS);
}

int fko_calculate_hmac(fko_ctx_t ctx,
    const char * const hmac_key, const int hmac_key_len)
{
    unsigned char hmac[SHA512_DIGEST_STR_LEN] = {0};
    char *hmac_base64 = NULL;
    int   hmac_digest_str_len = 0;
    int   hmac_digest_len = 0;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    memset(hmac, 0x00, SHA512_DIGEST_STR_LEN);

    if(ctx->hmac_type == FKO_HMAC_MD5)
    {
        hmac_md5(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = MD5_DIGEST_LEN;
        hmac_digest_str_len = MD5_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == FKO_HMAC_SHA1)
    {
        hmac_sha1(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA1_DIGEST_LEN;
        hmac_digest_str_len = SHA1_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == FKO_HMAC_SHA256)
    {
        hmac_sha256(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA256_DIGEST_LEN;
        hmac_digest_str_len = SHA256_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == FKO_HMAC_SHA384)
    {
        hmac_sha384(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA384_DIGEST_LEN;
        hmac_digest_str_len = SHA384_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == FKO_HMAC_SHA512)
    {
        hmac_sha512(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA512_DIGEST_LEN;
        hmac_digest_str_len = SHA512_DIGEST_STR_LEN;
    }

    hmac_base64 = calloc(1, MD_HEX_SIZE(hmac_digest_len)+1);
    if (hmac_base64 == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    b64_encode(hmac, hmac_base64, hmac_digest_len);
    strip_b64_eq(hmac_base64);

    if(ctx->msg_hmac != NULL)
        free(ctx->msg_hmac);

    ctx->msg_hmac     = strdup(hmac_base64);
    ctx->msg_hmac_len = strnlen(ctx->msg_hmac, hmac_digest_str_len);

    free(hmac_base64);

    switch(ctx->msg_hmac_len)
    {
        case MD5_B64_LEN:
            break;
        case SHA1_B64_LEN:
            break;
        case SHA256_B64_LEN:
            break;
        case SHA384_B64_LEN:
            break;
        case SHA512_B64_LEN:
            break;
        default:
            return(FKO_ERROR_INVALID_DATA);
    }

    return FKO_SUCCESS;
}

/***EOF***/
