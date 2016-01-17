/**
 * \file lib/fko_hmac.c
 *
 * \brief Provide HMAC support to SPA communications
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
#include "fko_common.h"
#include "fko.h"
#include "cipher_funcs.h"
#include "hmac.h"
#include "base64.h"

int
fko_verify_hmac(fko_ctx_t ctx,
    const char * const hmac_key, const int hmac_key_len)
{
    char    *hmac_digest_from_data = NULL;
    char    *tbuf = NULL;
    int      res = FKO_SUCCESS;
    int      hmac_b64_digest_len = 0, zero_free_rv = FKO_SUCCESS;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(hmac_key == NULL)
        return(FKO_ERROR_INVALID_DATA);

    if (! is_valid_encoded_msg_len(ctx->encrypted_msg_len))
        return(FKO_ERROR_INVALID_DATA_HMAC_MSGLEN_VALIDFAIL);

    if(hmac_key_len < 0 || hmac_key_len > MAX_DIGEST_BLOCK_LEN)
        return(FKO_ERROR_INVALID_HMAC_KEY_LEN);

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
    else if(ctx->hmac_type == FKO_HMAC_SHA3_256)
        hmac_b64_digest_len = SHA3_256_B64_LEN;
    else if(ctx->hmac_type == FKO_HMAC_SHA3_512)
        hmac_b64_digest_len = SHA3_512_B64_LEN;
    else
        return(FKO_ERROR_UNSUPPORTED_HMAC_MODE);

    if((ctx->encrypted_msg_len - hmac_b64_digest_len)
            < MIN_SPA_ENCODED_MSG_SIZE)
        return(FKO_ERROR_INVALID_DATA_HMAC_ENCMSGLEN_VALIDFAIL);

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
        if(zero_free(hmac_digest_from_data, strnlen(hmac_digest_from_data,
                MAX_SPA_ENCODED_MSG_SIZE)) == FKO_SUCCESS)
            return(FKO_ERROR_MEMORY_ALLOCATION);
        else
            return(FKO_ERROR_ZERO_OUT_DATA);
    }

    if(zero_free(ctx->encrypted_msg, ctx->encrypted_msg_len) != FKO_SUCCESS)
        zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    ctx->encrypted_msg      = tbuf;
    ctx->encrypted_msg_len -= hmac_b64_digest_len;

    if(ctx->encryption_mode == FKO_ENC_MODE_ASYMMETRIC)
    {
        /* See if we need to add the "hQ" string to the front of the
         * encrypted data.
         */
        if(! ctx->added_gpg_prefix)
        {
            res = add_gpg_prefix(ctx);
        }
    }
    else
    {
        /* See if we need to add the "Salted__" string to the front of the
         * encrypted data.
         */
        if(! ctx->added_salted_str)
        {
            res = add_salted_str(ctx);
        }
    }

    if (res != FKO_SUCCESS)
    {
        if(zero_free(hmac_digest_from_data, strnlen(hmac_digest_from_data,
                        MAX_SPA_ENCODED_MSG_SIZE)) != FKO_SUCCESS)
            zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

        if(zero_free_rv == FKO_SUCCESS)
            return(res);
        else
            return(zero_free_rv);
    }

    /* Calculate the HMAC from the encrypted data and then
     * compare
    */
    res = fko_set_spa_hmac_type(ctx, ctx->hmac_type);
    if(res == FKO_SUCCESS)
    {
        res = fko_set_spa_hmac(ctx, hmac_key, hmac_key_len);

        if(res == FKO_SUCCESS)
        {
            if(constant_runtime_cmp(hmac_digest_from_data,
                    ctx->msg_hmac, hmac_b64_digest_len) != 0)
            {
                res = FKO_ERROR_INVALID_DATA_HMAC_COMPAREFAIL;
            }
        }
    }

    if(zero_free(hmac_digest_from_data, strnlen(hmac_digest_from_data,
                    MAX_SPA_ENCODED_MSG_SIZE)) != FKO_SUCCESS)
        zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    if(res == FKO_SUCCESS)
        return(zero_free_rv);
    else
        return(res);
}

/* Return the fko HMAC data
*/
int
fko_get_spa_hmac(fko_ctx_t ctx, char **hmac_data)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(hmac_data == NULL)
        return(FKO_ERROR_INVALID_DATA);

    *hmac_data = ctx->msg_hmac;

    return(FKO_SUCCESS);
}

/* Set the HMAC type
*/
int
fko_set_spa_hmac_type(fko_ctx_t ctx, const short hmac_type)
{
#if HAVE_LIBFIU
    fiu_return_on("fko_set_spa_hmac_type_init",
            FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

#if HAVE_LIBFIU
    fiu_return_on("fko_set_spa_hmac_type_val",
            FKO_ERROR_INVALID_DATA_HMAC_TYPE_VALIDFAIL);
#endif

    if(hmac_type < 0 || hmac_type >= FKO_LAST_HMAC_MODE)
        return(FKO_ERROR_INVALID_DATA_HMAC_TYPE_VALIDFAIL);

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

    if(hmac_type == NULL)
        return(FKO_ERROR_INVALID_DATA);

    *hmac_type = ctx->hmac_type;

    return(FKO_SUCCESS);
}

int fko_set_spa_hmac(fko_ctx_t ctx,
    const char * const hmac_key, const int hmac_key_len)
{
    unsigned char hmac[SHA512_DIGEST_STR_LEN] = {0};
    char *hmac_base64 = NULL;
    int   hmac_digest_str_len = 0;
    int   hmac_digest_len = 0;
    int   res = FKO_ERROR_UNKNOWN ;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(hmac_key == NULL)
        return(FKO_ERROR_INVALID_DATA);

    if(hmac_key_len < 0 || hmac_key_len > MAX_DIGEST_BLOCK_LEN)
        return(FKO_ERROR_INVALID_HMAC_KEY_LEN);

    if(ctx->hmac_type == FKO_HMAC_MD5)
    {
        res = hmac_md5(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = MD5_DIGEST_LEN;
        hmac_digest_str_len = MD5_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == FKO_HMAC_SHA1)
    {
        res = hmac_sha1(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA1_DIGEST_LEN;
        hmac_digest_str_len = SHA1_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == FKO_HMAC_SHA256)
    {
        res = hmac_sha256(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA256_DIGEST_LEN;
        hmac_digest_str_len = SHA256_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == FKO_HMAC_SHA384)
    {
        res = hmac_sha384(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA384_DIGEST_LEN;
        hmac_digest_str_len = SHA384_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == FKO_HMAC_SHA512)
    {
        res = hmac_sha512(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA512_DIGEST_LEN;
        hmac_digest_str_len = SHA512_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == FKO_HMAC_SHA3_256)
    {
        res = hmac_sha3_256(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);
        hmac_digest_len     = SHA3_256_DIGEST_LEN;
        hmac_digest_str_len = SHA3_256_DIGEST_STR_LEN;

    }
    else if(ctx->hmac_type == FKO_HMAC_SHA3_512)
    {
        res = hmac_sha3_512(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);
        hmac_digest_len     = SHA3_512_DIGEST_LEN;
        hmac_digest_str_len = SHA3_512_DIGEST_STR_LEN;

    }

    if (res != FKO_SUCCESS)
        return res;

    hmac_base64 = calloc(1, MD_HEX_SIZE(hmac_digest_len)+1);
    if (hmac_base64 == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    b64_encode(hmac, hmac_base64, hmac_digest_len);
    strip_b64_eq(hmac_base64);

    if(ctx->msg_hmac != NULL)
        free(ctx->msg_hmac);

    ctx->msg_hmac = strdup(hmac_base64);

    free(hmac_base64);

    if(ctx->msg_hmac == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    ctx->msg_hmac_len = strnlen(ctx->msg_hmac, hmac_digest_str_len);

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
            return(FKO_ERROR_INVALID_DATA_HMAC_LEN_VALIDFAIL);
    }

    return FKO_SUCCESS;
}

/***EOF***/
