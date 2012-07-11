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
#include "hmac.h"
#include "base64.h"

int fko_verify_hmac(fko_ctx_t ctx,
    const char *hmac_key, const int hmac_key_len)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
    {
        return(FKO_ERROR_CTX_NOT_INITIALIZED);
    }

    return FKO_SUCCESS;
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
fko_set_hmac_mode(fko_ctx_t ctx, const short hmac_mode)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(hmac_mode < 0 || hmac_mode >= FKO_LAST_HMAC_MODE)
        return(FKO_ERROR_INVALID_DATA);

    ctx->hmac_mode = hmac_mode;

    ctx->state |= FKO_HMAC_MODE_MODIFIED;

    return(FKO_SUCCESS);
}

int fko_calculate_hmac(fko_ctx_t ctx,
    const char *hmac_key, const int hmac_key_len)
{
    unsigned char hmac[SHA256_DIGEST_STRING_LENGTH] = {0};
    char *hmac_base64 = NULL;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    /* Only HMAC-SHA256 is supported for now
    */
    if(ctx->hmac_mode != FKO_HMAC_SHA256)
        return(FKO_ERROR_UNSUPPORTED_HMAC_MODE);

    hmac_base64 = calloc(1, MD_HEX_SIZE(SHA256_DIGEST_LENGTH)+1);
    if (hmac_base64 == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    hmac_sha256(ctx->encrypted_msg,
        strlen(ctx->encrypted_msg), hmac, hmac_key);

    b64_encode(hmac, hmac_base64, SHA256_DIGEST_LENGTH);
    strip_b64_eq(hmac_base64);

    ctx->msg_hmac = strdup(hmac_base64);

    free(hmac_base64);

    return FKO_SUCCESS;
}

/***EOF***/
