/*
 *****************************************************************************
 *
 * File:    fko_decode.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Decode an FKO SPA message after decryption.
 *
 * Copyright 2009-2010 Damien Stuart (dstuart@dstuart.org)
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
#include "base64.h"
#include "digest.h"

/* Decode the encoded SPA data.
*/
int
fko_decode_spa_data(fko_ctx_t ctx)
{
    char       *tbuf, *ndx, *tmp;
    int         t_size, i, is_err;

    if (! is_valid_encoded_msg_len(ctx->encoded_msg_len))
        return(FKO_ERROR_INVALID_DATA);

    /* Make sure there are no non-ascii printable chars
    */
    for (i=0; i < (int)strnlen(ctx->encoded_msg, MAX_SPA_ENCODED_MSG_SIZE); i++)
        if(isprint(ctx->encoded_msg[i]) == 0)
            return(FKO_ERROR_INVALID_DATA);

    /* Make sure there are enough fields in the SPA packet
     * delimited with ':' chars
    */
    ndx = ctx->encoded_msg;
    for (i=0; i < MAX_SPA_FIELDS; i++)
    {
        if ((tmp = strchr(ndx, ':')) == NULL)
            break;

        ndx = tmp;
        ndx++;
    }

    if (i < MIN_SPA_FIELDS)
        return(FKO_ERROR_INVALID_DATA);

    t_size = strnlen(ndx, SHA512_B64_LEN+1);

    switch(t_size)
    {
        case MD5_B64_LEN:
            ctx->digest_type = FKO_DIGEST_MD5;
            break;

        case SHA1_B64_LEN:
            ctx->digest_type = FKO_DIGEST_SHA1;
            break;

        case SHA256_B64_LEN:
            ctx->digest_type = FKO_DIGEST_SHA256;
            break;

        case SHA384_B64_LEN:
            ctx->digest_type = FKO_DIGEST_SHA384;
            break;

        case SHA512_B64_LEN:
            ctx->digest_type = FKO_DIGEST_SHA512;
            break;

        default: /* Invalid or unsupported digest */
            return(FKO_ERROR_INVALID_DIGEST_TYPE);
    }

    if (ctx->encoded_msg_len - t_size < 0)
        return(FKO_ERROR_INVALID_DATA);

    if(ctx->digest != NULL)
        free(ctx->digest);

    /* Copy the digest into the context and terminate the encoded data
     * at that point so the original digest is not part of the
     * encoded string.
    */
    ctx->digest = strdup(ndx);
    if(ctx->digest == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    /* Zero out the rest of the encoded_msg bucket...
    */
    bzero((ndx-1), t_size);

    ctx->encoded_msg_len -= t_size+1;

    /* Make a tmp bucket for processing base64 encoded data and
     * other general use.
    */
    tbuf = malloc(FKO_ENCODE_TMP_BUF_SIZE);
    if(tbuf == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    /* Can now verify the digest.
    */
    switch(ctx->digest_type)
    {
        case FKO_DIGEST_MD5:
            md5_base64(tbuf, (unsigned char*)ctx->encoded_msg, ctx->encoded_msg_len);
            break;

        case FKO_DIGEST_SHA1:
            sha1_base64(tbuf, (unsigned char*)ctx->encoded_msg, ctx->encoded_msg_len);
            break;

        case FKO_DIGEST_SHA256:
            sha256_base64(tbuf, (unsigned char*)ctx->encoded_msg, ctx->encoded_msg_len);
            break;

        case FKO_DIGEST_SHA384:
            sha384_base64(tbuf, (unsigned char*)ctx->encoded_msg, ctx->encoded_msg_len);
            break;

        case FKO_DIGEST_SHA512:
            sha512_base64(tbuf, (unsigned char*)ctx->encoded_msg, ctx->encoded_msg_len);
            break;
    }

    /* We give up here if the computed digest does not match the
     * digest in the message data.
    */
    if(strncmp(ctx->digest, tbuf, t_size))
    {
        free(tbuf);
        return(FKO_ERROR_DIGEST_VERIFICATION_FAILED);
    }

    /* Now we will work through the encoded data and extract (and base64-
     * decode where necessary), the SPA data fields and populate the context.
    */
    ndx = ctx->encoded_msg;

    /* The rand val data */
    if((t_size = strcspn(ndx, ":")) < FKO_RAND_VAL_SIZE)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }

    if(ctx->rand_val != NULL)
        free(ctx->rand_val);

    ctx->rand_val = calloc(1, FKO_RAND_VAL_SIZE+1);
    if(ctx->rand_val == NULL)
    {
        free(tbuf);
        return(FKO_ERROR_MEMORY_ALLOCATION);
    }
    ctx->rand_val = strncpy(ctx->rand_val, ndx, FKO_RAND_VAL_SIZE);

    /* Jump to the next field (username).  We need to use the temp buffer
     * for the base64 decode step.
    */
    ndx += t_size + 1;
    if((t_size = strcspn(ndx, ":")) < 1)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }

    if (t_size > MAX_SPA_USERNAME_SIZE)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }

    strlcpy(tbuf, ndx, t_size+1);

    if(ctx->username != NULL)
        free(ctx->username);

    ctx->username = malloc(t_size+1); /* Yes, more than we need */
    if(ctx->username == NULL)
    {
        free(tbuf);
        return(FKO_ERROR_MEMORY_ALLOCATION);
    }

    if(b64_decode(tbuf, (unsigned char*)ctx->username) < 0)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }
    if(validate_username(ctx->username) != FKO_SUCCESS)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }

    /* Extract the timestamp value.
    */
    ndx += t_size + 1;
    if((t_size = strcspn(ndx, ":")) < 1)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }

    if (t_size > MAX_SPA_TIMESTAMP_SIZE)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }

    strlcpy(tbuf, ndx, t_size+1);

    ctx->timestamp = (unsigned int) strtol_wrapper(tbuf,
            0, -1, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }

    /* Extract the version string.
    */
    ndx += t_size + 1;
    if((t_size = strcspn(ndx, ":")) < 1)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }

    if (t_size > MAX_SPA_VERSION_SIZE)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }

    if(ctx->version != NULL)
        free(ctx->version);

    ctx->version = malloc(t_size+1);
    if(ctx->version == NULL)
    {
        free(tbuf);
        return(FKO_ERROR_MEMORY_ALLOCATION);
    }

    strlcpy(ctx->version, ndx, t_size+1);

    /* Extract the message type value.
    */
    ndx += t_size + 1;
    if((t_size = strcspn(ndx, ":")) < 1)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }

    if (t_size > MAX_SPA_MESSAGE_TYPE_SIZE)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }

    strlcpy(tbuf, ndx, t_size+1);

    ctx->message_type = strtol_wrapper(tbuf, 0,
            FKO_LAST_MSG_TYPE, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }

    /* Extract the SPA message string.
    */
    ndx += t_size + 1;
    if((t_size = strcspn(ndx, ":")) < 1)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }

    if (t_size > MAX_SPA_MESSAGE_SIZE)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }

    strlcpy(tbuf, ndx, t_size+1);

    if(ctx->message != NULL)
        free(ctx->message);

    ctx->message = malloc(t_size+1); /* Yes, more than we need */
    if(ctx->message == NULL)
    {
        free(tbuf);
        return(FKO_ERROR_MEMORY_ALLOCATION);
    }

    if(b64_decode(tbuf, (unsigned char*)ctx->message) < 0)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }

    if(ctx->message_type == FKO_COMMAND_MSG)
    {
        /* Require a message similar to: 1.2.3.4,<command>
        */
        if(validate_cmd_msg(ctx->message) != FKO_SUCCESS)
        {
            free(tbuf);
            return(FKO_ERROR_INVALID_DATA);
        }
    }
    else
    {
        /* Require a message similar to: 1.2.3.4,tcp/22
        */
        if(validate_access_msg(ctx->message) != FKO_SUCCESS)
        {
            free(tbuf);
            return(FKO_ERROR_INVALID_DATA);
        }
    }

    /* Extract nat_access string if the message_type indicates so.
    */
    if(  ctx->message_type == FKO_NAT_ACCESS_MSG
      || ctx->message_type == FKO_LOCAL_NAT_ACCESS_MSG
      || ctx->message_type == FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG
      || ctx->message_type == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
    {
        ndx += t_size + 1;
        if((t_size = strcspn(ndx, ":")) < 1)
        {
            free(tbuf);
            return(FKO_ERROR_INVALID_DATA);
        }

        if (t_size > MAX_SPA_MESSAGE_SIZE)
        {
            free(tbuf);
            return(FKO_ERROR_INVALID_DATA);
        }

        strlcpy(tbuf, ndx, t_size+1);

        if(ctx->nat_access != NULL)
            free(ctx->nat_access);

        ctx->nat_access = malloc(t_size+1); /* Yes, more than we need */
        if(ctx->nat_access == NULL)
        {
            free(tbuf);
            return(FKO_ERROR_MEMORY_ALLOCATION);
        }

        if(b64_decode(tbuf, (unsigned char*)ctx->nat_access) < 0)
        {
            free(tbuf);
            return(FKO_ERROR_INVALID_DATA);
        }

        if(validate_nat_access_msg(ctx->nat_access) != FKO_SUCCESS)
        {
            free(tbuf);
            return(FKO_ERROR_INVALID_DATA);
        }
    }

    /* Now look for a server_auth string.
    */
    ndx += t_size + 1;
    if((t_size = strlen(ndx)) > 0)
    {
        if (t_size > MAX_SPA_MESSAGE_SIZE)
        {
            free(tbuf);
            return(FKO_ERROR_INVALID_DATA);
        }

        /* There is data, but what is it?
         * If the message_type does not have a timeout, assume it is a
         * server_auth field.
        */
        if(  ctx->message_type != FKO_CLIENT_TIMEOUT_ACCESS_MSG
          && ctx->message_type != FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG
          && ctx->message_type != FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
        {
            strlcpy(tbuf, ndx, t_size+1);

            if(ctx->server_auth != NULL)
                free(ctx->server_auth);

            ctx->server_auth = malloc(t_size+1); /* Yes, more than we need */
            if(ctx->server_auth == NULL)
            {
                free(tbuf);
                return(FKO_ERROR_MEMORY_ALLOCATION);
            }

            if(b64_decode(tbuf, (unsigned char*)ctx->server_auth) < 0)
            {
                free(tbuf);
                return(FKO_ERROR_INVALID_DATA);
            }

            /* At this point we should be done.
            */
            free(tbuf);

            /* Call the context initialized.
            */
            ctx->initval = FKO_CTX_INITIALIZED;
            FKO_SET_CTX_INITIALIZED(ctx);

            return(FKO_SUCCESS);
        }

        /* If we are here then we may still have a server_auth string,
         * or a timeout, or both. So we look for a ':' delimiter.  If
         * it is there we have both, if not we check the message_type
         * again.
        */
        if(strchr(ndx, ':'))
        {
            t_size = strcspn(ndx, ":");

            if (t_size > MAX_SPA_MESSAGE_SIZE)
            {
                free(tbuf);
                return(FKO_ERROR_INVALID_DATA);
            }

            /* Looks like we have both, so assume this is the 
            */
            strlcpy(tbuf, ndx, t_size+1);

            if(ctx->server_auth != NULL)
                free(ctx->server_auth);

            ctx->server_auth = malloc(t_size+1); /* Yes, more than we need */
            if(ctx->server_auth == NULL)
            {
                free(tbuf);
                return(FKO_ERROR_MEMORY_ALLOCATION);
            }

            if(b64_decode(tbuf, (unsigned char*)ctx->server_auth) < 0)
            {
                free(tbuf);
                return(FKO_ERROR_INVALID_DATA);
            }

            ndx += t_size + 1;
        }

        /* Now we look for a timeout value if one is supposed to be there.
        */
        if(  ctx->message_type == FKO_CLIENT_TIMEOUT_ACCESS_MSG
          || ctx->message_type == FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG
          || ctx->message_type == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
        {
            if((t_size = strlen(ndx)) < 1)
            {
                free(tbuf);
                return(FKO_ERROR_INVALID_DATA);
            }
            if (t_size > MAX_SPA_MESSAGE_SIZE)
            {
                free(tbuf);
                return(FKO_ERROR_INVALID_DATA);
            }

            /* Should be a number only.
            */
            if(strspn(ndx, "0123456789") != t_size)
            {
                free(tbuf);
                return(FKO_ERROR_INVALID_DATA);
            }

            ctx->client_timeout = (unsigned int) strtol_wrapper(ndx, 0,
                    (2 << 15), NO_EXIT_UPON_ERR, &is_err);
            if(is_err != FKO_SUCCESS)
            {
                free(tbuf);
                return(FKO_ERROR_INVALID_DATA);
            }
        }
    }

    /* Done with the tmp buffer.
    */
    free(tbuf);

    /* Call the context initialized.
    */
    ctx->initval = FKO_CTX_INITIALIZED;
    FKO_SET_CTX_INITIALIZED(ctx);

    return(FKO_SUCCESS);
}

/***EOF***/
