/* $Id$
 *****************************************************************************
 *
 * File:    fko_decode.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Decrypt and decode an FKO SPA message.
 *
 * Copyright (C) 2008 Damien Stuart (dstuart@dstuart.org)
 *
 *  License (GNU Public License):
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program; if not, write to the Free Software
 *     Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *     USA
 *
 *****************************************************************************
*/
#include "fko_common.h"
#include "fko.h"
#include "cipher_funcs.h"
#include "base64.h"
#include "digest.h"

/* Decrypt the encoded SPA data.
*/
int
fko_decode_spa_data(fko_ctx_t ctx)
{
    char       *tbuf, *ndx;
    int         edata_size, t_size;

    /* Check for required data.
    */
    if(ctx->encoded_msg == NULL
      || strlen(ctx->encoded_msg) < MIN_SPA_ENCODED_MSG_SIZE)
        return(FKO_ERROR_INVALID_DATA);

    edata_size = strlen(ctx->encoded_msg);

    /* Move the Digest to its place in the context.
    */
    ndx = strrchr(ctx->encoded_msg, ':'); /* Find the last : in the data */
    if(ndx == NULL)
        return(FKO_ERROR_INVALID_DATA);

    ndx++;

    t_size = strlen(ndx);

    switch(t_size)
    {
        case MD_B64_SIZE(MD5_DIGESTSIZE):
            ctx->digest_type = FKO_DIGEST_MD5;
            break;

        case MD_B64_SIZE(SHA1_DIGESTSIZE):
            ctx->digest_type = FKO_DIGEST_SHA1;
            break;

        case MD_B64_SIZE(SHA256_DIGESTSIZE):
            ctx->digest_type = FKO_DIGEST_SHA256;
            break;

        default: /* Invalid or unsupported digest */
            return(FKO_ERROR_INVALID_DIGEST_TYPE);
    }

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
            md5_base64(tbuf, (unsigned char*)ctx->encoded_msg, strlen(ctx->encoded_msg));
            break;

        case FKO_DIGEST_SHA1:
            sha1_base64(tbuf, (unsigned char*)ctx->encoded_msg, strlen(ctx->encoded_msg));
            break;

        case FKO_DIGEST_SHA256:
            sha256_base64(tbuf, (unsigned char*)ctx->encoded_msg, strlen(ctx->encoded_msg));
            break;

    } 

    /* We give up here if the computed digest does not match the
     * digest in the message data.
    */
    if(strcmp(ctx->digest, tbuf))
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

    ctx->rand_val = strndup(ndx, FKO_RAND_VAL_SIZE);
    if(ctx->rand_val == NULL)
    {
        free(tbuf);
        return(FKO_ERROR_MEMORY_ALLOCATION);
    }

    /* Jump to the next field (username).  We need to use the temp buffer
     * for the base64 decode step.
    */
    ndx += t_size + 1;
    if((t_size = strcspn(ndx, ":")) < 1)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }

    strlcpy(tbuf, ndx, t_size+1);
    
    ctx->username = malloc(t_size+1); /* Yes, more than we need */
    if(ctx->username == NULL)
    {
        free(tbuf);
        return(FKO_ERROR_MEMORY_ALLOCATION);
    }

    b64_decode(tbuf, (unsigned char*)ctx->username, t_size);

    /* Extract the timestamp value.
    */
    ndx += t_size + 1;
    if((t_size = strcspn(ndx, ":")) < 1)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }

    strlcpy(tbuf, ndx, t_size+1);

    ctx->timestamp = (unsigned int)atoi(tbuf);

    /* Extract the version string.
    */
    ndx += t_size + 1;
    if((t_size = strcspn(ndx, ":")) < 1)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }
 
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

    strlcpy(tbuf, ndx, t_size+1);

    ctx->message_type = (unsigned int)atoi(tbuf);

    /* Extract the SPA message string.
    */
    ndx += t_size + 1;
    if((t_size = strcspn(ndx, ":")) < 1)
    {
        free(tbuf);
        return(FKO_ERROR_INVALID_DATA);
    }

    strlcpy(tbuf, ndx, t_size+1);
    
    ctx->message = malloc(t_size+1); /* Yes, more than we need */
    if(ctx->message == NULL)
    {
        free(tbuf);
        return(FKO_ERROR_MEMORY_ALLOCATION);
    }

    b64_decode(tbuf, (unsigned char*)ctx->message, t_size);

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

        strlcpy(tbuf, ndx, t_size+1);
    
        ctx->nat_access = malloc(t_size+1); /* Yes, more than we need */
        if(ctx->nat_access == NULL)
        {
            free(tbuf);
            return(FKO_ERROR_MEMORY_ALLOCATION);
        }

        b64_decode(tbuf, (unsigned char*)ctx->nat_access, t_size);
    }

    /* Now look for a server_auth string.
    */
    ndx += t_size + 1;
    if((t_size = strlen(ndx)) > 0)
    {
        /* There is data, but what is it?
         * If the message_type does not have a timeout, assume it is a
         * server_auth field.
        */
        if(  ctx->message_type != FKO_CLIENT_TIMEOUT_ACCESS_MSG
          && ctx->message_type != FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG
          && ctx->message_type != FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
        {
            strlcpy(tbuf, ndx, t_size+1);
    
            ctx->server_auth = malloc(t_size+1); /* Yes, more than we need */
            if(ctx->server_auth == NULL)
            {
                free(tbuf);
                return(FKO_ERROR_MEMORY_ALLOCATION);
            }

            b64_decode(tbuf, (unsigned char*)ctx->server_auth, t_size);
 
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

            /* Looks like we have both, so assume this is the 
            */
            strlcpy(tbuf, ndx, t_size+1);
    
            ctx->server_auth = malloc(t_size+1); /* Yes, more than we need */
            if(ctx->server_auth == NULL)
            {
                free(tbuf);
                return(FKO_ERROR_MEMORY_ALLOCATION);
            }

            b64_decode(tbuf, (unsigned char*)ctx->server_auth, t_size);

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

            /* Should be a number only.
            */
            if(strspn(ndx, "0123456789") != t_size)
            {
                free(tbuf);
                return(FKO_ERROR_INVALID_DATA);
            }

            ctx->client_timeout = (unsigned int)atoi(ndx);
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
