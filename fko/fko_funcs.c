/* $Id$
 *****************************************************************************
 *
 * File:    fko_funcs.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: General utility functions for libfko
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

/* The base64 encoded version of "Salted__" that may be found at the head
 * of Rijndael encrypted data.
*/
#define B64_RIJNDAEL_SALT "U2FsdGVkX1"

/* Initialize an fko context.
*/
int
fko_new(fko_ctx_t *ctx)
{
    int         res;
    char       *ver;

    /* Zero out the context...
    */
    bzero(ctx, sizeof(fko_ctx_t));

    /* Set default values and state.
     *
     * Note: We have to explicitly set the ctx->state to initialized
     *       just before making an fko_xxx function call, then set it
     *       back to zero just afer.  During initialization, we need
     *       to make these functions think they are operating on an
     *       initialized context, or else they would fail.
    */

    /* Set the version string.
    */
    ctx->initval = FKO_CTX_INITIALIZED;
    ver = strdup(FKO_PROTOCOL_VERSION);
    ctx->initval = 0;
    if(ver == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);
    
    ctx->version = ver;

    /* Rand value.
    */
    ctx->initval = FKO_CTX_INITIALIZED;
    res = fko_set_rand_value(ctx, NULL);
    ctx->initval = 0;
    if(res != FKO_SUCCESS)
        return res;

    /* Username.
    */
    ctx->initval = FKO_CTX_INITIALIZED;
    res = fko_set_username(ctx, NULL);
    ctx->initval = 0;
    if(res != FKO_SUCCESS)
        return res;

    /* Timestamp.
    */
    ctx->initval = FKO_CTX_INITIALIZED;
    res = fko_set_timestamp(ctx, 0);
    ctx->initval = 0;
    if(res != FKO_SUCCESS)
        return res;

    /* Default Digest Type.
    */
    ctx->initval = FKO_CTX_INITIALIZED;
    res = fko_set_spa_digest_type(ctx, FKO_DEFAULT_DIGEST);
    ctx->initval = 0;
    if(res != FKO_SUCCESS)
        return res;

    /* Default Message Type.
    */
    ctx->initval = FKO_CTX_INITIALIZED;
    res = fko_set_spa_message_type(ctx, FKO_DEFAULT_MSG_TYPE);
    ctx->initval = 0;
    if(res != FKO_SUCCESS)
        return res;

    /* Default Encryption Type.
    */
    ctx->initval = FKO_CTX_INITIALIZED;
    res = fko_set_spa_encryption_type(ctx, FKO_DEFAULT_ENCRYPTION);
    ctx->initval = 0;
    if(res != FKO_SUCCESS)
        return res;

    /* Now we mean it.
    */
    ctx->initval = FKO_CTX_INITIALIZED;

    FKO_SET_CTX_INITIALIZED(ctx);

    return(FKO_SUCCESS);
} 

/* Initialize an fko context with external (encrypted/encoded) data.
 * This is used to create a context with the purpose of decoding
 * and parsing the provided data into the context data.
*/
int
fko_new_with_data(fko_ctx_t *ctx, char *enc_msg, const char *dec_key)
{
    /* Zero out the context...
    */
    bzero(ctx, sizeof(fko_ctx_t));

    /* First, add the data to the context.
    */
    ctx->encrypted_msg = strdup(enc_msg);
    if(ctx->encrypted_msg == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    FKO_SET_CTX_INITIALIZED(ctx);

    if(dec_key != NULL)
        return(fko_decrypt_spa_data(ctx, dec_key));

    return(FKO_SUCCESS);
}

/* Destroy a context and free its resources
*/
void
fko_destroy(fko_ctx_t *ctx)
{
    if(CTX_INITIALIZED(ctx))
    {
        if(ctx->rand_val != NULL)
            free(ctx->rand_val);

        if(ctx->username != NULL)
            free(ctx->username);

        if(ctx->version != NULL)
            free(ctx->version);

        if(ctx->message != NULL)
            free(ctx->message);

        if(ctx->nat_access != NULL)
            free(ctx->nat_access);

        if(ctx->server_auth != NULL)
            free(ctx->server_auth);

        if(ctx->digest != NULL)
            free(ctx->digest);

        if(ctx->encoded_msg != NULL)
            free(ctx->encoded_msg);

        if(ctx->encrypted_msg != NULL)
            free(ctx->encrypted_msg);

        bzero(ctx, sizeof(fko_ctx_t));
    }
}

/* Return the fko version
*/
char*
fko_version(fko_ctx_t *ctx)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(NULL);

    return(ctx->version);
}

/* Final update and encoding of data in the context.
 * This does require all requisite fields be properly
 * set.
*/
int
fko_spa_data_final(fko_ctx_t *ctx, const char *enc_key)
{
    int res;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    return(fko_encrypt_spa_data(ctx, enc_key));
}

/* Return the fko SPA encrypted data.
*/
char*
fko_get_spa_data(fko_ctx_t *ctx)
{
    int res;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return NULL;

    return(ctx->encrypted_msg); 
}

/***EOF***/
