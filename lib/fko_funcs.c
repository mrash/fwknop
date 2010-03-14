/* $Id$
 *****************************************************************************
 *
 * File:    fko_funcs.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: General utility functions for libfko
 *
 * Copyright (C) 2009 Damien Stuart (dstuart@dstuart.org)
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

/* Initialize an fko context.
*/
int
fko_new(fko_ctx_t *r_ctx)
{
    fko_ctx_t   ctx;
    int         res;
    char       *ver;

    ctx = calloc(1, sizeof *ctx);
    if(ctx == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

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
    {
        free(ctx);
        return(FKO_ERROR_MEMORY_ALLOCATION);
    }
    
    ctx->version = ver;

    /* Rand value.
    */
    ctx->initval = FKO_CTX_INITIALIZED;
    res = fko_set_rand_value(ctx, NULL);
    ctx->initval = 0;
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        return res;
    }

    /* Username.
    */
    ctx->initval = FKO_CTX_INITIALIZED;
    res = fko_set_username(ctx, NULL);
    ctx->initval = 0;
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        return res;
    }

    /* Timestamp.
    */
    ctx->initval = FKO_CTX_INITIALIZED;
    res = fko_set_timestamp(ctx, 0);
    ctx->initval = 0;
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        return res;
    }

    /* Default Digest Type.
    */
    ctx->initval = FKO_CTX_INITIALIZED;
    res = fko_set_spa_digest_type(ctx, FKO_DEFAULT_DIGEST);
    ctx->initval = 0;
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        return res;
    }

    /* Default Message Type.
    */
    ctx->initval = FKO_CTX_INITIALIZED;
    res = fko_set_spa_message_type(ctx, FKO_DEFAULT_MSG_TYPE);
    ctx->initval = 0;
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        return res;
    }

    /* Default Encryption Type.
    */
    ctx->initval = FKO_CTX_INITIALIZED;
    res = fko_set_spa_encryption_type(ctx, FKO_DEFAULT_ENCRYPTION);
    ctx->initval = 0;
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        return res;
    }

#if HAVE_LIBGPGME
    /* Set gpg signature verify on.
    */
    ctx->verify_gpg_sigs = 1;

#endif /* HAVE_LIBGPGME */

    /* Now we mean it.
    */
    ctx->initval = FKO_CTX_INITIALIZED;

    FKO_SET_CTX_INITIALIZED(ctx);

    *r_ctx = ctx;

    return(FKO_SUCCESS);
} 

/* Initialize an fko context with external (encrypted/encoded) data.
 * This is used to create a context with the purpose of decoding
 * and parsing the provided data into the context data.
*/
int
fko_new_with_data(fko_ctx_t *r_ctx, char *enc_msg, char *dec_key)
{
    fko_ctx_t   ctx;
    int         res = FKO_SUCCESS; /* Are we optimistic or what? */

    ctx = calloc(1, sizeof *ctx);
    if(ctx == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    /* First, add the data to the context.
    */
    ctx->encrypted_msg = strdup(enc_msg);
    if(ctx->encrypted_msg == NULL)
    {
        free(ctx);
        return(FKO_ERROR_MEMORY_ALLOCATION);
    }

    /* Consider it initialized here.
    */
    ctx->initval = FKO_CTX_INITIALIZED;
    FKO_SET_CTX_INITIALIZED(ctx);

    /* If a decryption password is provided, go ahead and decrypt and
     * decode.
    */
    if(dec_key != NULL)
    {
        res = fko_decrypt_spa_data(ctx, dec_key);

        if(res != FKO_SUCCESS)
        {
            fko_destroy(ctx);
            *r_ctx = NULL; /* Make sure the caller ctx is null just in case */
            return(res);
        }
    }

#if HAVE_LIBGPGME
    /* Set gpg signature verify on.
    */
    ctx->verify_gpg_sigs = 1;

#endif /* HAVE_LIBGPGME */

    *r_ctx = ctx;

    return(res);
}

/* Destroy a context and free its resources
*/
void
fko_destroy(fko_ctx_t ctx)
{
#if HAVE_LIBGPGME
    fko_gpg_sig_t   gsig, tgsig;
#endif

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

#if HAVE_LIBGPGME
        if(ctx->gpg_exe != NULL)
            free(ctx->gpg_exe);

        if(ctx->gpg_home_dir != NULL)
            free(ctx->gpg_home_dir);

        if(ctx->gpg_recipient != NULL)
            free(ctx->gpg_recipient);

        if(ctx->gpg_signer != NULL)
            free(ctx->gpg_signer);

        if(ctx->recipient_key != NULL)
        {
            gpgme_key_unref(ctx->recipient_key);
        }
        
        if(ctx->signer_key != NULL)
        {
            gpgme_key_unref(ctx->signer_key);
        }
        
        if(ctx->gpg_ctx != NULL)
            gpgme_release(ctx->gpg_ctx);

        gsig = ctx->gpg_sigs;
        while(gsig != NULL)
        {
            if(gsig->fpr != NULL)
                free(gsig->fpr);

            tgsig = gsig;
            gsig = gsig->next;

            free(tgsig);
        }

#endif /* HAVE_LIBGPGME */

        bzero(ctx, sizeof(*ctx));
    }

    free(ctx);
}

/* Return the fko version
*/
int
fko_get_version(fko_ctx_t ctx, char **version)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *version = ctx->version;

    return(FKO_SUCCESS);
}

/* Final update and encoding of data in the context.
 * This does require all requisite fields be properly
 * set.
*/
int
fko_spa_data_final(fko_ctx_t ctx, char *enc_key)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    return(fko_encrypt_spa_data(ctx, enc_key));
}

/* Return the fko SPA encrypted data.
*/
int
fko_get_spa_data(fko_ctx_t ctx, char **spa_data)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *spa_data = ctx->encrypted_msg; 

    /* Notice we omit the first 10 bytes if Rijndael encryption is
     * used (to eliminate the consistent 'Salted__' string), and
     * in GnuPG mode we eliminate the consistent 'hQ' base64 encoded
     * prefix
    */
    if(ctx->encryption_type == FKO_ENCRYPTION_RIJNDAEL)
        *spa_data += strlen(B64_RIJNDAEL_SALT);
    else if(ctx->encryption_type == FKO_ENCRYPTION_GPG)
        *spa_data += strlen(B64_GPG_PREFIX);

    return(FKO_SUCCESS);
}

/* Set the fko SPA encrypted data.
*/
int
fko_set_spa_data(fko_ctx_t ctx, char *enc_msg)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* First, add the data to the context.
    */
    ctx->encrypted_msg = strdup(enc_msg);
    if(ctx->encrypted_msg == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    return(FKO_SUCCESS); 
}

/***EOF***/
