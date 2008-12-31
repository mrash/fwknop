/* $Id$
 *****************************************************************************
 *
 * File:    fko_encryption.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Set/Get the spa encryption type.
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

#define B64_RIJNDAEL_SALT "U2FsdGVkX1"

/* Set the SPA encryption type.
*/
int
fko_set_spa_encryption_type(fko_ctx_t ctx, short encrypt_type)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(encrypt_type < 0 || encrypt_type >= FKO_LAST_ENCRYPTION_TYPE)
        return(FKO_ERROR_INVALID_DATA);

    ctx->encryption_type = encrypt_type;

    ctx->state |= FKO_ENCRYPT_TYPE_MODIFIED;

    return(FKO_SUCCESS);
}

/* Return the SPA encryption type.
*/
short
fko_get_spa_encryption_type(fko_ctx_t ctx)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    return(ctx->encryption_type);
}

/* Encrypt the encoded SPA data.
*/
int
fko_encrypt_spa_data(fko_ctx_t ctx, const char *enc_key)
{
    char           *plain;
    char           *b64cipher;
    unsigned char  *cipher;
    int             cipher_len, res;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    /* If there is no encoded data or the SPA data has been modified,
     * go ahead and re-encode here.
    */
    if(ctx->encoded_msg == NULL || FKO_SPA_DATA_MODIFIED(ctx))
    {
        res = fko_encode_spa_data(ctx);

        if(res != FKO_SUCCESS)
            return(res);
    }

    /* Croak on invalid encoded message as well. At present this is a
     * check for a somewhat arbitrary minimum length for the encoded
     * data.
    */
    if(strlen(ctx->encoded_msg) < MIN_SPA_ENCODED_MSG_SIZE)
        return(FKO_ERROR_MISSING_ENCODED_DATA);

    /* Make a bucket big enough to hold the enc msg + digest (plaintext)
     * and populate it appropriately.
    */
    plain = malloc(strlen(ctx->encoded_msg) + strlen(ctx->digest) + 2);
    if(plain == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    sprintf(plain, "%s:%s", ctx->encoded_msg, ctx->digest);

    /* Make a bucket for the encrypted version and populate it.
    */
    cipher = malloc(strlen(plain) + 32); /* Plus padding for salt and Block */
    if(cipher == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    cipher_len = fko_encrypt(
        (unsigned char*)plain, strlen(plain), (char*)enc_key, cipher
    );

    /* Now make a bucket for the base64-encoded version and populate it.
    */
    b64cipher = malloc(((cipher_len / 3) * 4) + 4);
    if(b64cipher == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    b64_encode(cipher, b64cipher, cipher_len);
    strip_b64_eq(b64cipher);

    ctx->encrypted_msg = strdup(b64cipher);
    
    /* Clean-up
    */
    free(plain);
    free(cipher);
    free(b64cipher);

    if(ctx->encrypted_msg == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    return(FKO_SUCCESS);
}

/* Decode, decrypt, and parse SPA data into the context.
*/
int
fko_decrypt_spa_data(fko_ctx_t ctx, const char *dec_key)
{
    char           *tbuf;
    unsigned char  *cipher;
    int             b64_len, cipher_len, pt_len;

    /* First, make sure we have data to work with.
    */
    if(ctx->encrypted_msg == NULL
      || strlen(ctx->encrypted_msg) <  MIN_SPA_ENCODED_MSG_SIZE)
        return(FKO_ERROR_INVALID_DATA);

    /* Determine type of encryption used.  For know, we are using the
     * size of the message.  However, we will want to come up with a
     * more reliable method of identification.
    */
    b64_len = strlen(ctx->encrypted_msg);

    if(b64_len > MIN_GNUPG_MSG_SIZE)
    {
        /* TODO: add GPG handling */
        /* Since we do not support GPG yet, we will just fall through */
    }

    /* Assuming Rijndael */

    /* Now see if we need to add the "Salted__" string to the front of the
     * encrypted data.
    */
    if(strncmp(ctx->encrypted_msg, B64_RIJNDAEL_SALT, strlen(B64_RIJNDAEL_SALT)))
    {
        /* We need to realloc space for the salt.
        */
        tbuf = realloc(ctx->encrypted_msg, b64_len + 12);
        if(tbuf == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);

        memmove(tbuf+10, tbuf, b64_len);
        ctx->encrypted_msg = memcpy(tbuf, B64_RIJNDAEL_SALT, strlen(B64_RIJNDAEL_SALT));
    }

    /* Create a bucket for the (base64) decoded encrypted data and get the
     * raw cipher data.
    */
    cipher = malloc(strlen(ctx->encrypted_msg));
    if(cipher == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);
 
    cipher_len = b64_decode(ctx->encrypted_msg, cipher, b64_len);

    /* Create a bucket for the plaintext data and decrypt the message
     * data into it.
    */
    ctx->encoded_msg = malloc(cipher_len);
    if(ctx->encoded_msg == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    pt_len = fko_decrypt(cipher, cipher_len, dec_key, (unsigned char*)ctx->encoded_msg);
 
    /* Done with cipher...
    */
    free(cipher);

    /* The length of the decrypted data should be within 16 of the
     * length of the encrypted version.
    */
    if(pt_len < (cipher_len - 32))
        return(FKO_ERROR_DECRYPTION_SIZE_ERROR);

    /* Call fko_decode and return the results.
    */
    return(fko_decode_spa_data(ctx));
}

/***EOF***/
