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

#if HAVE_LIBGPGME
  #include "gpgme_funcs.h"
  #if HAVE_SYS_STAT_H
    #include <sys/stat.h>
  #endif
#endif

#define B64_RIJNDAEL_SALT "U2FsdGVkX1"

/* Wipe out the password buffer.
*/
void
wipe_pw(char *pw)
{
    if(pw != NULL)
        bzero(pw, strlen(pw));
}

/* Prep and encrypt using Rijndael
*/
int
_rijndael_encrypt(fko_ctx_t ctx, char *enc_key)
{
    char           *plain;
    char           *b64cipher;
    unsigned char  *cipher;
    int             cipher_len;

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

    cipher_len = rij_encrypt(
        (unsigned char*)plain, strlen(plain), (char*)enc_key, cipher
    );

    /* Now make a bucket for the base64-encoded version and populate it.
    */
    b64cipher = malloc(((cipher_len / 3) * 4) + 8);
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
_rijndael_decrypt(fko_ctx_t ctx, char *dec_key, int b64_len)
{
    char           *tbuf, *ndx;
    unsigned char  *cipher;
    int             cipher_len, pt_len, i, err = 0;

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

        /* Adjust b64_len for added SALT value and Make sure we are still
         * a properly NULL-terminated string (Ubuntu was one system for
         * which this was an issue).
        */
        b64_len += 10;
        tbuf[b64_len] = '\0';
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

    pt_len = rij_decrypt(cipher, cipher_len, dec_key, (unsigned char*)ctx->encoded_msg);
 
    /* Done with cipher...
    */
    free(cipher);

    /* The length of the decrypted data should be within 32 bytes of the
     * length of the encrypted version.
    */
    if(pt_len < (cipher_len - 32))
        return(FKO_ERROR_DECRYPTION_SIZE);

    /* At this point we can check the data to see if we have a good
     * decryption by ensuring the first field (16-digit random decimal
     * value) is valid and is followed by a colon.
    */
    ndx = ctx->encoded_msg;
    for(i=0; i<FKO_RAND_VAL_SIZE; i++)
        if(!isdigit(*(ndx++)))
            err++;

    if(err > 0 || *ndx != ':')
        return(FKO_ERROR_DECRYPTION_FAILURE);
    
    /* Call fko_decode and return the results.
    */
    return(fko_decode_spa_data(ctx));
}


#if HAVE_LIBGPGME

/* Prep and encrypt using gpgme
*/
int
gpg_encrypt(fko_ctx_t ctx, char *enc_key)
{
    int             res;
    char           *plain;
    char           *b64cipher;
    unsigned char  *cipher = NULL;
    size_t          cipher_len;

    /* First make sure we have signer and recipient keys set.
    */
    if(ctx->gpg_signer == NULL || ctx->gpg_recipient == NULL)
        return(FKO_ERROR_MISSING_GPG_KEY_DATA);

    /* Make a bucket big enough to hold the enc msg + digest (plaintext)
     * and populate it appropriately.
    */
    plain = malloc(strlen(ctx->encoded_msg) + strlen(ctx->digest) + 2);
    if(plain == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    sprintf(plain, "%s:%s", ctx->encoded_msg, ctx->digest);

    res = gpgme_encrypt(ctx,
        (unsigned char*)plain, strlen(plain),
        enc_key, &cipher, &cipher_len
    );

    /* --DSS XXX: Better parsing of what went wrong would be nice :)
    */
    if(res != FKO_SUCCESS)
    {
        free(plain);

        if(cipher)
            free(cipher);

        return(res);
    }

    /* Now make a bucket for the base64-encoded version and populate it.
    */
    b64cipher = malloc(((cipher_len / 3) * 4) + 8);
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

/* Prep and encrypt using gpgme
*/
int
gpg_decrypt(fko_ctx_t ctx, char *dec_key, size_t b64_len)
{
    unsigned char  *cipher;
    size_t          cipher_len;
    int             res;

    /* First make sure we have signer and recipient keys set.
    if(ctx->gpg_signer == NULL || ctx->gpg_recipient == NULL)
        return(FKO_ERROR_MISSING_GPG_KEY_DATA);
    */

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

    res = gpgme_decrypt(ctx, cipher, cipher_len,
        dec_key,  (unsigned char**)&ctx->encoded_msg, &cipher_len
    );
    
 
    /* Done with cipher...
    */
    free(cipher);

    if(res != FKO_SUCCESS)
        return(res);

    /* XXX: We could put some kind of sanity check  of the decrypted
     *      data here
    */

    /* Call fko_decode and return the results.
    */
    return(fko_decode_spa_data(ctx));
}

#endif /* HAVE_LIBGPGME */

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
fko_encrypt_spa_data(fko_ctx_t ctx, char *enc_key)
{
    int             res;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
    {
        res = FKO_ERROR_CTX_NOT_INITIALIZED;
        goto EWIPEOUT;
    }

    /* If there is no encoded data or the SPA data has been modified,
     * go ahead and re-encode here.
    */
    if(ctx->encoded_msg == NULL || FKO_IS_SPA_DATA_MODIFIED(ctx))
        res = fko_encode_spa_data(ctx);

    /* Croak on invalid encoded message as well. At present this is a
     * check for a somewhat arbitrary minimum length for the encoded
     * data.
    */
    if(strlen(ctx->encoded_msg) < MIN_SPA_ENCODED_MSG_SIZE)
    {
        res = FKO_ERROR_MISSING_ENCODED_DATA;
        goto EWIPEOUT;
    }

    /* Encrypt according to type and return...
    */
    if(ctx->encryption_type == FKO_ENCRYPTION_RIJNDAEL)
        res = _rijndael_encrypt(ctx, enc_key);
    else if(ctx->encryption_type == FKO_ENCRYPTION_GPG)
#if HAVE_LIBGPGME
        res = gpg_encrypt(ctx, enc_key);
#else
        res = FKO_ERROR_UNSUPPORTED_FEATURE;
#endif
    else
        res = FKO_ERROR_INVALID_ENCRYPTION_TYPE;

EWIPEOUT:
    wipe_pw(enc_key);

    return(res);
}

/* Decode, decrypt, and parse SPA data into the context.
*/
int
fko_decrypt_spa_data(fko_ctx_t ctx, char *dec_key)
{
    int             b64_len, res;
    char           *ndx;

    /* First, make sure we have data to work with.
    */
    if(ctx->encrypted_msg == NULL
      || strlen(ctx->encrypted_msg) <  MIN_SPA_ENCODED_MSG_SIZE)
    {
        res = FKO_ERROR_INVALID_DATA;
        goto DWIPEOUT;
    }

    /* Determine type of encryption used.  For know, we are using the
     * size of the message.  
     *
     * XXX: We will want to come up with a more reliable method of
     *      identifying the encryption type.
    */
    b64_len = strlen(ctx->encrypted_msg);

    if(b64_len > MIN_GNUPG_MSG_SIZE)
    {
        ctx->encryption_type = FKO_ENCRYPTION_GPG;
#if HAVE_LIBGPGME
        res = gpg_decrypt(ctx, dec_key, b64_len);
#else
        res = FKO_ERROR_UNSUPPORTED_FEATURE;
#endif
    }
    else /* We are assuming the default of Rijndael */
    {
        ctx->encryption_type = FKO_ENCRYPTION_RIJNDAEL;
        res = _rijndael_decrypt(ctx, dec_key, b64_len);
    }

DWIPEOUT:
    wipe_pw(dec_key);

    return(res);
}

/* Set the GPG recipient key name.
*/
int
fko_set_gpg_recipient(fko_ctx_t ctx, const char *recip)
{
#if HAVE_LIBGPGME
    int             res;
    gpgme_key_t     key     = NULL;
    
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(ctx->encryption_type != FKO_ENCRYPTION_GPG)
        return(FKO_ERROR_WRONG_ENCRYPTION_TYPE);

    ctx->gpg_recipient = strdup(recip);
    if(ctx->gpg_recipient == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    /* Get the key.
    */
    res = get_gpg_key(ctx, &key, 0);
    if(res != FKO_SUCCESS)
    {
        free(ctx->gpg_recipient);
        ctx->gpg_recipient = NULL;
        return(res);
    }

    ctx->recipient_key = key;

    ctx->state |= FKO_DATA_MODIFIED;

    return(FKO_SUCCESS);
#else
    return(FKO_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

/* Get the GPG recipient key name.
*/
char*
fko_get_gpg_recipient(fko_ctx_t ctx)
{
#if HAVE_LIBGPGME
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(NULL);

    return(ctx->gpg_recipient);
#else
    //--DSS we should make this an error
    return(NULL);
#endif  /* HAVE_LIBGPGME */
}

/* Set the GPG signer key name.
*/
int
fko_set_gpg_signer(fko_ctx_t ctx, const char *signer)
{
#if HAVE_LIBGPGME
    int             res;
    gpgme_key_t     key     = NULL;
    
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(ctx->encryption_type != FKO_ENCRYPTION_GPG)
        return(FKO_ERROR_WRONG_ENCRYPTION_TYPE);

    ctx->gpg_signer = strdup(signer);
    if(ctx->gpg_signer == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    /* Get the key.
    */
    res = get_gpg_key(ctx, &key, 1);
    if(res != FKO_SUCCESS)
    {
        free(ctx->gpg_signer);
        ctx->gpg_signer = NULL;
        return(res);
    }

    ctx->signer_key = key;

    ctx->state |= FKO_DATA_MODIFIED;

    return(FKO_SUCCESS);
#else
    return(FKO_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

/* Get the GPG signer key name.
*/
char*
fko_get_gpg_signer(fko_ctx_t ctx)
{
#if HAVE_LIBGPGME
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(NULL);

    return(ctx->gpg_signer);
#else
    //--DSS we should make this an error
    return(NULL);
#endif  /* HAVE_LIBGPGME */
}

/* Set the GPG home dir.
*/
int
fko_set_gpg_home_dir(fko_ctx_t ctx, const char *gpg_home_dir)
{
#if HAVE_LIBGPGME
    struct stat     st;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    /* If we are unable to stat the given dir, then return with error.
    */
    if(stat(gpg_home_dir, &st) != 0)
        return(FKO_ERROR_GPGME_BAD_HOME_DIR);

    if(!S_ISDIR(st.st_mode)) 
        return(FKO_ERROR_GPGME_BAD_HOME_DIR);

    ctx->gpg_home_dir = strdup(gpg_home_dir);
    if(ctx->gpg_home_dir == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    return(FKO_SUCCESS);
#else
    return(FKO_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

/* Get the GPG home dir.
*/
char*
fko_get_gpg_home_dir(fko_ctx_t ctx)
{
#if HAVE_LIBGPGME
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(NULL);

    return(ctx->gpg_home_dir);
#else
    //--DSS we should make this an error
    return(NULL);
#endif  /* HAVE_LIBGPGME */
}

/***EOF***/
