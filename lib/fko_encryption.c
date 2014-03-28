/*
 *****************************************************************************
 *
 * File:    fko_encryption.c
 *
 * Purpose: Set/Get the spa encryption type.
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2014 fwknop developers and contributors. For a full
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
#include "base64.h"
#include "digest.h"

#if HAVE_LIBGPGME
  #include "gpgme_funcs.h"
  #if HAVE_SYS_STAT_H
    #include <sys/stat.h>
  #endif
#endif

/* Prep and encrypt using Rijndael
*/
static int
_rijndael_encrypt(fko_ctx_t ctx, const char *enc_key, const int enc_key_len)
{
    char           *plaintext;
    char           *b64ciphertext;
    unsigned char  *ciphertext;
    int             cipher_len;
    int             pt_len;
    int             zero_free_rv = FKO_SUCCESS;

    if(enc_key_len < 0 || enc_key_len > RIJNDAEL_MAX_KEYSIZE)
        return(FKO_ERROR_INVALID_KEY_LEN);

    if (! is_valid_encoded_msg_len(ctx->encoded_msg_len))
        return(FKO_ERROR_INVALID_DATA_ENCRYPT_MSGLEN_VALIDFAIL);

    switch(ctx->digest_len)
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
            return(FKO_ERROR_INVALID_DATA_ENCRYPT_DIGESTLEN_VALIDFAIL);
    }

    pt_len = ctx->encoded_msg_len + ctx->digest_len + RIJNDAEL_BLOCKSIZE + 2;

    /* Make a bucket big enough to hold the enc msg + digest (plaintext)
     * and populate it appropriately.
    */
    plaintext = calloc(1, pt_len);

    if(plaintext == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    pt_len = snprintf(plaintext, pt_len, "%s:%s", ctx->encoded_msg, ctx->digest);

    if(! is_valid_pt_msg_len(pt_len))
    {
        if(zero_free(plaintext, pt_len) == FKO_SUCCESS)
            return(FKO_ERROR_INVALID_DATA_ENCRYPT_PTLEN_VALIDFAIL);
        else
            return(FKO_ERROR_ZERO_OUT_DATA);
    }

    /* Make a bucket for the encrypted version and populate it.
    */
    ciphertext = calloc(1, pt_len + 32); /* Plus padding for salt and Block */
    if(ciphertext == NULL)
    {
        if(zero_free(plaintext, pt_len) == FKO_SUCCESS)
            return(FKO_ERROR_MEMORY_ALLOCATION);
        else
            return(FKO_ERROR_ZERO_OUT_DATA);
    }

    cipher_len = rij_encrypt(
        (unsigned char*)plaintext, pt_len,
        (char*)enc_key, enc_key_len,
        ciphertext, ctx->encryption_mode
    );

    /* Now make a bucket for the base64-encoded version and populate it.
    */
    b64ciphertext = calloc(1, ((cipher_len / 3) * 4) + 8);
    if(b64ciphertext == NULL)
    {
        if(zero_free((char *) ciphertext, pt_len+32) == FKO_SUCCESS
                && zero_free(plaintext, pt_len) == FKO_SUCCESS)
            return(FKO_ERROR_MEMORY_ALLOCATION);
        else
            return(FKO_ERROR_ZERO_OUT_DATA);
    }

    b64_encode(ciphertext, b64ciphertext, cipher_len);
    strip_b64_eq(b64ciphertext);

    if(ctx->encrypted_msg != NULL)
        zero_free_rv = zero_free(ctx->encrypted_msg,
                strnlen(ctx->encrypted_msg, MAX_SPA_ENCODED_MSG_SIZE));

    ctx->encrypted_msg     = strdup(b64ciphertext);
    ctx->encrypted_msg_len = strnlen(ctx->encrypted_msg, MAX_SPA_ENCODED_MSG_SIZE);

    /* Clean-up
    */
    if(zero_free(plaintext, pt_len) != FKO_SUCCESS)
        zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    if(zero_free((char *) ciphertext, pt_len+32) != FKO_SUCCESS)
        zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    if(zero_free(b64ciphertext, strnlen(b64ciphertext,
                    MAX_SPA_ENCODED_MSG_SIZE)) != FKO_SUCCESS)
        zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    if(ctx->encrypted_msg == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    if(! is_valid_encoded_msg_len(ctx->encrypted_msg_len))
        return(FKO_ERROR_INVALID_DATA_ENCRYPT_RESULT_MSGLEN_VALIDFAIL);

    return(zero_free_rv);
}

/* Decode, decrypt, and parse SPA data into the context.
*/
static int
_rijndael_decrypt(fko_ctx_t ctx,
    const char *dec_key, const int key_len, int encryption_mode)
{
    unsigned char  *ndx;
    unsigned char  *cipher;
    int             cipher_len, pt_len, i, err = 0, res = FKO_SUCCESS;
    int             zero_free_rv = FKO_SUCCESS;

    if(key_len < 0 || key_len > RIJNDAEL_MAX_KEYSIZE)
        return(FKO_ERROR_INVALID_KEY_LEN);

    /* Now see if we need to add the "Salted__" string to the front of the
     * encrypted data.
    */
    if(! ctx->added_salted_str)
    {
        res = add_salted_str(ctx);
        if(res != FKO_SUCCESS)
            return res;
    }

    /* Create a bucket for the (base64) decoded encrypted data and get the
     * raw cipher data.
    */
    cipher = calloc(1, ctx->encrypted_msg_len);
    if(cipher == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    if((cipher_len = b64_decode(ctx->encrypted_msg, cipher)) < 0)
    {
        if(zero_free((char *)cipher, ctx->encrypted_msg_len) == FKO_SUCCESS)
            return(FKO_ERROR_INVALID_DATA_ENCRYPT_CIPHERLEN_DECODEFAIL);
        else
            return(FKO_ERROR_ZERO_OUT_DATA);
    }

    /* Since we're using AES, make sure the incoming data is a multiple of
     * the blocksize
    */
    if((cipher_len % RIJNDAEL_BLOCKSIZE) != 0)
    {
        if(zero_free((char *)cipher, ctx->encrypted_msg_len) == FKO_SUCCESS)
            return(FKO_ERROR_INVALID_DATA_ENCRYPT_CIPHERLEN_VALIDFAIL);
        else
            return(FKO_ERROR_ZERO_OUT_DATA);
    }

    if(ctx->encoded_msg != NULL)
        zero_free_rv = zero_free(ctx->encoded_msg,
                strnlen(ctx->encoded_msg, MAX_SPA_ENCODED_MSG_SIZE));

    /* Create a bucket for the plaintext data and decrypt the message
     * data into it.
    */
    ctx->encoded_msg = calloc(1, cipher_len);
    if(ctx->encoded_msg == NULL)
    {
        if(zero_free((char *)cipher, ctx->encrypted_msg_len) == FKO_SUCCESS)
            return(FKO_ERROR_MEMORY_ALLOCATION);
        else
            return(FKO_ERROR_ZERO_OUT_DATA);
    }

    pt_len = rij_decrypt(cipher, cipher_len, dec_key, key_len,
                (unsigned char*)ctx->encoded_msg, encryption_mode);

    /* Done with cipher...
    */
    if(zero_free((char *)cipher, ctx->encrypted_msg_len) != FKO_SUCCESS)
        zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    /* The length of the decrypted data should be within 32 bytes of the
     * length of the encrypted version.
    */
    if(pt_len < (cipher_len - 32) || pt_len <= 0)
        return(FKO_ERROR_DECRYPTION_SIZE);

    if(ctx->encoded_msg == NULL)
        return(FKO_ERROR_MISSING_ENCODED_DATA);

    if(! is_valid_encoded_msg_len(pt_len))
        return(FKO_ERROR_INVALID_DATA_DECODE_MSGLEN_VALIDFAIL);

    if(zero_free_rv != FKO_SUCCESS)
        return(zero_free_rv);

    ctx->encoded_msg_len = pt_len;

    /* At this point we can check the data to see if we have a good
     * decryption by ensuring the first field (16-digit random decimal
     * value) is valid and is followed by a colon.  Additional checks
     * are made in fko_decode_spa_data().
    */

    if(ctx->rand_mode == FKO_RAND_MODE_LEGACY)
    {
        ndx = (unsigned char *)ctx->encoded_msg;
        for(i=0; i<FKO_RAND_VAL_SIZE; i++)
            if(!isdigit(*(ndx++)))
                err++;
    }
    else
    {
        /* accounts for stripped '=' chars
        */
        ndx = (unsigned char *) &ctx->encoded_msg[FKO_RAND_VAL_B64_SIZE-3];
    }

    if(err > 0 || *ndx != ':')
        return(FKO_ERROR_DECRYPTION_FAILURE);

    /* Call fko_decode and return the results.
    */
    return(fko_decode_spa_data(ctx));
}


#if HAVE_LIBGPGME

/* Prep and encrypt using gpgme
*/
static int
gpg_encrypt(fko_ctx_t ctx, const char *enc_key)
{
    int             res;
    char           *plain;
    int             pt_len, zero_free_rv = FKO_SUCCESS;
    char           *b64cipher;
    unsigned char  *cipher = NULL;
    size_t          cipher_len;
    char           *empty_key = "";

    if (! is_valid_encoded_msg_len(ctx->encoded_msg_len))
        return(FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_MESSAGE_VALIDFAIL);

    switch(ctx->digest_len)
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
            return(FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_DIGEST_VALIDFAIL);
    }

    /* First make sure we have a recipient key set.
    */
    if(ctx->gpg_recipient == NULL)
        return(FKO_ERROR_MISSING_GPG_KEY_DATA);

    pt_len = ctx->encoded_msg_len + ctx->digest_len + 2;

    /* Make a bucket big enough to hold the enc msg + digest (plaintext)
     * and populate it appropriately.
    */
    plain = calloc(1, ctx->encoded_msg_len + ctx->digest_len + 2);
    if(plain == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    pt_len = snprintf(plain, pt_len+1, "%s:%s", ctx->encoded_msg, ctx->digest);

    if(! is_valid_pt_msg_len(pt_len))
    {
        if(zero_free(plain, pt_len) == FKO_SUCCESS)
            return(FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_MSGLEN_VALIDFAIL);
        else
            return(FKO_ERROR_ZERO_OUT_DATA);
    }

    if (enc_key != NULL)
    {
        res = gpgme_encrypt(ctx, (unsigned char*)plain, pt_len,
            enc_key, &cipher, &cipher_len
        );
    }
    else
    {
        res = gpgme_encrypt(ctx, (unsigned char*)plain, pt_len,
            empty_key, &cipher, &cipher_len
        );
    }

    /* --DSS XXX: Better parsing of what went wrong would be nice :)
    */
    if(res != FKO_SUCCESS)
    {
        zero_free_rv = zero_free(plain, pt_len);

        if(cipher != NULL)
            if(zero_free((char *) cipher, cipher_len) != FKO_SUCCESS)
                zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

        if(zero_free_rv == FKO_SUCCESS)
            return(res);
        else
            return(zero_free_rv);
    }

    /* Now make a bucket for the base64-encoded version and populate it.
    */
    b64cipher = calloc(1, ((cipher_len / 3) * 4) + 8);
    if(b64cipher == NULL)
    {
        if(zero_free(plain, pt_len) != FKO_SUCCESS)
            zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

        if(cipher != NULL)
            if(zero_free((char *) cipher, cipher_len) != FKO_SUCCESS)
                zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

        if(zero_free_rv == FKO_SUCCESS)
            return(FKO_ERROR_MEMORY_ALLOCATION);
        else
            return(zero_free_rv);
    }

    b64_encode(cipher, b64cipher, cipher_len);
    strip_b64_eq(b64cipher);

    if(ctx->encrypted_msg != NULL)
        zero_free_rv = zero_free(ctx->encrypted_msg,
                strnlen(ctx->encrypted_msg, MAX_SPA_ENCODED_MSG_SIZE));

    ctx->encrypted_msg     = strdup(b64cipher);
    ctx->encrypted_msg_len = strnlen(ctx->encrypted_msg, MAX_SPA_ENCODED_MSG_SIZE);

    /* Clean-up
    */
    if(zero_free(plain, pt_len) != FKO_SUCCESS)
        zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    if(zero_free((char *) cipher, cipher_len) != FKO_SUCCESS)
        zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    if(zero_free(b64cipher, strnlen(b64cipher,
                    MAX_SPA_ENCODED_MSG_SIZE)) != FKO_SUCCESS)
        zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    if(ctx->encrypted_msg == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    if(! is_valid_encoded_msg_len(ctx->encrypted_msg_len))
        return(FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_RESULT_MSGLEN_VALIDFAIL);

    return(zero_free_rv);
}

/* Prep and decrypt using gpgme
*/
static int
gpg_decrypt(fko_ctx_t ctx, const char *dec_key)
{
    unsigned char  *cipher;
    size_t          cipher_len;
    int             res, pt_len, b64_decode_len;

    /* Now see if we need to add the "hQ" string to the front of the
     * base64-encoded-GPG-encrypted data.
    */
    if(! ctx->added_gpg_prefix)
        add_gpg_prefix(ctx);

    /* Create a bucket for the (base64) decoded encrypted data and get the
     * raw cipher data.
    */
    cipher = calloc(1, ctx->encrypted_msg_len);
    if(cipher == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    if((b64_decode_len = b64_decode(ctx->encrypted_msg, cipher)) < 0)
    {
        if(zero_free((char *) cipher, ctx->encrypted_msg_len) == FKO_SUCCESS)
            return(FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_CIPHER_DECODEFAIL);
        else
            return(FKO_ERROR_ZERO_OUT_DATA);

    }

    cipher_len = b64_decode_len;

    /* Create a bucket for the plaintext data and decrypt the message
     * data into it.
    */
    /* --DSS Actually, the needed memory will be malloced in the gpgme_decrypt
    //       function. Just leaving this here for reference (for now).
    //ctx->encoded_msg = malloc(cipher_len);
    //if(ctx->encoded_msg == NULL)
    //    return(FKO_ERROR_MEMORY_ALLOCATION);
    */

    res = gpgme_decrypt(ctx, cipher, cipher_len,
        dec_key, (unsigned char**)&ctx->encoded_msg, &cipher_len
    );

    /* Done with cipher...
    */
    if(zero_free((char *) cipher, ctx->encrypted_msg_len) != FKO_SUCCESS)
        return(FKO_ERROR_ZERO_OUT_DATA);
    else
        if(res != FKO_SUCCESS) /* bail if there was some other problem */
            return(res);

    pt_len = strnlen(ctx->encoded_msg, MAX_SPA_ENCODED_MSG_SIZE);

    if(ctx->encoded_msg == NULL)
        return(FKO_ERROR_INVALID_DATA_ENCRYPT_DECRYPTED_MESSAGE_MISSING);

    if(! is_valid_encoded_msg_len(pt_len))
        return(FKO_ERROR_INVALID_DATA_ENCRYPT_DECRYPTED_MSGLEN_VALIDFAIL);

    ctx->encoded_msg_len = pt_len;

    /* Call fko_decode and return the results.
    */
    return(fko_decode_spa_data(ctx));
}

#endif /* HAVE_LIBGPGME */

/* Set the SPA encryption type.
*/
int
fko_set_spa_encryption_type(fko_ctx_t ctx, const short encrypt_type)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(encrypt_type < 0 || encrypt_type >= FKO_LAST_ENCRYPTION_TYPE)
        return(FKO_ERROR_INVALID_DATA_ENCRYPT_TYPE_VALIDFAIL);

    ctx->encryption_type = encrypt_type;

    ctx->state |= FKO_ENCRYPT_TYPE_MODIFIED;

    return(FKO_SUCCESS);
}

/* Return the SPA encryption type.
*/
int
fko_get_spa_encryption_type(fko_ctx_t ctx, short *enc_type)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *enc_type = ctx->encryption_type;

    return(FKO_SUCCESS);
}

/* Set the SPA encryption mode.
*/
int
fko_set_spa_encryption_mode(fko_ctx_t ctx, const int encrypt_mode)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(encrypt_mode < 0 || encrypt_mode >= FKO_LAST_ENC_MODE)
        return(FKO_ERROR_INVALID_DATA_ENCRYPT_MODE_VALIDFAIL);

    ctx->encryption_mode = encrypt_mode;

    ctx->state |= FKO_ENCRYPT_MODE_MODIFIED;

    return(FKO_SUCCESS);
}

/* Return the SPA encryption mode.
*/
int
fko_get_spa_encryption_mode(fko_ctx_t ctx, int *enc_mode)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(enc_mode == NULL)
        return(FKO_ERROR_INVALID_DATA);

    *enc_mode = ctx->encryption_mode;

    return(FKO_SUCCESS);
}

/* Encrypt the encoded SPA data.
*/
int
fko_encrypt_spa_data(fko_ctx_t ctx, const char * const enc_key,
        const int enc_key_len)
{
    int             res = 0;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(enc_key_len < 0)
        return(FKO_ERROR_INVALID_KEY_LEN);

    /* If there is no encoded data or the SPA data has been modified,
     * go ahead and re-encode here.
    */
    if(ctx->encoded_msg == NULL || FKO_IS_SPA_DATA_MODIFIED(ctx))
        res = fko_encode_spa_data(ctx);

    if(res != FKO_SUCCESS)
        return(res);

    /* Croak on invalid encoded message as well. At present this is a
     * check for a somewhat arbitrary minimum length for the encoded
     * data.
    */
    if (! is_valid_encoded_msg_len(ctx->encoded_msg_len))
        return(FKO_ERROR_MISSING_ENCODED_DATA);

    /* Encrypt according to type and return...
    */
    if(ctx->encryption_type == FKO_ENCRYPTION_RIJNDAEL)
    {
        if(enc_key == NULL)
            return(FKO_ERROR_INVALID_KEY_LEN);
        res = _rijndael_encrypt(ctx, enc_key, enc_key_len);
    }
    else if(ctx->encryption_type == FKO_ENCRYPTION_GPG)
#if HAVE_LIBGPGME
        res = gpg_encrypt(ctx, enc_key);
#else
        res = FKO_ERROR_UNSUPPORTED_FEATURE;
#endif
    else
        res = FKO_ERROR_INVALID_ENCRYPTION_TYPE;

    return(res);
}

/* Decode, decrypt, and parse SPA data into the context.
*/
int
fko_decrypt_spa_data(fko_ctx_t ctx, const char * const dec_key, const int key_len)
{
    int     enc_type, res;

    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(key_len < 0)
        return(FKO_ERROR_INVALID_KEY_LEN);

    /* Get the (assumed) type of encryption used. This will also provide
     * some data validation.
    */
    enc_type = fko_encryption_type(ctx->encrypted_msg);

    if(enc_type == FKO_ENCRYPTION_GPG
            && ctx->encryption_mode == FKO_ENC_MODE_ASYMMETRIC)
    {
        ctx->encryption_type = FKO_ENCRYPTION_GPG;
#if HAVE_LIBGPGME
        res = gpg_decrypt(ctx, dec_key);
#else
        res = FKO_ERROR_UNSUPPORTED_FEATURE;
#endif
    }
    else if(enc_type == FKO_ENCRYPTION_RIJNDAEL)
    {
        ctx->encryption_type = FKO_ENCRYPTION_RIJNDAEL;
        res = _rijndael_decrypt(ctx,
            dec_key, key_len, ctx->encryption_mode);
    }
    else
        return(FKO_ERROR_INVALID_DATA_ENCRYPT_TYPE_UNKNOWN);

    return(res);
}

/* Return the assumed encryption type based on the raw encrypted data.
*/
int
fko_encryption_type(const char * const enc_data)
{
    int enc_data_len;

    /* Sanity check the data.
    */
    if(enc_data == NULL)
        return(FKO_ENCRYPTION_INVALID_DATA);

    enc_data_len = strnlen(enc_data, MAX_SPA_ENCODED_MSG_SIZE);

    if(! is_valid_encoded_msg_len(enc_data_len))
        return(FKO_ENCRYPTION_UNKNOWN);

    if(enc_data_len >= MIN_GNUPG_MSG_SIZE)
        return(FKO_ENCRYPTION_GPG);

    else if(enc_data_len < MIN_GNUPG_MSG_SIZE
      && enc_data_len >= MIN_SPA_ENCODED_MSG_SIZE)
        return(FKO_ENCRYPTION_RIJNDAEL);

    else
        return(FKO_ENCRYPTION_UNKNOWN);
}

/* Set the GPG recipient key name.
*/
int
fko_set_gpg_recipient(fko_ctx_t ctx, const char * const recip)
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

    if(ctx->gpg_recipient != NULL)
        free(ctx->gpg_recipient);

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

/* Set the GPG home dir.
*/
int
fko_set_gpg_exe(fko_ctx_t ctx, const char * const gpg_exe)
{
#if HAVE_LIBGPGME
    struct stat     st;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    /* If we are unable to stat the given path/file and determine if it
     * is a regular file or symbolic link, then return with error.
    */
    if(stat(gpg_exe, &st) != 0)
        return(FKO_ERROR_GPGME_BAD_GPG_EXE);

    if(!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode))
        return(FKO_ERROR_GPGME_BAD_GPG_EXE);

    if(ctx->gpg_exe != NULL)
        free(ctx->gpg_exe);

    ctx->gpg_exe = strdup(gpg_exe);
    if(ctx->gpg_exe == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    return(FKO_SUCCESS);
#else
    return(FKO_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

/* Get the GPG home dir.
*/
int
fko_get_gpg_exe(fko_ctx_t ctx, char **gpg_exe)
{
#if HAVE_LIBGPGME
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *gpg_exe = ctx->gpg_exe;

    return(FKO_SUCCESS);
#else
    return(FKO_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

/* Get the GPG recipient key name.
*/
int
fko_get_gpg_recipient(fko_ctx_t ctx, char **recipient)
{
#if HAVE_LIBGPGME
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *recipient = ctx->gpg_recipient;

    return(FKO_SUCCESS);
#else
    return(FKO_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

/* Set the GPG signer key name.
*/
int
fko_set_gpg_signer(fko_ctx_t ctx, const char * const signer)
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

    if(ctx->gpg_signer != NULL)
        free(ctx->gpg_signer);

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
int
fko_get_gpg_signer(fko_ctx_t ctx, char **signer)
{
#if HAVE_LIBGPGME
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *signer = ctx->gpg_signer;

    return(FKO_SUCCESS);
#else
    return(FKO_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

/* Set the GPG home dir.
*/
int
fko_set_gpg_home_dir(fko_ctx_t ctx, const char * const gpg_home_dir)
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

    if(ctx->gpg_home_dir != NULL)
        free(ctx->gpg_home_dir);

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
int
fko_get_gpg_home_dir(fko_ctx_t ctx, char **home_dir)
{
#if HAVE_LIBGPGME
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *home_dir = ctx->gpg_home_dir;

    return(FKO_SUCCESS);
#else
    return(FKO_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

int
fko_set_gpg_signature_verify(fko_ctx_t ctx, const unsigned char val)
{
#if HAVE_LIBGPGME
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    ctx->verify_gpg_sigs = (val != 0) ? 1 : 0;

    return(FKO_SUCCESS);
#else
    return(FKO_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

int
fko_get_gpg_signature_verify(fko_ctx_t ctx, unsigned char * const val)
{
#if HAVE_LIBGPGME
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *val = ctx->verify_gpg_sigs;

    return(FKO_SUCCESS);
#else
    return(FKO_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

int
fko_set_gpg_ignore_verify_error(fko_ctx_t ctx, const unsigned char val)
{
#if HAVE_LIBGPGME
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    ctx->ignore_gpg_sig_error = (val != 0) ? 1 : 0;

    return(FKO_SUCCESS);
#else
    return(FKO_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

int
fko_get_gpg_ignore_verify_error(fko_ctx_t ctx, unsigned char * const val)
{
#if HAVE_LIBGPGME
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *val = ctx->ignore_gpg_sig_error;

    return(FKO_SUCCESS);
#else
    return(FKO_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}


int
fko_get_gpg_signature_fpr(fko_ctx_t ctx, char **fpr)
{
#if HAVE_LIBGPGME
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    /* Must be using GPG encryption.
    */
    if(ctx->encryption_type != FKO_ENCRYPTION_GPG)
        return(FKO_ERROR_WRONG_ENCRYPTION_TYPE);

    /* Make sure we are supposed to verify signatures.
    */
    if(ctx->verify_gpg_sigs == 0)
        return(FKO_ERROR_GPGME_SIGNATURE_VERIFY_DISABLED);

    /* Make sure we have a signature to work with.
    */
    if(ctx->gpg_sigs == NULL)
        return(FKO_ERROR_GPGME_NO_SIGNATURE);

    *fpr = ctx->gpg_sigs->fpr;

    return(FKO_SUCCESS);
#else
    return(FKO_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

int
fko_get_gpg_signature_id(fko_ctx_t ctx, char **id)
{
#if HAVE_LIBGPGME
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    /* Must be using GPG encryption.
    */
    if(ctx->encryption_type != FKO_ENCRYPTION_GPG)
        return(FKO_ERROR_WRONG_ENCRYPTION_TYPE);

    /* Make sure we are supposed to verify signatures.
    */
    if(ctx->verify_gpg_sigs == 0)
        return(FKO_ERROR_GPGME_SIGNATURE_VERIFY_DISABLED);

    /* Make sure we have a signature to work with.
    */
    if(ctx->gpg_sigs == NULL)
        return(FKO_ERROR_GPGME_NO_SIGNATURE);

    *id = ctx->gpg_sigs->fpr + strlen(ctx->gpg_sigs->fpr) - 8;

    return(FKO_SUCCESS);
#else
    return(FKO_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

int
fko_get_gpg_signature_summary(fko_ctx_t ctx, int *sigsum)
{
#if HAVE_LIBGPGME
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    /* Must be using GPG encryption.
    */
    if(ctx->encryption_type != FKO_ENCRYPTION_GPG)
        return(FKO_ERROR_WRONG_ENCRYPTION_TYPE);

    /* Make sure we are supposed to verify signatures.
    */
    if(ctx->verify_gpg_sigs == 0)
        return(FKO_ERROR_GPGME_SIGNATURE_VERIFY_DISABLED);

    /* Make sure we have a signature to work with.
    */
    if(ctx->gpg_sigs == NULL)
        return(FKO_ERROR_GPGME_NO_SIGNATURE);

    *sigsum = ctx->gpg_sigs->summary;

    return(FKO_SUCCESS);
#else
    return(FKO_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

int
fko_get_gpg_signature_status(fko_ctx_t ctx, int *sigstat)
{
#if HAVE_LIBGPGME
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    /* Must be using GPG encryption.
    */
    if(ctx->encryption_type != FKO_ENCRYPTION_GPG)
        return(FKO_ERROR_WRONG_ENCRYPTION_TYPE);

    /* Make sure we are supposed to verify signatures.
    */
    if(ctx->verify_gpg_sigs == 0)
        return(FKO_ERROR_GPGME_SIGNATURE_VERIFY_DISABLED);

    /* Make sure we have a signature to work with.
    */
    if(ctx->gpg_sigs == NULL)
        return(FKO_ERROR_GPGME_NO_SIGNATURE);

    *sigstat = ctx->gpg_sigs->status;

    return(FKO_SUCCESS);
#else
    return(FKO_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

int
fko_gpg_signature_id_match(fko_ctx_t ctx, const char * const id,
        unsigned char * const result)
{
#if HAVE_LIBGPGME
    char *curr_id;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    /* Must be using GPG encryption.
    */
    if(ctx->encryption_type != FKO_ENCRYPTION_GPG)
        return(FKO_ERROR_WRONG_ENCRYPTION_TYPE);

    /* Make sure we are supposed to verify signatures.
    */
    if(ctx->verify_gpg_sigs == 0)
        return(FKO_ERROR_GPGME_SIGNATURE_VERIFY_DISABLED);

    /* Make sure we have a signature to work with.
    */
    if(ctx->gpg_sigs == NULL)
        return(FKO_ERROR_GPGME_NO_SIGNATURE);

    fko_get_gpg_signature_id(ctx, &curr_id);

    *result = strcmp(id, curr_id) == 0 ? 1 : 0;

    return(FKO_SUCCESS);
#else
    return(FKO_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

int
fko_gpg_signature_fpr_match(fko_ctx_t ctx, const char * const id,
        unsigned char * const result)
{
#if HAVE_LIBGPGME
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    /* Must be using GPG encryption.
    */
    if(ctx->encryption_type != FKO_ENCRYPTION_GPG)
        return(FKO_ERROR_WRONG_ENCRYPTION_TYPE);

    /* Make sure we are supposed to verify signatures.
    */
    if(ctx->verify_gpg_sigs == 0)
        return(FKO_ERROR_GPGME_SIGNATURE_VERIFY_DISABLED);

    /* Make sure we have a signature to work with.
    */
    if(ctx->gpg_sigs == NULL)
        return(FKO_ERROR_GPGME_NO_SIGNATURE);

    *result = strcmp(id, ctx->gpg_sigs->fpr) == 0 ? 1 : 0;

    return(FKO_SUCCESS);
#else
    return(FKO_ERROR_UNSUPPORTED_FEATURE);
#endif  /* HAVE_LIBGPGME */
}

/***EOF***/
