/*
 *****************************************************************************
 *
 * File:    fko_util.c
 *
 * Author:  Michael Rash
 *
 * Purpose: Provide a set of common utility functions that fwknop can use.
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
#include "fko_util.h"
#include <errno.h>

/* Validate encoded message length
*/
int
is_valid_encoded_msg_len(const int len)
{
    if(len < MIN_SPA_ENCODED_MSG_SIZE || len >= MAX_SPA_ENCODED_MSG_SIZE)
        return(0);

    return(1);
}

/* Convert a digest_type string to its integer value.
*/
short
digest_strtoint(const char *dt_str)
{
    if(strcasecmp(dt_str, "md5") == 0)
        return(FKO_DIGEST_MD5);
    else if(strcasecmp(dt_str, "sha1") == 0)
        return(FKO_DIGEST_SHA1);
    else if(strcasecmp(dt_str, "sha256") == 0)
        return(FKO_DIGEST_SHA256);
    else if(strcasecmp(dt_str, "sha384") == 0)
        return(FKO_DIGEST_SHA384);
    else if(strcasecmp(dt_str, "sha512") == 0)
        return(FKO_DIGEST_SHA512);
    else
        return(-1);
}

/**
 * \brief Return a digest string according to a digest integer value
 *
 * This function checks the digest integer is valid, and write the digest
 * string associated.
 *
 * \param digest Digest inetger value (FKO_DIGEST_MD5, FKO_DIGEST_SHA1 ...)
 * \param digest_str Buffer to write the digest string
 * \param digest_size size of the digest string buffer
 *
 * \return -1 if the digest integer value is not supported, 0 otherwise
 */
short
digest_inttostr(int digest, char* digest_str, size_t digest_size)
{
    short digest_not_valid = 0;

    memset(digest_str, 0, digest_size);

    switch (digest)
    {
        case FKO_DIGEST_MD5:
            strlcpy(digest_str, "MD5", digest_size);
            break;
        case FKO_DIGEST_SHA1:
            strlcpy(digest_str, "SHA1", digest_size);
            break;
        case FKO_DIGEST_SHA256:
            strlcpy(digest_str, "SHA256", digest_size);
            break;
        case FKO_DIGEST_SHA384:
            strlcpy(digest_str, "SHA384", digest_size);
            break;
        case FKO_DIGEST_SHA512:
            strlcpy(digest_str, "SHA512", digest_size);
            break;
        default:
            digest_not_valid = -1;
            break;
    }

    return digest_not_valid;
}
short
hmac_digest_strtoint(const char *dt_str)
{
    if(strcasecmp(dt_str, "md5") == 0)
        return(FKO_HMAC_MD5);
    else if(strcasecmp(dt_str, "sha1") == 0)
        return(FKO_HMAC_SHA1);
    else if(strcasecmp(dt_str, "sha256") == 0)
        return(FKO_HMAC_SHA256);
    else if(strcasecmp(dt_str, "sha384") == 0)
        return(FKO_HMAC_SHA384);
    else if(strcasecmp(dt_str, "sha512") == 0)
        return(FKO_HMAC_SHA512);
    else
        return(-1);
}

/* Validate plaintext input size
*/
int
is_valid_pt_msg_len(const int len)
{
    if(len < MIN_SPA_PLAINTEXT_MSG_SIZE || len >= MAX_SPA_PLAINTEXT_MSG_SIZE)
        return(0);

    return(1);
}

/* Convert an encryption_mode string to its integer value.
*/
int
enc_mode_strtoint(const char *enc_mode_str)
{
    if(strcasecmp(enc_mode_str, "cbc") == 0)
        return(FKO_ENC_MODE_CBC);
    else if(strcasecmp(enc_mode_str, "ecb") == 0)
        return(FKO_ENC_MODE_ECB);
    else if(strcasecmp(enc_mode_str, "cfb") == 0)
        return(FKO_ENC_MODE_CFB);
    else if(strcasecmp(enc_mode_str, "pcbc") == 0)
        return(-1);  /* not supported yet */
    else if(strcasecmp(enc_mode_str, "ofb") == 0)
        return(FKO_ENC_MODE_OFB);
    else if(strcasecmp(enc_mode_str, "ctr") == 0)
        return(FKO_ENC_MODE_CTR);
    else if(strcasecmp(enc_mode_str, "legacy") == 0)
        return(FKO_ENC_MODE_CBC_LEGACY_IV);
    else
        return(-1);
}

/**
 * \brief Return an encryption mode string according to an enc_mode integer value
 *
 * This function checks if the encryption mode integer is valid, and write the
 * encryption mode string associated.
 *
 * \param enc_mode Encryption mode inetger value (FKO_ENC_MODE_CBC, FKO_ENC_MODE_ECB ...)
 * \param enc_mode_str Buffer to write the encryption mode string
 * \param enc_mode_size size of the encryption mode string buffer
 *
 * \return -1 if the encryption mode integer value is not supported, 0 otherwise
 */
short
enc_mode_inttostr(int enc_mode, char* enc_mode_str, size_t enc_mode_size)
{
    short enc_mode_not_valid = 0;

    memset(enc_mode_str, 0, enc_mode_size);

    switch (enc_mode)
    {
        case FKO_ENC_MODE_CBC :
            strlcpy(enc_mode_str, "CBC", enc_mode_size);
            break;
        case FKO_ENC_MODE_ECB :
            strlcpy(enc_mode_str, "ECB", enc_mode_size);
            break;
        case FKO_ENC_MODE_CFB :
            strlcpy(enc_mode_str, "CFB", enc_mode_size);
            break;
        case FKO_ENC_MODE_PCBC :
            //strlcpy(enc_mode_str, "PCBC", enc_mode_size);
            enc_mode_not_valid = -1;
            break;
        case FKO_ENC_MODE_OFB :
            strlcpy(enc_mode_str, "OFB", enc_mode_size);
            break;
        case FKO_ENC_MODE_CTR :
            strlcpy(enc_mode_str, "CTR", enc_mode_size);
            break;
        case FKO_ENC_MODE_CBC_LEGACY_IV:
            strlcpy(enc_mode_str, "LEGACY", enc_mode_size);
            break;
        default:
            enc_mode_not_valid = -1;
            break;
    }

    return enc_mode_not_valid;
}

int
strtol_wrapper(const char * const str, const int min,
    const int max, const int exit_upon_err, int *err)
{
    int val;

    errno = 0;
    *err = FKO_SUCCESS;

    val = strtol(str, (char **) NULL, 10);

    if ((errno == ERANGE || (errno != 0 && val == 0)))
    {
        *err = errno;
        if(exit_upon_err == EXIT_UPON_ERR)
        {
            perror("strtol");
            fprintf(stderr, "[*] Value %d out of range %d - %d\n",
                val, min, max);
            exit(EXIT_FAILURE);
        }
    }

    if(val < min)
    {
        *err = FKO_ERROR_INVALID_DATA;
        if(exit_upon_err == EXIT_UPON_ERR)
        {
            fprintf(stderr, "[*] Value %d out of range %d - %d\n",
                val, min, max);
            exit(EXIT_FAILURE);
        }
    }

    /* allow max == -1 to be an exception where we don't care about the
     * maximum - note that the ERANGE check is still in place above
    */
    if((max >= 0) && (val > max))
    {
        *err = FKO_ERROR_INVALID_DATA;
        if(exit_upon_err == EXIT_UPON_ERR)
        {
            fprintf(stderr, "[*] Value %d out of range %d - %d\n",
                val, min, max);
            exit(EXIT_FAILURE);
        }
    }

    return val;
}

/***EOF***/
