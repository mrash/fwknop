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

#define FKO_ENCRYPTION_MODE_BUFSIZE 16                      /*!< Maximum size of an encryption mode string */
#define FKO_ENC_MODE_SUPPORTED      0                       /*!< Defined a supported fko encryption mode */
#define FKO_ENC_MODE_NOT_SUPPORTED  !FKO_ENC_MODE_SUPPORTED /*!< Defined an unsupported fko encryption mode */

/**
 * Structure to handle an encryption mode string string and its associated integer value
 */
typedef struct fko_enc_mode_str
{
    const char  str[FKO_ENCRYPTION_MODE_BUFSIZE];   /*!< String which represents an encryption mode value for the FKO library */
    int         val;                                /*!< Value of the encryption mode according to the FKO library */
    int         supported;                          /*!< SUPPORTED or NOT_SUPPORTED */
} fko_enc_mode_str_t;

/**
 * Array to associate all of encryption modes with their respective string
 */
static fko_enc_mode_str_t fko_enc_mode_strs[] =
{
    { "CBC",            FKO_ENC_MODE_CBC,           FKO_ENC_MODE_SUPPORTED      },
    { "ECB",            FKO_ENC_MODE_ECB,           FKO_ENC_MODE_SUPPORTED      },
    { "CFB",            FKO_ENC_MODE_CFB,           FKO_ENC_MODE_SUPPORTED      },
    { "PCBC",           FKO_ENC_MODE_PCBC,          FKO_ENC_MODE_NOT_SUPPORTED  },
    { "OFB",            FKO_ENC_MODE_OFB,           FKO_ENC_MODE_SUPPORTED      },
    { "CTR",            FKO_ENC_MODE_CTR,           FKO_ENC_MODE_SUPPORTED      },
    { "Asymmetric",     FKO_ENC_MODE_ASYMMETRIC,    FKO_ENC_MODE_SUPPORTED      },
    { "CBC legacy IV",  FKO_ENC_MODE_CBC_LEGACY_IV, FKO_ENC_MODE_SUPPORTED      }
};

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
            strlcpy(digest_str, "Unknown", digest_size);
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

/* Return encryption type string representation
*/
const char *
enc_type_inttostr(const int type)
{
    if(type == FKO_ENC_MODE_UNKNOWN)
        return("Unknown encryption type");
    else if(type == FKO_ENCRYPTION_RIJNDAEL)
        return("Rijndael");
    else if(type == FKO_ENCRYPTION_GPG)
        return("GPG");

    return("Unknown encryption type");
}

/* Return message type string representation
*/
const char *
msg_type_inttostr(const int type)
{
    if(type == FKO_COMMAND_MSG)
        return("Command msg");
    else if(type == FKO_ACCESS_MSG)
        return("Access msg");
    else if(type == FKO_NAT_ACCESS_MSG)
        return("NAT access msg");
    else if(type == FKO_CLIENT_TIMEOUT_ACCESS_MSG)
        return("Client timeout access msg");
    else if(type == FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG)
        return("Client timeout NAT access msg");
    else if(type == FKO_LOCAL_NAT_ACCESS_MSG)
        return("Local NAT access msg");
    else if(type == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
        return("Client timeout local NAT access msg");

    return("Unknown message type");
}

/**
 * \brief Return a hmac digest string according to a hmac digest integer value
 *
 * This function checks if the digest integer is valid, and write the digest
 * string associated.
 *
 * \param digest Digest inetger value (FKO_HMAC_MD5, FKO_HMAC_SHA1 ...)
 * \param digest_str Buffer to write the digest string
 * \param digest_size size of the digest string buffer
 *
 * \return -1 if the digest integer value is not supported, 0 otherwise
 */
short
hmac_digest_inttostr(int digest, char* digest_str, size_t digest_size)
{
    short digest_not_valid = 0;

    memset(digest_str, 0, digest_size);

    switch (digest)
    {
        case FKO_HMAC_MD5:
            strlcpy(digest_str, "MD5", digest_size);
            break;
        case FKO_HMAC_SHA1:
            strlcpy(digest_str, "SHA1", digest_size);
            break;
        case FKO_HMAC_SHA256:
            strlcpy(digest_str, "SHA256", digest_size);
            break;
        case FKO_HMAC_SHA384:
            strlcpy(digest_str, "SHA384", digest_size);
            break;
        case FKO_HMAC_SHA512:
            strlcpy(digest_str, "SHA512", digest_size);
            break;
        default:
            strlcpy(digest_str, "Unknown", digest_size);
            digest_not_valid = -1;
            break;
    }

    return digest_not_valid;
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

/**
 * @brief Convert an encryption mode string to its integer value.
 *
 * @param enc_mode_str Encryption mode string (CBC,ECB...)
 *
 * @return -1 if the encryption mode string is not supported,
 *         otherwise the encryption mode value
 */
int
enc_mode_strtoint(const char *enc_mode_str)
{
    unsigned char           ndx_enc_mode;
    int                     enc_mode_int = -1;     /* Encryption mode integer value */
    fko_enc_mode_str_t     *enc_mode_str_pt;

    /* Look into the fko_enc_mode_strs array to find out the right encryption mode */
    for (ndx_enc_mode = 0 ; ndx_enc_mode < ARRAY_SIZE(fko_enc_mode_strs) ; ndx_enc_mode++)
    {
        enc_mode_str_pt = &(fko_enc_mode_strs[ndx_enc_mode]);

        /* If the encryption mode matches, grab it */
        if (   (strcasecmp(enc_mode_str, enc_mode_str_pt->str) == 0)
            && (enc_mode_str_pt->supported == FKO_ENC_MODE_SUPPORTED) )
        {
            enc_mode_int = enc_mode_str_pt->val;
            break;
        }
    }

    return enc_mode_int;
}

/**
 * @brief Return an encryption mode string according to an enc_mode integer value
 *
 * This function checks if the encryption mode integer is valid, and write the
 * encryption mode string associated.
 *
 * @param enc_mode Encryption mode integer value (FKO_ENC_MODE_CBC, FKO_ENC_MODE_ECB ...)
 * @param enc_mode_str Buffer to write the encryption mode string to
 * @param enc_mode_size Size of the encryption mode string buffer
 *
 * @return -1 if the encryption mode integer value is not supported, 0 otherwise
 */
short
enc_mode_inttostr(int enc_mode, char* enc_mode_str, size_t enc_mode_size)
{
    short                   enc_mode_error = -1;
    unsigned char           ndx_enc_mode;
    fko_enc_mode_str_t     *enc_mode_str_pt;

    /* Initialize the protocol string */
    memset(enc_mode_str, 0, enc_mode_size);

    /* Look into the fko_enc_mode_strs array to find out the right protocol */
    for (ndx_enc_mode = 0 ; ndx_enc_mode < ARRAY_SIZE(fko_enc_mode_strs) ; ndx_enc_mode++)
    {
        enc_mode_str_pt = &(fko_enc_mode_strs[ndx_enc_mode]);

        /* If the encryption mode matches, grab it */
        if (   (enc_mode_str_pt->val == enc_mode)
            && (enc_mode_str_pt->supported == FKO_ENC_MODE_SUPPORTED) )
        {
            strlcpy(enc_mode_str, enc_mode_str_pt->str, enc_mode_size);
            enc_mode_error = 0;
            break;
        }
    }

    return enc_mode_error;
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


#ifdef WIN32
/* Windows does not have strndup, so we well implement it here.
 * This was the Public Domain C Library (PDCLib).
*/
char 
*strndup( const char * s, size_t len )
{
    char* ns = NULL;
    if(s) {
        ns = malloc(len + 1);
        if(ns) {
            ns[len] = 0;
            // strncpy to be pedantic about modification in multithreaded 
            // applications
            return strncpy(ns, s, len);
        }
    }
    return ns;
}
#endif

/***EOF***/
