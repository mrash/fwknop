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
#include "fko_util.h"
#include <errno.h>
#include <stdarg.h>

/* Check for a FKO error returned by a function an return the error code */
#define RETURN_ON_FKO_ERROR(e, f)   do { if (((e)=(f)) != FKO_SUCCESS) { return (e); } } while(0);

#define FKO_ENCRYPTION_MODE_BUFSIZE 16                      /*!< Maximum size of an encryption mode string */
#define FKO_ENC_MODE_SUPPORTED      0                       /*!< Defined a supported fko encryption mode */
#define FKO_ENC_MODE_NOT_SUPPORTED  !FKO_ENC_MODE_SUPPORTED /*!< Defined an unsupported fko encryption mode */

#define NULL_STRING                 "<NULL>"                /*!< String which represents a NULL buffer */

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
    { "legacy",         FKO_ENC_MODE_CBC_LEGACY_IV, FKO_ENC_MODE_SUPPORTED      }
};

/* Compare all bytes with constant run time regardless of
 * input characteristics (i.e. don't return early if a difference
 * is found before comparing all bytes).  This code was adapted
 * from YaSSL which is GPLv2 after a timing bug was reported by
 * Ryman through github (#85)
*/
int
constant_runtime_cmp(const char *a, const char *b, int len)
{
    int good = 0;
    int bad  = 0;
    int i;

    for(i=0; i < len; i++) {
        if (a[i] == b[i])
            good++;
        else
            bad++;
    }

    if (good == len)
        return 0;
    else
        return 0 - bad;
}

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
        *err = FKO_ERROR_INVALID_DATA_UTIL_STRTOL_LT_MIN;
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
        *err = FKO_ERROR_INVALID_DATA_UTIL_STROL_GT_MAX;
        if(exit_upon_err == EXIT_UPON_ERR)
        {
            fprintf(stderr, "[*] Value %d out of range %d - %d\n",
                val, min, max);
            exit(EXIT_FAILURE);
        }
    }

    return val;
}

/* zero out a buffer before free()
*/
int zero_free(char *buf, int len)
{
    int res = FKO_SUCCESS;

    if(buf == NULL)
        return res;

    if(len == 0)
    {
        free(buf);  /* always free() if buf != NULL */
        return res;
    }

    res = zero_buf(buf, len);

    free(buf);

    return res;
}

/* zero out sensitive information in a way that isn't optimized out by the compiler
 * since we force a comparision and return an error if there is a problem (though
 * the caller should do something with this information too).
*/
int
zero_buf(char *buf, int len)
{
    int i, res = FKO_SUCCESS;

    if(buf == NULL || len == 0)
        return res;

    if(len < 0 || len > MAX_SPA_ENCODED_MSG_SIZE)
        return FKO_ERROR_ZERO_OUT_DATA;

    for(i=0; i < len; i++)
        buf[i] = 0x0;

    for(i=0; i < len; i++)
        if(buf[i] != 0x0)
            res = FKO_ERROR_ZERO_OUT_DATA;

    return res;
}

#if defined(WIN32) || !defined(HAVE_STRNDUP)
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

/**
 * @brief Add a printf style message to a buffer
 *
 * This function allows to append a printf style message to a buffer
 * and prevents buffer overflow by taking care of the size the buffer.
 * It returns the number of bytes really written to the buffer.
 * Thus if an error is encoutered during the process the number of bytes
 * written is set to 0. This way the user knows exactly how many bytes
 * can be appended afterwards.
 *
 * @param buf       Buffer to write the formated message to
 * @param buf_size  Maximum number of bytes to write to the buffer
 * @param msg       Message to format and to append to the buffer
 *
 * @return the number of bytes written to the buffer
 */
static int
append_msg_to_buf(char *buf, size_t buf_size, const char* msg, ...)
{
    int     bytes_written = 0;  /* Number of bytes written to buf */
    va_list ap;

    /* Check if the buffer is valid */
    if (buf_size > 0)
    {
        va_start(ap, msg);

        /* Format the message like a printf message */
        bytes_written = vsnprintf(buf, buf_size, msg, ap);

        /* It looks like the message has been truncated or an error occured*/
        if (bytes_written < 0)
            bytes_written = 0;

        else if (bytes_written >= buf_size)
            bytes_written = buf_size;

        /* The messsage has been formatted correctly */
        else;

        va_end(ap);
    }

    /* No valid buffer has been supplied, thus we do not write anything */
    else;

    /* Return the number of bytes written to the buffer */
    return bytes_written;
}

/**
 * @brief Dump a FKO context to a buffer
 *
 * This function parses a FKO context and decodes each field to dump them to a
 * buffer in a comprehensible way.
 *
 * @param ctx           FKO context to dump
 * @param dump_buf      Buffer where to store the dump of the context
 * @param dump_buf_len  Number of bytes available in the dump_buf array
 *
 * @return a FKO error code. FKO_SUCCESS if successful.
 */
int
dump_ctx_to_buffer(fko_ctx_t ctx, char *dump_buf, size_t dump_buf_len)
{
    int         cp = 0;
    int         err = FKO_LAST_ERROR;

    char       *rand_val        = NULL;
    char       *username        = NULL;
    char       *version         = NULL;
    char       *spa_message     = NULL;
    char       *nat_access      = NULL;
    char       *server_auth     = NULL;
    char       *enc_data        = NULL;
    char       *hmac_data       = NULL;
    char       *spa_digest      = NULL;
    char       *spa_data        = NULL;
    char        digest_str[24]   = {0};
    char        hmac_str[24]     = {0};
    char        enc_mode_str[FKO_ENCRYPTION_MODE_BUFSIZE] = {0};

    time_t      timestamp       = 0;
    short       msg_type        = -1;
    short       digest_type     = -1;
    short       hmac_type       = -1;
    short       encryption_type = -1;
    int         encryption_mode = -1;
    int         client_timeout  = -1;

    /* Zero-ed the buffer */
    memset(dump_buf, 0, dump_buf_len);

    /* Make sure the FKO context is initialized before printing it */
    if(!CTX_INITIALIZED(ctx))
        err = FKO_ERROR_CTX_NOT_INITIALIZED;

    else
    {
        /* Parse the FKO context and collect data */
        RETURN_ON_FKO_ERROR(err, fko_get_rand_value(ctx, &rand_val));
        RETURN_ON_FKO_ERROR(err, fko_get_username(ctx, &username));
        RETURN_ON_FKO_ERROR(err, fko_get_timestamp(ctx, &timestamp));
        RETURN_ON_FKO_ERROR(err, fko_get_version(ctx, &version));
        RETURN_ON_FKO_ERROR(err, fko_get_spa_message_type(ctx, &msg_type));
        RETURN_ON_FKO_ERROR(err, fko_get_spa_message(ctx, &spa_message));
        RETURN_ON_FKO_ERROR(err, fko_get_spa_nat_access(ctx, &nat_access));
        RETURN_ON_FKO_ERROR(err, fko_get_spa_server_auth(ctx, &server_auth));
        RETURN_ON_FKO_ERROR(err, fko_get_spa_client_timeout(ctx, &client_timeout));
        RETURN_ON_FKO_ERROR(err, fko_get_spa_digest_type(ctx, &digest_type));
        RETURN_ON_FKO_ERROR(err, fko_get_spa_hmac_type(ctx, &hmac_type));
        RETURN_ON_FKO_ERROR(err, fko_get_spa_encryption_type(ctx, &encryption_type));
        RETURN_ON_FKO_ERROR(err, fko_get_spa_encryption_mode(ctx, &encryption_mode));
        RETURN_ON_FKO_ERROR(err, fko_get_encoded_data(ctx, &enc_data));
        RETURN_ON_FKO_ERROR(err, fko_get_spa_hmac(ctx, &hmac_data));
        RETURN_ON_FKO_ERROR(err, fko_get_spa_digest(ctx, &spa_digest));
        RETURN_ON_FKO_ERROR(err, fko_get_spa_data(ctx, &spa_data));

        /* Convert the digest integer to a string */
        if (digest_inttostr(digest_type, digest_str, sizeof(digest_str)) != 0)
            return (FKO_ERROR_INVALID_DIGEST_TYPE);

        /* Convert the encryption mode integer to a string */
        if (enc_mode_inttostr(encryption_mode, enc_mode_str, sizeof(enc_mode_str)) != 0)
            return (FKO_ERROR_INVALID_ENCRYPTION_TYPE);

        /* Convert the HMAC digest integer to a string if a HMAC message is available */
        if (ctx->msg_hmac_len != 0)
        {
            if (hmac_digest_inttostr(hmac_type, hmac_str, sizeof(hmac_str)) != 0)
                return (FKO_ERROR_UNSUPPORTED_HMAC_MODE);
        }

        /* Fill in the buffer to dump */
        cp  = append_msg_to_buf(dump_buf,    dump_buf_len,    "SPA Field Values:\n=================\n");
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "   Random Value: %s\n", rand_val == NULL ? NULL_STRING : rand_val);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "       Username: %s\n", username == NULL ? NULL_STRING : username);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "      Timestamp: %u\n", (unsigned int) timestamp);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "    FKO Version: %s\n", version == NULL ? NULL_STRING : version);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "   Message Type: %i (%s)\n", msg_type, msg_type_inttostr(msg_type));
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, " Message String: %s\n", spa_message == NULL ? NULL_STRING : spa_message);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "     Nat Access: %s\n", nat_access == NULL ? NULL_STRING : nat_access);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "    Server Auth: %s\n", server_auth == NULL ? NULL_STRING : server_auth);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, " Client Timeout: %u\n", client_timeout);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "    Digest Type: %u (%s)\n", digest_type, digest_str);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "      HMAC Type: %u (%s)\n", hmac_type, hmac_str);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "Encryption Type: %d (%s)\n", encryption_type, enc_type_inttostr(encryption_type));
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "Encryption Mode: %d (%s)\n", encryption_mode, enc_mode_str);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "   Encoded Data: %s\n", enc_data == NULL ? NULL_STRING : enc_data);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "SPA Data Digest: %s\n", spa_digest == NULL ? NULL_STRING : spa_digest);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "           HMAC: %s\n", hmac_data == NULL ? NULL_STRING : hmac_data);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, " Final SPA Data: %s\n", spa_data);

        err = FKO_SUCCESS;
    }

    return (err);
}

/***EOF***/
