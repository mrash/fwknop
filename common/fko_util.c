/**
 * \file common/fko_util.c
 *
 * \brief Provide a set of common utility functions that fwknop can use.
 */

/*  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
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
#include "fko_util.h"
#include <errno.h>
#include <stdarg.h>

#ifndef WIN32
  /* for inet_aton() IP validation
  */
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
#endif

/* Check for a FKO error returned by a function an return the error code */
#define RETURN_ON_FKO_ERROR(e, f)   do { if (((e)=(f)) != FKO_SUCCESS) { return (e); } } while(0);

#define FKO_ENCRYPTION_MODE_BUFSIZE 16                      /*!< Maximum size of an encryption mode string */
#define FKO_ENC_MODE_SUPPORTED      0                       /*!< Defined a supported fko encryption mode */
#define FKO_ENC_MODE_NOT_SUPPORTED  !FKO_ENC_MODE_SUPPORTED /*!< Defined an unsupported fko encryption mode */

#define NULL_STRING                 "<NULL>"                /*!< String which represents a NULL buffer */

#ifdef HAVE_C_UNIT_TESTS /* LCOV_EXCL_START */
#include "cunit_common.h"
DECLARE_TEST_SUITE(utils_test, "Utility functions test suite");
#endif /* LCOV_EXCL_STOP */

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
#if HAVE_LIBFIU
    fiu_return_on("is_valid_encoded_msg_len_val", 0);
#endif
    if(len < MIN_SPA_ENCODED_MSG_SIZE || len >= MAX_SPA_ENCODED_MSG_SIZE)
        return(0);

    return(1);
}

/* Validate an IPv4 address
*/
int
is_valid_ipv4_addr(const char * const ip_str, const int len)
{
    const char         *ndx     = ip_str;
    char         tmp_ip_str[MAX_IPV4_STR_LEN + 1]={0};
    int                 dot_ctr = 0, char_ctr = 0;
    int                 res     = 1;
#if HAVE_SYS_SOCKET_H
    struct in_addr      in;
#endif

    if(ip_str == NULL)
        return 0;

    if((len > MAX_IPV4_STR_LEN) || (len < MIN_IPV4_STR_LEN))
        return 0;


    while(char_ctr < len)
    {
        /* If we've hit a null within the given length, then not valid regardless*/
        if(*ndx == '\0')
            return 0;

        char_ctr++;

        if(*ndx == '.')
            dot_ctr++;
        else if(isdigit((int)(unsigned char)*ndx) == 0)
        {
            res = 0;
            break;
        }
        ndx++;
    }



    if((res == 1) && (dot_ctr != 3))
        res = 0;

#if HAVE_SYS_SOCKET_H
    /* Stronger IP validation now that we have a candidate that looks
     * close enough
    */
    if(res == 1) {
        strncpy(tmp_ip_str, ip_str, len);
        if (inet_aton(tmp_ip_str, &in) == 0)
            res = 0;
    }
#endif
    return(res);
}

/* Validate a hostname
*/
int
is_valid_hostname(const char * const hostname_str, const int len)
{
    int                 label_size = 0, total_size = 0;
    const char         *ndx     = hostname_str;

    if (hostname_str == NULL)
        return 0;

    if (len > 254)
        return 0;

    while(total_size < len)
    {
        if (*ndx == '\0')
            return 0;

        if (label_size == 0) //More restrictions on first character of a label
        {
            if (!isalnum((int)(unsigned char)*ndx))
                return 0;
        }
        else if (!(isalnum((int)(unsigned char)*ndx) | (*ndx == '.') | (*ndx == '-')))
            return 0;

        if (*ndx == '.')
        {
            if (label_size > 63)
                return 0;
            if (!isalnum((int)(unsigned char)*(ndx-1)))  //checks that previous character was not a . or -
                return 0;

            label_size = 0;
        }
        else
        {
            label_size++;
        }

        total_size++;

        ndx++; //move to next character
    }
    /* At this point, we're pointing at the null.  Decrement ndx for simplicity
    */
    ndx--;
    if (*ndx == '-')
        return 0;

    if (*ndx == '.')
        total_size--;

    if (label_size > 63)
        return 0;

    /* By now we've bailed if invalid
    */
    return 1;
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
    else if(strcasecmp(dt_str, "sha3_256") == 0)
        return(FKO_DIGEST_SHA3_256);
    else if(strcasecmp(dt_str, "sha3_512") == 0)
        return(FKO_DIGEST_SHA3_512);
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
        case FKO_DIGEST_SHA3_256:
            strlcpy(digest_str, "SHA3_256", digest_size);
            break;
        case FKO_DIGEST_SHA3_512:
            strlcpy(digest_str, "SHA3_512", digest_size);
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
    else if(strcasecmp(dt_str, "sha3_256") == 0)
        return(FKO_HMAC_SHA3_256);
    else if(strcasecmp(dt_str, "sha3_512") == 0)
        return(FKO_HMAC_SHA3_512);
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
        case FKO_HMAC_SHA3_256:
            strlcpy(digest_str, "SHA3_256", digest_size);
            break;
        case FKO_HMAC_SHA3_512:
            strlcpy(digest_str, "SHA3_512", digest_size);
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
#if HAVE_LIBFIU
    fiu_return_on("is_valid_pt_msg_len_val", 0);
#endif
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
            fprintf(stderr, "[*] Value %d out of range [(%d)-(%d)]\n",
                val, min, max);
            exit(EXIT_FAILURE);
        }
    }

    if(val < min)
    {
        *err = FKO_ERROR_INVALID_DATA_UTIL_STRTOL_LT_MIN;
        if(exit_upon_err == EXIT_UPON_ERR)
        {
            fprintf(stderr, "[*] Value %d out of range [(%d)-(%d)]\n",
                val, min, max);
            exit(EXIT_FAILURE);
        }
    }

    /* allow max == -1 to be an exception where we don't care about the
     * maximum - note that the ERANGE check is still in place above
    */
    if((max >= 0) && (val > max))
    {
        *err = FKO_ERROR_INVALID_DATA_UTIL_STRTOL_GT_MAX;
        if(exit_upon_err == EXIT_UPON_ERR)
        {
            fprintf(stderr, "[*] Value %d out of range [(%d)-(%d)]\n",
                val, min, max);
            exit(EXIT_FAILURE);
        }
    }

#if HAVE_LIBFIU
    fiu_return_on("strtol_wrapper_lt_min",
            FKO_ERROR_INVALID_DATA_UTIL_STRTOL_LT_MIN);
    fiu_return_on("strtol_wrapper_gt_max",
            FKO_ERROR_INVALID_DATA_UTIL_STRTOL_GT_MAX);
#endif

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

#if HAVE_LIBFIU
    fiu_return_on("zero_free_err", FKO_ERROR_ZERO_OUT_DATA);
#endif

    return res;
}

/* zero out sensitive information in a way that isn't optimized out by the compiler
 * since we force a comparison and return an error if there is a problem (though
 * the caller should do something with this information too).
*/
int
zero_buf(char *buf, int len)
{
    int i, res = FKO_SUCCESS;

#if HAVE_LIBFIU
    fiu_return_on("zero_buf_err", FKO_ERROR_ZERO_OUT_DATA);
#endif

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
        ns = calloc(1, len + 1);
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
 * @param buf       Buffer to write the formatted message to
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

        /* It looks like the message has been truncated or an error occurred*/
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

/* Determine if a buffer contains only characters from the base64
 * encoding set
*/
int
is_base64(const unsigned char * const buf, const unsigned short int len)
{
    unsigned short int  i;
    int                 rv = 1;

    for(i=0; i<len; i++)
    {
        if(!(isalnum(buf[i]) || buf[i] == '/' || buf[i] == '+' || buf[i] == '='))
        {
            rv = 0;
            break;
        }
    }

    return rv;
}

void
chop_char(char *str, const char chop)
{
    if(str != NULL
            && str[0] != 0x0
            && strlen(str) > 1 /* don't truncate a single-char string */
            && str[strlen(str)-1] == chop)
        str[strlen(str)-1] = 0x0;
    return;
}

void
chop_newline(char *str)
{
    chop_char(str, 0x0a);
    return;
}

void chop_spaces(char *str)
{
    int i;
    if (str != NULL && str[0] != 0x0)
    {
        for (i=strlen(str)-1; i > 0; i--)
        {
            if(str[i] != 0x20)
                break;
            str[i] = 0x0;
        }
    }
    return;
}

static int
add_argv(char **argv_new, int *argc_new, const char *new_arg)
{
    int buf_size = 0;

    buf_size = strlen(new_arg) + 1;
    argv_new[*argc_new] = calloc(1, buf_size);

    if(argv_new[*argc_new] == NULL)
        return 0;

    strlcpy(argv_new[*argc_new], new_arg, buf_size);

    *argc_new += 1;

    if(*argc_new >= MAX_CMDLINE_ARGS-1)
        return 0;

    argv_new[*argc_new] = NULL;

    return 1;
}

int
strtoargv(const char * const args_str, char **argv_new, int *argc_new)
{
    int       current_arg_ctr = 0, i;
    char      arg_tmp[MAX_ARGS_LINE_LEN] = {0};

    for (i=0; i < (int)strlen(args_str); i++)
    {
        if (!isspace((int)(unsigned char)args_str[i]))
        {
            arg_tmp[current_arg_ctr] = args_str[i];
            current_arg_ctr++;
        }
        else
        {
            if(current_arg_ctr > 0)
            {
                arg_tmp[current_arg_ctr] = '\0';
                if (add_argv(argv_new, argc_new, arg_tmp) != 1)
                {
                    free_argv(argv_new, argc_new);
                    return 0;
                }
                current_arg_ctr = 0;
            }
        }
    }

    /* pick up the last argument in the string
    */
    if(current_arg_ctr > 0)
    {
        arg_tmp[current_arg_ctr] = '\0';
        if (add_argv(argv_new, argc_new, arg_tmp) != 1)
        {
            free_argv(argv_new, argc_new);
            return 0;
        }
    }
    return 1;
}

void
free_argv(char **argv_new, int *argc_new)
{
    int i;

    if(argv_new == NULL || *argv_new == NULL)
        return;

    for (i=0; i < *argc_new; i++)
    {
        if(argv_new[i] == NULL)
            break;
        else
            free(argv_new[i]);
    }
    return;
}

#define ASCII_LEN 16

/* Generic hex dump function.
*/
void
hex_dump(const unsigned char *data, const int size)
{
    int ln=0, i=0, j=0;
    char ascii_str[ASCII_LEN+1] = {0};

    for(i=0; i<size; i++)
    {
        if((i % ASCII_LEN) == 0)
        {
            printf(" %s\n  0x%.4x:  ", ascii_str, i);
            memset(ascii_str, 0x0, ASCII_LEN-1);
            j = 0;
        }

        printf("%.2x ", data[i]);

        ascii_str[j++] = (data[i] < 0x20 || data[i] > 0x7e) ? '.' : data[i];

        if(j == 8)
            printf(" ");
    }

    /* Remainder...
    */
    ln = strlen(ascii_str);
    if(ln > 0)
    {
        for(i=0; i < ASCII_LEN-ln; i++)
            printf("   ");
        if(ln < 8)
            printf(" ");

        printf(" %s\n\n", ascii_str);
    }
    return;
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
#if HAVE_LIBGPGME
    char          *gpg_signer        = NULL;
    char          *gpg_recip         = NULL;
    char          *gpg_sig_id        = NULL;
    unsigned char  gpg_sig_verify    = 0;
    unsigned char  gpg_ignore_verify = 0;
    char          *gpg_sig_fpr       = NULL;
    char          *gpg_home_dir      = NULL;
    char          *gpg_exe           = NULL;
    int            gpg_sigsum        = -1;
    int            gpg_sig_stat      = -1;
#endif
    char       *spa_data         = NULL;
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

#if HAVE_LIBGPGME
        if(encryption_mode == FKO_ENC_MODE_ASYMMETRIC)
        {
            /* Populate GPG variables
            */
            RETURN_ON_FKO_ERROR(err, fko_get_gpg_signer(ctx, &gpg_signer));
            RETURN_ON_FKO_ERROR(err, fko_get_gpg_recipient(ctx, &gpg_recip));
            RETURN_ON_FKO_ERROR(err, fko_get_gpg_signature_verify(ctx, &gpg_sig_verify));
            RETURN_ON_FKO_ERROR(err, fko_get_gpg_ignore_verify_error(ctx, &gpg_ignore_verify));
            RETURN_ON_FKO_ERROR(err, fko_get_gpg_home_dir(ctx, &gpg_home_dir));
            RETURN_ON_FKO_ERROR(err, fko_get_gpg_exe(ctx, &gpg_exe));
            if(fko_get_gpg_signature_id(ctx, &gpg_sig_id) != FKO_SUCCESS)
                gpg_sig_id = NULL;
            if(fko_get_gpg_signature_summary(ctx, &gpg_sigsum) != FKO_SUCCESS)
                gpg_sigsum = -1;
            if(fko_get_gpg_signature_status(ctx, &gpg_sig_stat) != FKO_SUCCESS)
                gpg_sig_stat = -1;
            if(fko_get_gpg_signature_fpr(ctx, &gpg_sig_fpr) != FKO_SUCCESS)
                gpg_sig_fpr = NULL;
        }
#endif

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
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "      HMAC Type: %u (%s)\n", hmac_type, hmac_type == 0 ? "None" : hmac_str);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "Encryption Type: %d (%s)\n", encryption_type, enc_type_inttostr(encryption_type));
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "Encryption Mode: %d (%s)\n", encryption_mode, enc_mode_str);
#if HAVE_LIBGPGME
        if(encryption_mode == FKO_ENC_MODE_ASYMMETRIC)
        {
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "     GPG signer: %s\n", gpg_signer == NULL ? NULL_STRING : gpg_signer);
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "  GPG recipient: %s\n", gpg_recip == NULL ? NULL_STRING : gpg_recip);
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, " GPG sig verify: %s\n", gpg_sig_verify == 0 ? "No" : "Yes");
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, " GPG ignore sig: %s\n", gpg_ignore_verify == 0 ? "No" : "Yes");
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "     GPG sig ID: %s\n", gpg_sig_id == NULL ? NULL_STRING : gpg_sig_id);
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "    GPG sig fpr: %s\n", gpg_sig_fpr == NULL ? NULL_STRING : gpg_sig_fpr);
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "GPG sig summary: %d\n", gpg_sigsum);
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, " GPG sig status: %d\n", gpg_sig_stat);
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "   GPG home dir: %s\n", gpg_home_dir == NULL ? NULL_STRING : gpg_home_dir);
            cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "        GPG exe: %s\n", gpg_exe == NULL ? GPG_EXE : gpg_exe);
        }
#endif
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "   Encoded Data: %s\n", enc_data == NULL ? NULL_STRING : enc_data);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "SPA Data Digest: %s\n", spa_digest == NULL ? NULL_STRING : spa_digest);
        cp += append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, "           HMAC: %s\n", hmac_data == NULL ? NULL_STRING : hmac_data);
        append_msg_to_buf(dump_buf+cp, dump_buf_len-cp, " Final SPA Data: %s\n", spa_data);

        err = FKO_SUCCESS;
    }

    return (err);
}

/**
 * @brief Grab the sin address from the sockaddr structure.
 *
 * This function returns the sin address as a sockaddr_in or sockaddr_in6
 * structure according to the family set (ipv4 or ipv6) in the sockaddr
 * structure.
 *
 * @param sa sockaddr strcuture
 *
 * @return the sin addr if the sa family is AF_INET or the sin6_addr otherwise.
 */
static void *
get_in_addr(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET)
  {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }

  else
  {
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
  }
}

/**
 * @brief  Resolve a domain name as an IP address.
 *
 * @param dns_str    Name of the host to resolve.
 * @param hints      Hints to reduce the number of result from getaddrinfo()
 * @param ip_str     String where to store the resolve ip address
 * @param ip_bufsize Number of bytes available in the ip_str buffer
 * @param opts       Client command line options
 *
 * @return 0 if successful, 1 if an error occurred.
 */
int
ipv4_resolve(const char *dns_str, char *ip_str)
{
    int                 error;      /* Function error return code */
    size_t ip_bufsize = MAX_IPV4_STR_LEN;
    struct addrinfo     hints;
    struct addrinfo    *result;     /* Result of getaddrinfo() */
    struct addrinfo    *rp;         /* Element of the linked list returned by getaddrinfo() */

#if WIN32 && WINVER <= 0x0600
    struct sockaddr_in *in;
    char               *win_ip;
#else
    struct sockaddr_in *sai_remote; /* Remote host information as a sockaddr_in structure */
#endif

#if WIN32 
    WSADATA wsa_data;
	error = WSAStartup( MAKEWORD(1,1), &wsa_data );
    if( error != 0 )
    {
        fprintf(stderr, "Winsock initialization error %d", error);
        return(error);
    }
#endif

    memset(&hints, 0 , sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    /* Try to resolve the host name */
    error = getaddrinfo(dns_str, NULL, &hints, &result);
    if (error != 0)
        fprintf(stderr, "ipv4_resolve() : %s\n", gai_strerror(error));

    else
    {
        error = 1;

        /* Go through the linked list of addrinfo structures */
        for (rp = result; rp != NULL; rp = rp->ai_next)
        {
            memset(ip_str, 0, ip_bufsize);

#if WIN32 && WINVER <= 0x0600
                        /* On older Windows systems (anything before Vista?),
                         * we use inet_ntoa for now.
                        */
                        in = (struct sockaddr_in*)(rp->ai_addr);
                        win_ip = inet_ntoa(in->sin_addr);

                        if (win_ip != NULL && (strlcpy(ip_str, win_ip, ip_bufsize) > 0))
#else
            sai_remote = (struct sockaddr_in *)get_in_addr((struct sockaddr *)(rp->ai_addr));
            if (inet_ntop(rp->ai_family, sai_remote, ip_str, ip_bufsize) != NULL)
#endif
            {
                error = 0;
                break;
            }
        }

        /* Free our result from getaddrinfo() */
        freeaddrinfo(result);
    }

#if WIN32
	WSACleanup();
#endif
    return error;
}

int
count_characters(const char *str, const char match, int len)
{
    int i, count = 0;

    for (i=0; i < len && str[i] != '\0'; i++) {
        if (str[i] == match)
            count++;
    }
    return count;
}

#ifdef HAVE_C_UNIT_TESTS /* LCOV_EXCL_START */

DECLARE_UTEST(test_hostname_validator, "test the is_valid_hostname function")
{
    char test_hostname[300];
    strcpy(test_hostname, "a");
    CU_ASSERT(is_valid_hostname(test_hostname, strlen(test_hostname)) == 1);
    strcpy(test_hostname, "a.b");
    CU_ASSERT(is_valid_hostname(test_hostname, strlen(test_hostname)) == 1);
    strcpy(test_hostname, "a.b.");
    CU_ASSERT(is_valid_hostname(test_hostname, strlen(test_hostname)) == 1);
    strcpy(test_hostname, "a.");
    CU_ASSERT(is_valid_hostname(test_hostname, strlen(test_hostname)) == 1);

    strcpy(test_hostname, "a..b");
    CU_ASSERT(is_valid_hostname(test_hostname, strlen(test_hostname)) == 0);
    strcpy(test_hostname, ".a.b");
    CU_ASSERT(is_valid_hostname(test_hostname, strlen(test_hostname)) == 0);
    strcpy(test_hostname, "a-.b");
    CU_ASSERT(is_valid_hostname(test_hostname, strlen(test_hostname)) == 0);
    strcpy(test_hostname, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b");
    CU_ASSERT(is_valid_hostname(test_hostname, strlen(test_hostname)) == 0);
}
DECLARE_UTEST(test_ipv4_validator, "test the is_valid_ipv4_addr function")
{
    char test_str[32];
    strcpy(test_str, "1.2.3.4");
    CU_ASSERT(is_valid_ipv4_addr(test_str, strlen(test_str)));
    strcpy(test_str, "127.0.0.2");
    CU_ASSERT(is_valid_ipv4_addr(test_str, 9));
    strcpy(test_str, "1.2.3.400");
    CU_ASSERT(is_valid_ipv4_addr(test_str, strlen(test_str)) == 0);
}

DECLARE_UTEST(test_count_characters, "test the count_characters function")
{
    char test_str[32];
    strcpy(test_str, "abcd");
    CU_ASSERT(count_characters(test_str, 'a', 4) == 1);
    strcpy(test_str, "aacd");
    CU_ASSERT(count_characters(test_str, 'a', 4) == 2);
    strcpy(test_str, "a,b,c,d,");
    CU_ASSERT(count_characters(test_str, ',', 4) == 2);
    strcpy(test_str, "a,b,c,d,");
    CU_ASSERT(count_characters(test_str, ',', 8) == 4);
    strcpy(test_str, "aaaa");
    CU_ASSERT(count_characters(test_str, 'a', 3) == 3);
}

int register_utils_test(void)
{
    ts_init(&TEST_SUITE(utils_test), TEST_SUITE_DESCR(utils_test), NULL, NULL);
    ts_add_utest(&TEST_SUITE(utils_test), UTEST_FCT(test_count_characters), UTEST_DESCR(test_count_characters));
    ts_add_utest(&TEST_SUITE(utils_test), UTEST_FCT(test_ipv4_validator), UTEST_DESCR(test_ipv4_validator));
    ts_add_utest(&TEST_SUITE(utils_test), UTEST_FCT(test_hostname_validator), UTEST_DESCR(test_hostname_validator));
    return register_ts(&TEST_SUITE(utils_test));
}
#endif /* LCOV_EXCL_STOP */
/***EOF***/
