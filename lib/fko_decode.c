/**
 * \file lib/fko_decode.c
 *
 * \brief Decode an FKO SPA message after decryption.
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
#include "fko.h"
#include "cipher_funcs.h"
#include "base64.h"
#include "digest.h"

#define FIELD_PARSERS 9

/* Char used to separate SPA fields in an SPA packet */
#define SPA_FIELD_SEPARATOR    ":"

#ifdef HAVE_C_UNIT_TESTS
DECLARE_TEST_SUITE(fko_decode, "FKO decode test suite");
#endif

static int
num_fields(char *str)
{
    int    i=0;
    char   *tmp = NULL;

    /* Count the number of remaining SPA packet fields
    */
    for (i=0; i <= MAX_SPA_FIELDS+1; i++)
    {
        if ((tmp = strchr(str, ':')) == NULL)
            break;
        str = tmp + 1;
    }
    return i;
}

static int
last_field(char *str)
{
    int    i=0, pos_last=0;
    char   *tmp = NULL;

    /* Count the number of bytes to the last ':' char
    */
    for (i=0; i <= MAX_SPA_FIELDS+1; i++)
    {
        if ((tmp = strchr(str, ':')) == NULL)
            break;

        pos_last += (tmp - str) + 1;
        str = tmp + 1;
    }
    return pos_last;
}

static int
verify_digest(char *tbuf, int t_size, fko_ctx_t ctx)
{
#if AFL_FUZZING
    return FKO_SUCCESS;
#endif

    switch(ctx->digest_type)
    {
        case FKO_DIGEST_MD5:
            md5_base64(tbuf, (unsigned char*)ctx->encoded_msg, ctx->encoded_msg_len);
            break;

        case FKO_DIGEST_SHA1:
            sha1_base64(tbuf, (unsigned char*)ctx->encoded_msg, ctx->encoded_msg_len);
            break;

        case FKO_DIGEST_SHA256:
            sha256_base64(tbuf, (unsigned char*)ctx->encoded_msg, ctx->encoded_msg_len);
            break;

        case FKO_DIGEST_SHA384:
            sha384_base64(tbuf, (unsigned char*)ctx->encoded_msg, ctx->encoded_msg_len);
            break;

        case FKO_DIGEST_SHA512:
            sha512_base64(tbuf, (unsigned char*)ctx->encoded_msg, ctx->encoded_msg_len);
            break;

        default: /* Invalid or unsupported digest */
            return(FKO_ERROR_INVALID_DIGEST_TYPE);
    }

    /* We give up here if the computed digest does not match the
     * digest in the message data.
    */
    if(constant_runtime_cmp(ctx->digest, tbuf, t_size) != 0)
        return(FKO_ERROR_DIGEST_VERIFICATION_FAILED);

    return FKO_SUCCESS;
}

static int
is_valid_digest_len(int t_size, fko_ctx_t ctx)
{
    switch(t_size)
    {
        case MD5_B64_LEN:
            ctx->digest_type = FKO_DIGEST_MD5;
            ctx->digest_len  = MD5_B64_LEN;
            break;

        case SHA1_B64_LEN:
            ctx->digest_type = FKO_DIGEST_SHA1;
            ctx->digest_len  = SHA1_B64_LEN;
            break;

        case SHA256_B64_LEN:
            ctx->digest_type = FKO_DIGEST_SHA256;
            ctx->digest_len  = SHA256_B64_LEN;
            break;

        case SHA384_B64_LEN:
            ctx->digest_type = FKO_DIGEST_SHA384;
            ctx->digest_len  = SHA384_B64_LEN;
            break;

        case SHA512_B64_LEN:
            ctx->digest_type = FKO_DIGEST_SHA512;
            ctx->digest_len  = SHA512_B64_LEN;
            break;

        default: /* Invalid or unsupported digest */
            return(FKO_ERROR_INVALID_DIGEST_TYPE);
    }

    if (ctx->encoded_msg_len - t_size < 0)
        return(FKO_ERROR_INVALID_DATA_DECODE_ENC_MSG_LEN_MT_T_SIZE);

    return FKO_SUCCESS;
}

static int
parse_msg(char *tbuf, char **ndx, int *t_size, fko_ctx_t ctx)
{
    if((*t_size = strcspn(*ndx, ":")) < 1)
        return(FKO_ERROR_INVALID_DATA_DECODE_MESSAGE_MISSING);

    if (*t_size > MAX_SPA_MESSAGE_SIZE)
        return(FKO_ERROR_INVALID_DATA_DECODE_MESSAGE_TOOBIG);

    strlcpy(tbuf, *ndx, *t_size+1);

    if(ctx->message != NULL)
        free(ctx->message);

    ctx->message = calloc(1, *t_size+1); /* Yes, more than we need */

    if(ctx->message == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    if(b64_decode(tbuf, (unsigned char*)ctx->message) < 0)
        return(FKO_ERROR_INVALID_DATA_DECODE_MESSAGE_DECODEFAIL);

    if(ctx->message_type == FKO_COMMAND_MSG)
    {
        /* Require a message similar to: 1.2.3.4,<command>
        */
        if(validate_cmd_msg(ctx->message) != FKO_SUCCESS)
        {
            return(FKO_ERROR_INVALID_DATA_DECODE_MESSAGE_VALIDFAIL);
        }
    }
    else
    {
        /* Require a message similar to: 1.2.3.4,tcp/22
        */
        if(validate_access_msg(ctx->message) != FKO_SUCCESS)
        {
            return(FKO_ERROR_INVALID_DATA_DECODE_ACCESS_VALIDFAIL);
        }
    }

    *ndx += *t_size + 1;
    return FKO_SUCCESS;
}

static int
parse_nat_msg(char *tbuf, char **ndx, int *t_size, fko_ctx_t ctx)
{
    if(  ctx->message_type == FKO_NAT_ACCESS_MSG
      || ctx->message_type == FKO_LOCAL_NAT_ACCESS_MSG
      || ctx->message_type == FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG
      || ctx->message_type == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
    {
        if((*t_size = strcspn(*ndx, ":")) < 1)
            return(FKO_ERROR_INVALID_DATA_DECODE_NATACCESS_MISSING);

        if (*t_size > MAX_SPA_MESSAGE_SIZE)
            return(FKO_ERROR_INVALID_DATA_DECODE_NATACCESS_TOOBIG);

        strlcpy(tbuf, *ndx, *t_size+1);

        if(ctx->nat_access != NULL)
            free(ctx->nat_access);

        ctx->nat_access = calloc(1, *t_size+1); /* Yes, more than we need */
        if(ctx->nat_access == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);

        if(b64_decode(tbuf, (unsigned char*)ctx->nat_access) < 0)
            return(FKO_ERROR_INVALID_DATA_DECODE_NATACCESS_DECODEFAIL);

        if(validate_nat_access_msg(ctx->nat_access) != FKO_SUCCESS)
            return(FKO_ERROR_INVALID_DATA_DECODE_NATACCESS_VALIDFAIL);

        *ndx += *t_size + 1;
    }

    return FKO_SUCCESS;
}

static int
parse_server_auth(char *tbuf, char **ndx, int *t_size, fko_ctx_t ctx)
{
    if((*t_size = strlen(*ndx)) > 0)
    {
        if (*t_size > MAX_SPA_MESSAGE_SIZE)
        {
            return(FKO_ERROR_INVALID_DATA_DECODE_SRVAUTH_MISSING);
        }
    }
    else
        return FKO_SUCCESS;

    if(  ctx->message_type == FKO_CLIENT_TIMEOUT_ACCESS_MSG
      || ctx->message_type == FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG
      || ctx->message_type == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
    {
        /* If we are here then we may still have a server_auth string,
         * or a timeout, or both. So we look for a ':' delimiter.  If
         * it is there we have both, if not we check the message_type
         * again.
        */
        if(strchr(*ndx, ':'))
        {
            *t_size = strcspn(*ndx, ":");

            if (*t_size > MAX_SPA_MESSAGE_SIZE)
                return(FKO_ERROR_INVALID_DATA_DECODE_EXTRA_TOOBIG);

            strlcpy(tbuf, *ndx, *t_size+1);

            if(ctx->server_auth != NULL)
                free(ctx->server_auth);

            ctx->server_auth = calloc(1, *t_size+1); /* Yes, more than we need */
            if(ctx->server_auth == NULL)
                return(FKO_ERROR_MEMORY_ALLOCATION);

            if(b64_decode(tbuf, (unsigned char*)ctx->server_auth) < 0)
                return(FKO_ERROR_INVALID_DATA_DECODE_EXTRA_DECODEFAIL);

            *ndx += *t_size + 1;
        }
    }
    else
    {
        strlcpy(tbuf, *ndx, *t_size+1);

        if(ctx->server_auth != NULL)
            free(ctx->server_auth);

        ctx->server_auth = calloc(1, *t_size+1); /* Yes, more than we need */
        if(ctx->server_auth == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);

        if(b64_decode(tbuf, (unsigned char*)ctx->server_auth) < 0)
            return(FKO_ERROR_INVALID_DATA_DECODE_SRVAUTH_DECODEFAIL);
    }

    return FKO_SUCCESS;
}

static int
parse_client_timeout(char *tbuf, char **ndx, int *t_size, fko_ctx_t ctx)
{
    int         is_err;

    if(  ctx->message_type == FKO_CLIENT_TIMEOUT_ACCESS_MSG
      || ctx->message_type == FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG
      || ctx->message_type == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
    {
        if((*t_size = strlen(*ndx)) < 1)
            return(FKO_ERROR_INVALID_DATA_DECODE_TIMEOUT_MISSING);

        if (*t_size > MAX_SPA_MESSAGE_SIZE)
            return(FKO_ERROR_INVALID_DATA_DECODE_TIMEOUT_TOOBIG);

        /* Should be a number only.
        */
        if(strspn(*ndx, "0123456789") != *t_size)
            return(FKO_ERROR_INVALID_DATA_DECODE_TIMEOUT_VALIDFAIL);

        ctx->client_timeout = (unsigned int) strtol_wrapper(*ndx, 0,
                (2 << 15), NO_EXIT_UPON_ERR, &is_err);
        if(is_err != FKO_SUCCESS)
            return(FKO_ERROR_INVALID_DATA_DECODE_TIMEOUT_DECODEFAIL);
    }

    return FKO_SUCCESS;
}

static int
parse_msg_type(char *tbuf, char **ndx, int *t_size, fko_ctx_t ctx)
{
    int    is_err, remaining_fields;

    if((*t_size = strcspn(*ndx, ":")) < 1)
        return(FKO_ERROR_INVALID_DATA_DECODE_MSGTYPE_MISSING);

    if(*t_size > MAX_SPA_MESSAGE_TYPE_SIZE)
        return(FKO_ERROR_INVALID_DATA_DECODE_MSGTYPE_TOOBIG);

    strlcpy(tbuf, *ndx, *t_size+1);

    ctx->message_type = strtol_wrapper(tbuf, 0,
            FKO_LAST_MSG_TYPE-1, NO_EXIT_UPON_ERR, &is_err);

    if(is_err != FKO_SUCCESS)
        return(FKO_ERROR_INVALID_DATA_DECODE_MSGTYPE_DECODEFAIL);

    /* Now that we have a valid type, ensure that the total
     * number of SPA fields is also valid for the type
    */
    remaining_fields = num_fields(*ndx);

    switch(ctx->message_type)
    {
        /* optional server_auth + digest */
        case FKO_COMMAND_MSG:
        case FKO_ACCESS_MSG:
            if(remaining_fields > 2)
                return FKO_ERROR_INVALID_DATA_DECODE_WRONG_NUM_FIELDS;
            break;

        /* nat or client timeout + optional server_auth + digest */
        case FKO_NAT_ACCESS_MSG:
        case FKO_LOCAL_NAT_ACCESS_MSG:
        case FKO_CLIENT_TIMEOUT_ACCESS_MSG:
            if(remaining_fields > 3)
                return FKO_ERROR_INVALID_DATA_DECODE_WRONG_NUM_FIELDS;
            break;

        /* client timeout + nat + optional server_auth + digest */
        case FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG:
        case FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG:
            if(remaining_fields > 4)
                return FKO_ERROR_INVALID_DATA_DECODE_WRONG_NUM_FIELDS;
            break;

        default: /* Should not reach here */
            return(FKO_ERROR_INVALID_DATA_DECODE_MSGTYPE_DECODEFAIL);
    }

    *ndx += *t_size + 1;
    return FKO_SUCCESS;
}

static int
parse_version(char *tbuf, char **ndx, int *t_size, fko_ctx_t ctx)
{
    if((*t_size = strcspn(*ndx, ":")) < 1)
        return(FKO_ERROR_INVALID_DATA_DECODE_VERSION_MISSING);

    if (*t_size > MAX_SPA_VERSION_SIZE)
        return(FKO_ERROR_INVALID_DATA_DECODE_VERSION_TOOBIG);

    if(ctx->version != NULL)
        free(ctx->version);

    ctx->version = calloc(1, *t_size+1);
    if(ctx->version == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    strlcpy(ctx->version, *ndx, *t_size+1);

    *ndx += *t_size + 1;
    return FKO_SUCCESS;
}

static int
parse_timestamp(char *tbuf, char **ndx, int *t_size, fko_ctx_t ctx)
{
    int         is_err;

    if((*t_size = strcspn(*ndx, ":")) < 1)
        return(FKO_ERROR_INVALID_DATA_DECODE_TIMESTAMP_MISSING);

    if (*t_size > MAX_SPA_TIMESTAMP_SIZE)
        return(FKO_ERROR_INVALID_DATA_DECODE_TIMESTAMP_TOOBIG);

    strlcpy(tbuf, *ndx, *t_size+1);

    ctx->timestamp = (unsigned int) strtol_wrapper(tbuf,
            0, -1, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
        return(FKO_ERROR_INVALID_DATA_DECODE_TIMESTAMP_DECODEFAIL);

    *ndx += *t_size + 1;

    return FKO_SUCCESS;
}

static int
parse_username(char *tbuf, char **ndx, int *t_size, fko_ctx_t ctx)
{
    if((*t_size = strcspn(*ndx, ":")) < 1)
        return(FKO_ERROR_INVALID_DATA_DECODE_USERNAME_MISSING);

    if (*t_size > MAX_SPA_USERNAME_SIZE)
        return(FKO_ERROR_INVALID_DATA_DECODE_USERNAME_TOOBIG);

    strlcpy(tbuf, *ndx, *t_size+1);

    if(ctx->username != NULL)
        free(ctx->username);

    ctx->username = calloc(1, *t_size+1); /* Yes, more than we need */
    if(ctx->username == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    if(b64_decode(tbuf, (unsigned char*)ctx->username) < 0)
        return(FKO_ERROR_INVALID_DATA_DECODE_USERNAME_DECODEFAIL);

    if(validate_username(ctx->username) != FKO_SUCCESS)
        return(FKO_ERROR_INVALID_DATA_DECODE_USERNAME_VALIDFAIL);

    *ndx += *t_size + 1;

    return FKO_SUCCESS;
}

static int
parse_rand_val(char *tbuf, char **ndx, int *t_size, fko_ctx_t ctx)
{
    if((*t_size = strcspn(*ndx, ":")) < FKO_RAND_VAL_SIZE)
        return(FKO_ERROR_INVALID_DATA_DECODE_RAND_MISSING);

    if(ctx->rand_val != NULL)
        free(ctx->rand_val);

    ctx->rand_val = calloc(1, FKO_RAND_VAL_SIZE+1);
    if(ctx->rand_val == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    ctx->rand_val = strncpy(ctx->rand_val, *ndx, FKO_RAND_VAL_SIZE);

    *ndx += *t_size + 1;

    return FKO_SUCCESS;
}

/* Decode the encoded SPA data.
*/
int
fko_decode_spa_data(fko_ctx_t ctx)
{
    char       *tbuf, *ndx;
    int         t_size, i, res;

    /* Array of function pointers to SPA field parsing functions
    */
    int (*field_parser[FIELD_PARSERS])(char *tbuf, char **ndx, int *t_size, fko_ctx_t ctx)
        = { parse_rand_val,       /* Extract random value */
            parse_username,       /* Extract username */
            parse_timestamp,      /* Client timestamp */
            parse_version,        /* SPA version */
            parse_msg_type,       /* SPA msg type */
            parse_msg,            /* SPA msg string */
            parse_nat_msg,        /* SPA NAT msg string */
            parse_server_auth,    /* optional server authentication method */
            parse_client_timeout  /* client defined timeout */
          };

    if (! is_valid_encoded_msg_len(ctx->encoded_msg_len))
        return(FKO_ERROR_INVALID_DATA_DECODE_MSGLEN_VALIDFAIL);

    /* Make sure there are no non-ascii printable chars
    */
    for (i=0; i < (int)strnlen(ctx->encoded_msg, MAX_SPA_ENCODED_MSG_SIZE); i++)
        if(isprint(ctx->encoded_msg[i]) == 0)
            return(FKO_ERROR_INVALID_DATA_DECODE_NON_ASCII);

    /* Make sure there are enough fields in the SPA packet
     * delimited with ':' chars
    */
    ndx = ctx->encoded_msg;

    if (num_fields(ndx) < MIN_SPA_FIELDS)
        return(FKO_ERROR_INVALID_DATA_DECODE_LT_MIN_FIELDS);

    ndx += last_field(ndx);

    t_size = strnlen(ndx, SHA512_B64_LEN+1);

    /* Validate digest length
    */
    res = is_valid_digest_len(t_size, ctx);
    if(res != FKO_SUCCESS)
        return res;

    if(ctx->digest != NULL)
        free(ctx->digest);

    /* Copy the digest into the context and terminate the encoded data
     * at that point so the original digest is not part of the
     * encoded string.
    */
    ctx->digest = strdup(ndx);
    if(ctx->digest == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    /* Chop the digest off of the encoded_msg bucket...
    */
    bzero((ndx-1), t_size);

    ctx->encoded_msg_len -= t_size+1;

    /* Make a tmp bucket for processing base64 encoded data and
     * other general use.
    */
    tbuf = calloc(1, FKO_ENCODE_TMP_BUF_SIZE);
    if(tbuf == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    /* Can now verify the digest.
    */
    res = verify_digest(tbuf, t_size, ctx);
    if(res != FKO_SUCCESS)
    {
        free(tbuf);
        return(FKO_ERROR_DIGEST_VERIFICATION_FAILED);
    }

    /* Now we will work through the encoded data and extract (and base64-
     * decode where necessary), the SPA data fields and populate the context.
    */
    ndx = ctx->encoded_msg;

    for (i=0; i < FIELD_PARSERS; i++)
    {
        res = (*field_parser[i])(tbuf, &ndx, &t_size, ctx);
        if(res != FKO_SUCCESS)
        {
            free(tbuf);
            return res;
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

#ifdef HAVE_C_UNIT_TESTS

DECLARE_UTEST(num_fields, "Count the number of SPA fields in a SPA packet")
{
    int ix_field=0;
    char spa_packet[(MAX_SPA_FIELDS+1)*3];

    /* Zeroing the spa packet */
    memset(spa_packet, 0, sizeof(spa_packet));
    
    /* Check we are able to count the number of SPA fields */
    for(ix_field=0 ; ix_field<=MAX_SPA_FIELDS+2 ; ix_field++)
    {
        strcat(spa_packet, "x");
        CU_ASSERT(num_fields(spa_packet) == ix_field);
        strcat(spa_packet, SPA_FIELD_SEPARATOR);
    }

    /* Check for possible overflow */
    strcat(spa_packet, "x");
    CU_ASSERT(num_fields(spa_packet) == MAX_SPA_FIELDS + 2);
    strcat(spa_packet, "x");
    strcat(spa_packet, SPA_FIELD_SEPARATOR);
    CU_ASSERT(num_fields(spa_packet) == MAX_SPA_FIELDS + 2);
}

DECLARE_UTEST(last_field, "Count the number of bytes to the last :")
{
    int ix_field;
    char spa_packet[(MAX_SPA_FIELDS+1)*3];

    /* Zeroing the spa packet */
    memset(spa_packet, 0, sizeof(spa_packet));
    
    /* Check for a valid count when the number of field is less than MAX_SPA_FIELDS  */
    CU_ASSERT(last_field("a:") == 2);
    CU_ASSERT(last_field("ab:abc:") == 7);
    CU_ASSERT(last_field("abc:abcd:") == 9);
    CU_ASSERT(last_field("abc:abcd:abc") == 9);


    /*  */
    for(ix_field=0 ; ix_field<=MAX_SPA_FIELDS+2 ; ix_field++)
    {
        strcat(spa_packet, "x");
        strcat(spa_packet, SPA_FIELD_SEPARATOR);
    }
    CU_ASSERT(last_field(spa_packet) == ((MAX_SPA_FIELDS+2)*2));
}

int register_ts_fko_decode(void)
{
    ts_init(&TEST_SUITE(fko_decode), TEST_SUITE_DESCR(fko_decode), NULL, NULL);
    ts_add_utest(&TEST_SUITE(fko_decode), UTEST_FCT(num_fields), UTEST_DESCR(num_fields));
    ts_add_utest(&TEST_SUITE(fko_decode), UTEST_FCT(last_field), UTEST_DESCR(last_field));

    return register_ts(&TEST_SUITE(fko_decode));
}

#endif /* HAVE_C_UNIT_TESTS */

/***EOF***/
