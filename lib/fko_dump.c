/**
 * \file lib/fko_dump.c
 *
 * \brief Dump fko buffer
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stddef.h>
#include <string.h>
#include "fko.h"
#include "fko_common.h"

#define NULL_STRING                 "<NULL>"                /*!< String which represents a NULL buffer */

/* Check for a FKO error returned by a function an return the error code */
#define RETURN_ON_FKO_ERROR(e, f)   do { if (((e)=(f)) != FKO_SUCCESS) { return (e); } } while(0);


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
fko_dump_ctx_to_buffer(fko_ctx_t ctx, char *dump_buf, size_t dump_buf_len)
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
    char        enc_mode_str[16] = {0};

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