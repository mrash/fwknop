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

/* Return encryption mode string representation
*/
const char *
enc_mode_inttostr(const int mode)
{
    if(mode == FKO_ENC_MODE_UNKNOWN)
        return("Unknown encryption mode");
    else if(mode == FKO_ENC_MODE_ECB)
        return("ECB");
    else if(mode == FKO_ENC_MODE_CBC)
        return("CBC");
    else if(mode == FKO_ENC_MODE_CFB)
        return("CFB");
    else if(mode == FKO_ENC_MODE_PCBC)
        return("PCBC");
    else if(mode == FKO_ENC_MODE_OFB)
        return("OFB");
    else if(mode == FKO_ENC_MODE_CTR)
        return("CTR");
    else if(mode == FKO_ENC_MODE_ASYMMETRIC)
        return("Asymmetric");
    else if(mode == FKO_ENC_MODE_CBC_LEGACY_IV)
        return("CBC legacy initialization vector");

    return("Unknown encryption mode");
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

/* Return digest string representation
*/
const char *
digest_inttostr(const int type)
{
    if(type == FKO_DIGEST_MD5 || type == FKO_HMAC_MD5)
        return("MD5");
    else if(type == FKO_DIGEST_SHA1 || type == FKO_HMAC_SHA1)
        return("SHA1");
    else if(type == FKO_DIGEST_SHA256 || type == FKO_HMAC_SHA256)
        return("SHA256");
    else if(type == FKO_DIGEST_SHA384 || type == FKO_HMAC_SHA384)
        return("SHA384");
    else if(type == FKO_DIGEST_SHA512 || type == FKO_HMAC_SHA512)
        return("SHA512");

    return("Unknown digest type");
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
