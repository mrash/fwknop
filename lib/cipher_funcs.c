/*
 *****************************************************************************
 *
 * File:    cipher_funcs.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Cipher functions used by fwknop
 *
 * Copyright 2009-2010 Damien Stuart (dstuart@dstuart.org)
 *
 *  License (GNU Public License):
 *
 *  This library is free software; you can redistribute it and/or
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
#include <stdio.h>
#include <string.h>

#ifdef WIN32
  #include <sys/timeb.h>
  #include <time.h>
  #include <stdlib.h>
#else
  #include <sys/time.h>
#endif

#include "cipher_funcs.h"
#include "digest.h"

#ifndef WIN32
  #ifndef RAND_FILE
    #define RAND_FILE "/dev/urandom"
  #endif
#endif

/* Get random data.
*/
void
get_random_data(unsigned char *data, const size_t len)
{
    uint32_t    i;
#ifdef WIN32
	int				rnum;
	struct _timeb	tb;

	_ftime_s(&tb);

	srand((uint32_t)(tb.time*1000)+tb.millitm);

	for(i=0; i<len; i++)
	{
		rnum = rand();
        *(data+i) = rnum % 0xff;
	}
#else
	FILE           *rfd;
    struct timeval  tv;
    int             do_time = 0;
    size_t          amt_read;

    /* Attempt to read seed data from /dev/urandom.  If that does not
     * work, then fall back to a time-based method (less secure, but
     * probably more portable).
    */
    if((rfd = fopen(RAND_FILE, "r")) == NULL)
    {
        do_time = 1;
    }
    else
    {
        /* Read seed from /dev/urandom
        */
        amt_read = fread(data, len, 1, rfd);
        fclose(rfd);

        if (amt_read != 1)
            do_time = 1;
    }

    if (do_time)
    {
        /* Seed based on time (current usecs).
        */
        gettimeofday(&tv, NULL);
        srand(tv.tv_usec);

        for(i=0; i<len; i++)
            *(data+i) = rand() % 0xff;
    }

#endif

}


/*** These are Rijndael-specific functions ***/

/* Rijndael function to generate initial salt and initialization vector
 * (iv).  This is is done to be compatible with the data produced via
 * the Perl Crypt::CBC module's use of Rijndael.
*/
static void
rij_salt_and_iv(RIJNDAEL_context *ctx, const char *key,
        const int key_len, const unsigned char *data)
{
    char            pw_buf[RIJNDAEL_MAX_KEYSIZE];
    unsigned char   tmp_buf[64];    /* How big does this need to be? */
    unsigned char   kiv_buf[RIJNDAEL_MAX_KEYSIZE+RIJNDAEL_BLOCKSIZE]; /* Key and IV buffer */
    unsigned char   md5_buf[MD5_DIGEST_LEN]; /* Buffer for computed md5 hash */

    int             final_key_len = RIJNDAEL_MIN_KEYSIZE;
    size_t          kiv_len = 0;

    /* First make pw 32 bytes (pad with "0" (ascii 0x30)) or truncate.
     * Note: pw_buf was initialized with '0' chars (again, not the value
     *       0, but the digit '0' character).
    */
    if(key_len < RIJNDAEL_MIN_KEYSIZE)
    {
        memcpy(pw_buf, key, key_len);
        memset(pw_buf+key_len, '0', RIJNDAEL_MIN_KEYSIZE - key_len);
    }
    else
    {
        memcpy(pw_buf, key, key_len);
        final_key_len = key_len;
    }

    /* If we are decrypting, data will contain the salt. Otherwise,
     * for encryption, we generate a random salt.
    */
    if(data != NULL)
    {
        /* Pull the salt from the data
        */
        memcpy(ctx->salt, (data+SALT_LEN), SALT_LEN);
    }
    else
    {
        /* Generate a random 8-byte salt.
        */
        get_random_data(ctx->salt, SALT_LEN);
    }

    /* Now generate the key and initialization vector.
     * (again it is the perl Crypt::CBC way, with a touch of
     * fwknop).
    */
    memcpy(tmp_buf+MD5_DIGEST_LEN, pw_buf, final_key_len);
    memcpy(tmp_buf+MD5_DIGEST_LEN+final_key_len, ctx->salt, SALT_LEN);

    while(kiv_len < sizeof(kiv_buf))
    {
        if(kiv_len == 0)
            md5(md5_buf, tmp_buf+MD5_DIGEST_LEN, final_key_len+SALT_LEN);
        else
            md5(md5_buf, tmp_buf, MD5_DIGEST_LEN+final_key_len+SALT_LEN);

        memcpy(tmp_buf, md5_buf, MD5_DIGEST_LEN);

        memcpy(kiv_buf + kiv_len, md5_buf, MD5_DIGEST_LEN);

        kiv_len += MD5_DIGEST_LEN;
    }

    memcpy(ctx->key, kiv_buf, RIJNDAEL_MAX_KEYSIZE);
    memcpy(ctx->iv,  kiv_buf+RIJNDAEL_MAX_KEYSIZE, RIJNDAEL_BLOCKSIZE);
}

/* Initialization entry point.
*/
static void
rijndael_init(RIJNDAEL_context *ctx, const char *key,
    const int key_len, const unsigned char *data,
    int encryption_mode)
{

    /* The default (set in fko.h) is ECB mode to be compatible with the
     * Crypt::CBC perl module.
    */
    ctx->mode = encryption_mode;

    /* Generate the salt and initialization vector.
    */
    rij_salt_and_iv(ctx, key, key_len, data);

    /* Intialize our Rijndael context.
    */
    rijndael_setup(ctx, RIJNDAEL_MAX_KEYSIZE, ctx->key);
}

/* Take a chunk of data, encrypt it in the same way the perl Crypt::CBC
 * module would.
*/
size_t
rij_encrypt(unsigned char *in, size_t in_len,
    const char *key, const int key_len,
    unsigned char *out, int encryption_mode)
{
    RIJNDAEL_context    ctx;
    int                 i, pad_val;
    unsigned char      *ondx = out;

    rijndael_init(&ctx, key, key_len, NULL, encryption_mode);

    /* Prepend the salt to the ciphertext...
    */
    memcpy(ondx, "Salted__", SALT_LEN);
    ondx+=SALT_LEN;
    memcpy(ondx, ctx.salt, SALT_LEN);
    ondx+=SALT_LEN;

    /* Add padding to the original plaintext to ensure that it is a
     * multiple of the Rijndael block size
    */
    pad_val = RIJNDAEL_BLOCKSIZE - (in_len % RIJNDAEL_BLOCKSIZE);
    for (i = in_len; i < in_len+pad_val; i++)
        in[i] = pad_val;

    block_encrypt(&ctx, in, in_len+pad_val, ondx, ctx.iv);

    ondx += in_len+pad_val;

    return(ondx - out);
}

/* Decrypt the given data.
*/
size_t
rij_decrypt(unsigned char *in, size_t in_len,
    const char *key, const int key_len,
    unsigned char *out, int encryption_mode)
{
    RIJNDAEL_context    ctx;
    int                 i, pad_val, pad_err = 0;
    unsigned char      *pad_s;
    unsigned char      *ondx = out;

    rijndael_init(&ctx, key, key_len, in, encryption_mode);

    /* Remove the first block since it contains the salt (it was consumed
     * by the rijndael_init() function above).
    */
    in_len -= RIJNDAEL_BLOCKSIZE;
    memmove(in, in+RIJNDAEL_BLOCKSIZE, in_len);

    block_decrypt(&ctx, in, in_len, out, ctx.iv);

    ondx += in_len;

    /* Find and remove padding.
    */
    pad_val = *(ondx-1);

    if(pad_val >= 0 && pad_val <= RIJNDAEL_BLOCKSIZE)
    {
        pad_s = ondx - pad_val;

        for(i=0; i < (ondx-pad_s); i++)
        {
            if(*(pad_s+i) != pad_val)
                pad_err++;
        }

        if(pad_err == 0)
            ondx -= pad_val;
    }

    *ondx = '\0';

    return(ondx - out);
}

/* See if we need to add the "Salted__" string to the front of the
 * encrypted data.
*/
int
add_salted_str(fko_ctx_t ctx)
{
    char           *tbuf;

    if(strncmp(ctx->encrypted_msg,
            B64_RIJNDAEL_SALT, B64_RIJNDAEL_SALT_STR_LEN))
    {
        /* We need to realloc space for the salt.
        */
        tbuf = realloc(ctx->encrypted_msg, ctx->encrypted_msg_len
                    + B64_RIJNDAEL_SALT_STR_LEN+1);
        if(tbuf == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);

        memmove(tbuf+B64_RIJNDAEL_SALT_STR_LEN, tbuf, ctx->encrypted_msg_len);

        ctx->encrypted_msg = memcpy(tbuf,
                B64_RIJNDAEL_SALT, B64_RIJNDAEL_SALT_STR_LEN);

        /* Adjust the encoded msg len for added SALT value and Make sure we
         * are still a properly NULL-terminated string (Ubuntu was one system
         * for which this was an issue).
        */
        ctx->encrypted_msg_len += B64_RIJNDAEL_SALT_STR_LEN;
        tbuf[ctx->encrypted_msg_len] = '\0';

        ctx->added_salted_str = 1;
    }

    return(FKO_SUCCESS);
}


/***EOF***/
