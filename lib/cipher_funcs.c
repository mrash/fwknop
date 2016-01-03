/**
 * \file lib/cipher_funcs.c
 *
 * \brief Cipher functions used by fwknop
 */

/*  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
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

#include "fko_common.h"
#include "cipher_funcs.h"
#include "digest.h"

#ifndef WIN32
  #ifndef RAND_FILE
    #define RAND_FILE "/dev/urandom"
  #endif
#endif

#ifdef HAVE_C_UNIT_TESTS
DECLARE_TEST_SUITE(digest_test, "Cipher functions test suite");
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
 * (iv).  This is is done to be compatible with the data produced via OpenSSL
*/
static void
rij_salt_and_iv(RIJNDAEL_context *ctx, const char *key,
        const int key_len, const unsigned char *data, const int mode_flag)
{
    char            pw_buf[RIJNDAEL_MAX_KEYSIZE] = {0};
    unsigned char   tmp_buf[MD5_DIGEST_LEN+RIJNDAEL_MAX_KEYSIZE+RIJNDAEL_BLOCKSIZE] = {0};
    unsigned char   kiv_buf[RIJNDAEL_MAX_KEYSIZE+RIJNDAEL_BLOCKSIZE] = {0}; /* Key and IV buffer */
    unsigned char   md5_buf[MD5_DIGEST_LEN] = {0}; /* Buffer for computed md5 hash */

    int             final_key_len = 0;
    size_t          kiv_len = 0;

    if(mode_flag == FKO_ENC_MODE_CBC_LEGACY_IV)
    {
        /* Pad the pw with '0' chars up to the minimum Rijndael key size.
         *
         * This maintains compatibility with the old perl code if absolutely
         * necessary in some scenarios, but is not recommended to use since it
         * breaks compatibility with how OpenSSL implements AES and introduces
         * other problems.  This code will be removed altogether in a future
         * version of fwknop.
        */
        if(key_len < RIJNDAEL_MIN_KEYSIZE)
        {
            memcpy(pw_buf, key, key_len);
            memset(pw_buf+key_len, '0', RIJNDAEL_MIN_KEYSIZE - key_len);
            final_key_len = RIJNDAEL_MIN_KEYSIZE;
        }
        else
        {
            memcpy(pw_buf, key, key_len);
            final_key_len = key_len;
        }
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

    /* The default is Rijndael in CBC mode
    */
    if(encryption_mode == FKO_ENC_MODE_CBC
            || encryption_mode == FKO_ENC_MODE_CBC_LEGACY_IV)
        ctx->mode = MODE_CBC;
    else if(encryption_mode == FKO_ENC_MODE_CTR)
        ctx->mode = MODE_CTR;
    else if(encryption_mode == FKO_ENC_MODE_PCBC)
        ctx->mode = MODE_PCBC;
    else if(encryption_mode == FKO_ENC_MODE_OFB)
        ctx->mode = MODE_OFB;
    else if(encryption_mode == FKO_ENC_MODE_CFB)
        ctx->mode = MODE_CFB;
    else if(encryption_mode == FKO_ENC_MODE_ECB)
        ctx->mode = MODE_ECB;
    else  /* shouldn't get this far */
        ctx->mode = encryption_mode;

    /* Generate the salt and initialization vector.
    */
    rij_salt_and_iv(ctx, key, key_len, data, encryption_mode);

    /* Intialize our Rijndael context.
    */
    rijndael_setup(ctx, RIJNDAEL_MAX_KEYSIZE, ctx->key);
}

/* Take a chunk of data, encrypt it in the same way OpenSSL would
 * (with a default of AES in CBC mode).
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
    for (i = (int)in_len; i < ((int)in_len+pad_val); i++)
        in[i] = pad_val;

    block_encrypt(&ctx, in, in_len+pad_val, ondx, ctx.iv);

    ondx += in_len+pad_val;

    zero_buf((char *)ctx.key, RIJNDAEL_MAX_KEYSIZE);
    zero_buf((char *)ctx.iv, RIJNDAEL_BLOCKSIZE);
    zero_buf((char *)ctx.salt, SALT_LEN);

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

    if(in == NULL || key == NULL || out == NULL)
        return 0;

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

    zero_buf((char *)ctx.key, RIJNDAEL_MAX_KEYSIZE);
    zero_buf((char *)ctx.iv, RIJNDAEL_BLOCKSIZE);
    zero_buf((char *)ctx.salt, SALT_LEN);

    return(ondx - out);
}

/* See if we need to add the "Salted__" string to the front of the
 * encrypted data.
*/
int
add_salted_str(fko_ctx_t ctx)
{
    char           *tbuf;

#if AFL_FUZZING
    ctx->added_salted_str = 1;
    return(FKO_SUCCESS);
#endif

    /* We only add the base64 encoded salt to data that is already base64
     * encoded
    */
    if(is_base64((unsigned char *)ctx->encrypted_msg,
            ctx->encrypted_msg_len) == 0)
        return(FKO_ERROR_INVALID_DATA_ENCODE_NOTBASE64);

    if(constant_runtime_cmp(ctx->encrypted_msg,
            B64_RIJNDAEL_SALT, B64_RIJNDAEL_SALT_STR_LEN) != 0)
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

/* See if we need to add the "hQ" string to the front of the
 * encrypted data.
*/
int
add_gpg_prefix(fko_ctx_t ctx)
{
    char           *tbuf;

    /* We only add the base64 encoded salt to data that is already base64
     * encoded
    */
    if(is_base64((unsigned char *)ctx->encrypted_msg,
                ctx->encrypted_msg_len) == 0)
        return(FKO_ERROR_INVALID_DATA_ENCODE_NOTBASE64);

    if(constant_runtime_cmp(ctx->encrypted_msg,
            B64_GPG_PREFIX, B64_GPG_PREFIX_STR_LEN) != 0)
    {
        /* We need to realloc space for the prefix.
        */
        tbuf = realloc(ctx->encrypted_msg, ctx->encrypted_msg_len
                    + B64_GPG_PREFIX_STR_LEN+1);
        if(tbuf == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);

        memmove(tbuf+B64_GPG_PREFIX_STR_LEN, tbuf, ctx->encrypted_msg_len);

        ctx->encrypted_msg = memcpy(tbuf,
                B64_GPG_PREFIX, B64_GPG_PREFIX_STR_LEN);

        /* Adjust the encoded msg len for added SALT value and Make sure we
         * are still a properly NULL-terminated string (Ubuntu was one system
         * for which this was an issue).
        */
        ctx->encrypted_msg_len += B64_GPG_PREFIX_STR_LEN;
        tbuf[ctx->encrypted_msg_len] = '\0';

        ctx->added_gpg_prefix = 1;
    }

    return(FKO_SUCCESS);
}

#ifdef HAVE_C_UNIT_TESTS



DECLARE_UTEST(test_aes_ecb_128, "aes ecb 128 test vectors") //http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors#aes-cbc-128
{
    RIJNDAEL_context    ctx;
    unsigned char in[1024] = {0};
    unsigned char out[1024] = {0};
    unsigned char expected_out1[1024] = {0};
    unsigned char expected_out2[1024] = {0};
    unsigned char expected_out3[1024] = {0};
    unsigned char expected_out4[1024] = {0};

    memcpy(expected_out1, "\x3a\xd7\x7b\xb4\x0d\x7a\x36\x60\xa8\x9e\xca\xf3\x24\x66\xef\x97", 16);
    memcpy(expected_out2, "\xf5\xd3\xd5\x85\x03\xb9\x69\x9d\xe7\x85\x89\x5a\x96\xfd\xba\xaf", 16);
    memcpy(expected_out3, "\x43\xb1\xcd\x7f\x59\x8e\xce\x23\x88\x1b\x00\xe3\xed\x03\x06\x88", 16);
    memcpy(expected_out4, "\x7b\x0c\x78\x5e\x27\xe8\xad\x3f\x82\x23\x20\x71\x04\x72\x5d\xd4", 16);
    memcpy(ctx.key, "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c", 16);
    rijndael_setup(&ctx, 16, ctx.key);

    memcpy(in, "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a", 16);
    rijndael_encrypt(&ctx, in, out);
    CU_ASSERT(memcmp(out, expected_out1, 16) == 0);

    memcpy(in, "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51", 16);
    rijndael_encrypt(&ctx, in, out);
    CU_ASSERT(memcmp(out, expected_out2, 16) == 0);

    memcpy(in, "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef", 16);
    rijndael_encrypt(&ctx, in, out);
    CU_ASSERT(memcmp(out, expected_out3, 16) == 0);

    memcpy(in, "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10", 16);
    rijndael_encrypt(&ctx, in, out);
    CU_ASSERT(memcmp(out, expected_out4, 16) == 0);

}
DECLARE_UTEST(test_aes_ecb_192, "aes ecb 192 test vectors") //http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors#aes-cbc-128
{
    RIJNDAEL_context    ctx;
    unsigned char in[1024] = {0};
    unsigned char out[1024] = {0};
    unsigned char expected_out1[1024] = {0};
    unsigned char expected_out2[1024] = {0};
    unsigned char expected_out3[1024] = {0};
    unsigned char expected_out4[1024] = {0};

    memcpy(expected_out1, "\xbd\x33\x4f\x1d\x6e\x45\xf2\x5f\xf7\x12\xa2\x14\x57\x1f\xa5\xcc", 16);
    memcpy(expected_out2, "\x97\x41\x04\x84\x6d\x0a\xd3\xad\x77\x34\xec\xb3\xec\xee\x4e\xef", 16);
    memcpy(expected_out3, "\xef\x7a\xfd\x22\x70\xe2\xe6\x0a\xdc\xe0\xba\x2f\xac\xe6\x44\x4e", 16);
    memcpy(expected_out4, "\x9a\x4b\x41\xba\x73\x8d\x6c\x72\xfb\x16\x69\x16\x03\xc1\x8e\x0e", 16);
    memcpy(ctx.key, "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b", 24);
    rijndael_setup(&ctx, 24, ctx.key);

    memcpy(in, "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a", 16);
    rijndael_encrypt(&ctx, in, out);
    CU_ASSERT(memcmp(out, expected_out1, 16) == 0);

    memcpy(in, "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51", 16);
    rijndael_encrypt(&ctx, in, out);
    CU_ASSERT(memcmp(out, expected_out2, 16) == 0);

    memcpy(in, "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef", 16);
    rijndael_encrypt(&ctx, in, out);
    CU_ASSERT(memcmp(out, expected_out3, 16) == 0);

    memcpy(in, "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10", 16);
    rijndael_encrypt(&ctx, in, out);
    CU_ASSERT(memcmp(out, expected_out4, 16) == 0);

}
DECLARE_UTEST(test_aes_ecb_256, "aes ecb 256 test vectors") //http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors#aes-cbc-128
{
    RIJNDAEL_context    ctx;
    unsigned char in[1024] = {0};
    unsigned char out[1024] = {0};
    unsigned char expected_out1[1024] = {0};
    unsigned char expected_out2[1024] = {0};
    unsigned char expected_out3[1024] = {0};
    unsigned char expected_out4[1024] = {0};

    memcpy(expected_out1, "\xf3\xee\xd1\xbd\xb5\xd2\xa0\x3c\x06\x4b\x5a\x7e\x3d\xb1\x81\xf8", 16);
    memcpy(expected_out2, "\x59\x1c\xcb\x10\xd4\x10\xed\x26\xdc\x5b\xa7\x4a\x31\x36\x28\x70", 16);
    memcpy(expected_out3, "\xb6\xed\x21\xb9\x9c\xa6\xf4\xf9\xf1\x53\xe7\xb1\xbe\xaf\xed\x1d", 16);
    memcpy(expected_out4, "\x23\x30\x4b\x7a\x39\xf9\xf3\xff\x06\x7d\x8d\x8f\x9e\x24\xec\xc7", 16);
    memcpy(ctx.key, "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4", 32);
    rijndael_setup(&ctx, 32, ctx.key);

    memcpy(in, "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a", 16);
    rijndael_encrypt(&ctx, in, out);
    CU_ASSERT(memcmp(out, expected_out1, 16) == 0);

    memcpy(in, "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51", 16);
    rijndael_encrypt(&ctx, in, out);
    CU_ASSERT(memcmp(out, expected_out2, 16) == 0);

    memcpy(in, "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef", 16);
    rijndael_encrypt(&ctx, in, out);
    CU_ASSERT(memcmp(out, expected_out3, 16) == 0);

    memcpy(in, "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10", 16);
    rijndael_encrypt(&ctx, in, out);
    CU_ASSERT(memcmp(out, expected_out4, 16) == 0);

}

DECLARE_UTEST(test_aes_cbc_128, "aes cbc 128 test vectors") //http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors#aes-cbc-128
{  //would like to test rij_encrypt against known test vectors, but the method of generating the key and iv make this impossible.
    RIJNDAEL_context    ctx;
    unsigned char in[1024] = {0};
    unsigned char out[1024] = {0};
    unsigned char expected_out1[1024] = {0};
    unsigned char expected_out2[1024] = {0};
    unsigned char expected_out3[1024] = {0};
    unsigned char expected_out4[1024] = {0};

    memcpy(ctx.key, "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c", 16);
    memcpy(expected_out1, "\x76\x49\xab\xac\x81\x19\xb2\x46\xce\xe9\x8e\x9b\x12\xe9\x19\x7d", 16);
    memcpy(expected_out2, "\x50\x86\xcb\x9b\x50\x72\x19\xee\x95\xdb\x11\x3a\x91\x76\x78\xb2", 16);
    memcpy(expected_out3, "\x73\xbe\xd6\xb8\xe3\xc1\x74\x3b\x71\x16\xe6\x9e\x22\x22\x95\x16", 16);
    memcpy(expected_out4, "\x3f\xf1\xca\xa1\x68\x1f\xac\x09\x12\x0e\xca\x30\x75\x86\xe1\xa7", 16);
    ctx.mode = MODE_CBC;
    rijndael_setup(&ctx, 16, ctx.key);

    memcpy(ctx.iv, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F", 16);
    memcpy(in, "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a", 16);
    block_encrypt(&ctx, in, 16, out, ctx.iv);
    CU_ASSERT(memcmp(out, expected_out1, 16) == 0);

    memcpy(ctx.iv, "\x76\x49\xAB\xAC\x81\x19\xB2\x46\xCE\xE9\x8E\x9B\x12\xE9\x19\x7D", 16);
    memcpy(in, "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51", 16);
    block_encrypt(&ctx, in, 16, out, ctx.iv);
    CU_ASSERT(memcmp(out, expected_out2, 16) == 0);

    memcpy(ctx.iv, "\x50\x86\xCB\x9B\x50\x72\x19\xEE\x95\xDB\x11\x3A\x91\x76\x78\xB2", 16);
    memcpy(in, "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef", 16);
    block_encrypt(&ctx, in, 16, out, ctx.iv);
    CU_ASSERT(memcmp(out, expected_out3, 16) == 0);

    memcpy(ctx.iv, "\x73\xBE\xD6\xB8\xE3\xC1\x74\x3B\x71\x16\xE6\x9E\x22\x22\x95\x16", 16);
    memcpy(in, "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10", 16);
    block_encrypt(&ctx, in, 16, out, ctx.iv);
    CU_ASSERT(memcmp(out, expected_out4, 16) == 0);


}

DECLARE_UTEST(test_aes_cbc_192, "aes cbc 192 test vectors") //http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors#aes-cbc-128
{  //would like to test rij_encrypt against known test vectors, but the method of generating the key and iv make this impossible.
    RIJNDAEL_context    ctx;
    unsigned char in[1024] = {0};
    unsigned char out[1024] = {0};
    unsigned char expected_out1[1024] = {0};
    unsigned char expected_out2[1024] = {0};
    unsigned char expected_out3[1024] = {0};
    unsigned char expected_out4[1024] = {0};

    memcpy(ctx.key, "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b", 24);
    memcpy(expected_out1, "\x4f\x02\x1d\xb2\x43\xbc\x63\x3d\x71\x78\x18\x3a\x9f\xa0\x71\xe8", 16);
    memcpy(expected_out2, "\xb4\xd9\xad\xa9\xad\x7d\xed\xf4\xe5\xe7\x38\x76\x3f\x69\x14\x5a", 16);
    memcpy(expected_out3, "\x57\x1b\x24\x20\x12\xfb\x7a\xe0\x7f\xa9\xba\xac\x3d\xf1\x02\xe0", 16);
    memcpy(expected_out4, "\x08\xb0\xe2\x79\x88\x59\x88\x81\xd9\x20\xa9\xe6\x4f\x56\x15\xcd", 16);
    ctx.mode = MODE_CBC;
    rijndael_setup(&ctx, 24, ctx.key);

    memcpy(ctx.iv, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F", 16);
    memcpy(in, "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a", 16);
    block_encrypt(&ctx, in, 16, out, ctx.iv);
    CU_ASSERT(memcmp(out, expected_out1, 16) == 0);

    memcpy(ctx.iv, out, 16);
    memcpy(in, "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51", 16);
    block_encrypt(&ctx, in, 16, out, ctx.iv);
    CU_ASSERT(memcmp(out, expected_out2, 16) == 0);

    memcpy(ctx.iv, out, 16);
    memcpy(in, "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef", 16);
    block_encrypt(&ctx, in, 16, out, ctx.iv);
    CU_ASSERT(memcmp(out, expected_out3, 16) == 0);

    memcpy(ctx.iv, out, 16);
    memcpy(in, "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10", 16);
    block_encrypt(&ctx, in, 16, out, ctx.iv);
    CU_ASSERT(memcmp(out, expected_out4, 16) == 0);


}

DECLARE_UTEST(test_aes_cbc_256, "aes cbc 256 test vectors") //http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors#aes-cbc-128
{  //would like to test rij_encrypt against known test vectors, but the method of generating the key and iv make this impossible.
    RIJNDAEL_context    ctx;
    unsigned char in[1024] = {0};
    unsigned char out[1024] = {0};
    unsigned char expected_out1[1024] = {0};
    unsigned char expected_out2[1024] = {0};
    unsigned char expected_out3[1024] = {0};
    unsigned char expected_out4[1024] = {0};

    memcpy(ctx.key, "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4", 32);
    memcpy(expected_out1, "\xf5\x8c\x4c\x04\xd6\xe5\xf1\xba\x77\x9e\xab\xfb\x5f\x7b\xfb\xd6", 16);
    memcpy(expected_out2, "\x9c\xfc\x4e\x96\x7e\xdb\x80\x8d\x67\x9f\x77\x7b\xc6\x70\x2c\x7d", 16);
    memcpy(expected_out3, "\x39\xf2\x33\x69\xa9\xd9\xba\xcf\xa5\x30\xe2\x63\x04\x23\x14\x61", 16);
    memcpy(expected_out4, "\xb2\xeb\x05\xe2\xc3\x9b\xe9\xfc\xda\x6c\x19\x07\x8c\x6a\x9d\x1b", 16);
    ctx.mode = MODE_CBC;
    rijndael_setup(&ctx, 32, ctx.key);

    memcpy(ctx.iv, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F", 16);
    memcpy(in, "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a", 16);
    block_encrypt(&ctx, in, 16, out, ctx.iv);
    CU_ASSERT(memcmp(out, expected_out1, 16) == 0);

    memcpy(ctx.iv, out, 16);
    memcpy(in, "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51", 16);
    block_encrypt(&ctx, in, 16, out, ctx.iv);
    CU_ASSERT(memcmp(out, expected_out2, 16) == 0);

    memcpy(ctx.iv, out, 16);
    memcpy(in, "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef", 16);
    block_encrypt(&ctx, in, 16, out, ctx.iv);
    CU_ASSERT(memcmp(out, expected_out3, 16) == 0);

    memcpy(ctx.iv, out, 16);
    memcpy(in, "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10", 16);
    block_encrypt(&ctx, in, 16, out, ctx.iv);
    CU_ASSERT(memcmp(out, expected_out4, 16) == 0);


}

int register_ts_aes_test(void)
{
    ts_init(&TEST_SUITE(digest_test), TEST_SUITE_DESCR(digest_test), NULL, NULL);
    ts_add_utest(&TEST_SUITE(digest_test), UTEST_FCT(test_aes_ecb_128), UTEST_DESCR(test_aes_ecb_128));
    ts_add_utest(&TEST_SUITE(digest_test), UTEST_FCT(test_aes_ecb_192), UTEST_DESCR(test_aes_ecb_192));
    ts_add_utest(&TEST_SUITE(digest_test), UTEST_FCT(test_aes_ecb_256), UTEST_DESCR(test_aes_ecb_256));
    ts_add_utest(&TEST_SUITE(digest_test), UTEST_FCT(test_aes_cbc_128), UTEST_DESCR(test_aes_cbc_128));
    ts_add_utest(&TEST_SUITE(digest_test), UTEST_FCT(test_aes_cbc_192), UTEST_DESCR(test_aes_cbc_192));
    ts_add_utest(&TEST_SUITE(digest_test), UTEST_FCT(test_aes_cbc_256), UTEST_DESCR(test_aes_cbc_256));

    return register_ts(&TEST_SUITE(digest_test));
}
#endif
/***EOF***/
