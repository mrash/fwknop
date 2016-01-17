/**
 * \file lib/hmac.c
 *
 * \brief Provide HMAC support to SPA communications
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

#include "hmac.h"
#ifdef HAVE_C_UNIT_TESTS
DECLARE_TEST_SUITE(hmac_test, "hmac functions test suite");
#endif

/**
 * /brief populate the inner and outer pads
 *
 *
 */
static void
pad_init(unsigned char *inner_pad, unsigned char *outer_pad,
        const unsigned char * const key, const int key_len)
{
    int i = 0;

    for (i=0; i < MAX_DIGEST_BLOCK_LEN && i < key_len; i++) {
        inner_pad[i] = key[i] ^ 0x36;
        outer_pad[i] = key[i] ^ 0x5c;
    }

    if(i < MAX_DIGEST_BLOCK_LEN)
    {
        while(i < MAX_DIGEST_BLOCK_LEN)
        {
            inner_pad[i] = 0x36;
            outer_pad[i] = 0x5c;
            i++;
        }
    }
    return;
}

int
hmac_md5(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key, const int hmac_key_len)
{
    unsigned char inner_hash[MD5_DIGEST_LEN] = {0};
    unsigned char block_inner_pad[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char block_outer_pad[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char final_key[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char padded_hash[MD5_BLOCK_LEN + MD5_DIGEST_LEN + 1] = {0};
    unsigned char *padded_msg = calloc(1, msg_len + MAX_DIGEST_BLOCK_LEN + 1);
    int final_len = hmac_key_len;

    if (padded_msg == NULL)
        return FKO_ERROR_MEMORY_ALLOCATION;
	
    if(MD5_BLOCK_LEN < hmac_key_len)
    {
        /* Calculate the digest of the key
        */
        md5(final_key, (unsigned char *)hmac_key, final_len);
        final_len = MD5_DIGEST_LEN;
    }
    else
    {
        memcpy(final_key, hmac_key, hmac_key_len);
    }
    pad_init(block_inner_pad, block_outer_pad, final_key, final_len);

    //The first step is to hash the inner_pad + message
    memcpy(padded_msg, block_inner_pad, MD5_BLOCK_LEN);
    memcpy(padded_msg + MD5_BLOCK_LEN, msg, msg_len);

    //Calculate the inner hash
    md5(inner_hash, padded_msg, msg_len + MD5_BLOCK_LEN);

    //Then hash the outer pad + inner hash
    memcpy(padded_hash, block_outer_pad, MD5_BLOCK_LEN);
    memcpy(padded_hash + MD5_BLOCK_LEN, inner_hash, MD5_DIGEST_LEN);

    //the outer hash is the final hmac
    md5(hmac, padded_hash, MD5_BLOCK_LEN + MD5_DIGEST_LEN);

    free(padded_msg);
    return FKO_SUCCESS;
}

int
hmac_sha1(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key, const int hmac_key_len)
{
    unsigned char inner_hash[SHA1_DIGEST_LEN] = {0};
    unsigned char block_inner_pad[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char block_outer_pad[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char final_key[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char padded_hash[SHA1_BLOCK_LEN + SHA1_DIGEST_LEN + 1] = {0};
    unsigned char *padded_msg = calloc(1, msg_len + MAX_DIGEST_BLOCK_LEN + 1);
    int final_len = hmac_key_len;

    if (padded_msg == NULL)
        return FKO_ERROR_MEMORY_ALLOCATION;

    if(SHA1_BLOCK_LEN < hmac_key_len)
    {
        /* Calculate the digest of the key
        */
        sha1(final_key, (unsigned char *)hmac_key, final_len);
        final_len = SHA1_DIGEST_LEN;
    }
    else
    {
        memcpy(final_key, hmac_key, hmac_key_len);
    }
    pad_init(block_inner_pad, block_outer_pad, final_key, final_len);

    //The first step is to hash the inner_pad + message
    memcpy(padded_msg, block_inner_pad, SHA1_BLOCK_LEN);
    memcpy(padded_msg + SHA1_BLOCK_LEN, msg, msg_len);

    //Calculate the inner hash
    sha1(inner_hash, padded_msg, msg_len + SHA1_BLOCK_LEN);

    //Then hash the outer pad + inner hash
    memcpy(padded_hash, block_outer_pad, SHA1_BLOCK_LEN);
    memcpy(padded_hash + SHA1_BLOCK_LEN, inner_hash, SHA1_DIGEST_LEN);

    //the outer hash is the final hmac
    sha1(hmac, padded_hash, SHA1_BLOCK_LEN + SHA1_DIGEST_LEN);

    free(padded_msg);
    return FKO_SUCCESS;
}

int
hmac_sha256(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key, const int hmac_key_len)
{
    unsigned char inner_hash[SHA256_DIGEST_LEN] = {0};
    unsigned char block_inner_pad[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char block_outer_pad[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char final_key[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char padded_hash[SHA256_BLOCK_LEN + SHA256_DIGEST_LEN + 1] = {0};
    unsigned char *padded_msg = calloc(1, msg_len + MAX_DIGEST_BLOCK_LEN + 1);
    int final_len = hmac_key_len;

    if (padded_msg == NULL)
        return FKO_ERROR_MEMORY_ALLOCATION;

    if(SHA256_BLOCK_LEN < hmac_key_len)
    {
        /* Calculate the digest of the key
        */
        sha256(final_key, (unsigned char *)hmac_key, final_len);
        final_len = SHA256_DIGEST_LEN;
    }
    else
    {
        memcpy(final_key, hmac_key, hmac_key_len);
    }
    pad_init(block_inner_pad, block_outer_pad, final_key, final_len);

    //The first step is to hash the inner_pad + message
    memcpy(padded_msg, block_inner_pad, SHA256_BLOCK_LEN);
    memcpy(padded_msg + SHA256_BLOCK_LEN, msg, msg_len);

    //Calculate the inner hash
    sha256(inner_hash, padded_msg, msg_len + SHA256_BLOCK_LEN);

    //Then hash the outer pad + inner hash
    memcpy(padded_hash, block_outer_pad, SHA256_BLOCK_LEN);
    memcpy(padded_hash + SHA256_BLOCK_LEN, inner_hash, SHA256_DIGEST_LEN);

    //the outer hash is the final hmac
    sha256(hmac, padded_hash, SHA256_BLOCK_LEN + SHA256_DIGEST_LEN);

    free(padded_msg);
    return FKO_SUCCESS;
}

int
hmac_sha384(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key, const int hmac_key_len)
{
    unsigned char inner_hash[SHA384_DIGEST_LEN] = {0};
    unsigned char block_inner_pad[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char block_outer_pad[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char final_key[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char padded_hash[SHA384_BLOCK_LEN + SHA384_DIGEST_LEN + 1] = {0};
    unsigned char *padded_msg = calloc(1, msg_len + MAX_DIGEST_BLOCK_LEN + 1);
    int final_len = hmac_key_len;

    if (padded_msg == NULL)
        return FKO_ERROR_MEMORY_ALLOCATION;

    if(SHA384_BLOCK_LEN < hmac_key_len)
    {
        /* Calculate the digest of the key
        */
        sha384(final_key, (unsigned char *)hmac_key, final_len);
        final_len = SHA384_DIGEST_LEN;
    }
    else
    {
        memcpy(final_key, hmac_key, hmac_key_len);
    }
    pad_init(block_inner_pad, block_outer_pad, final_key, final_len);

    //The first step is to hash the inner_pad + message
    memcpy(padded_msg, block_inner_pad, SHA384_BLOCK_LEN);
    memcpy(padded_msg + SHA384_BLOCK_LEN, msg, msg_len);

    //Calculate the inner hash
    sha384(inner_hash, padded_msg, msg_len + SHA384_BLOCK_LEN);

    //Then hash the outer pad + inner hash
    memcpy(padded_hash, block_outer_pad, SHA384_BLOCK_LEN);
    memcpy(padded_hash + SHA384_BLOCK_LEN, inner_hash, SHA384_DIGEST_LEN);

    //the outer hash is the final hmac
    sha384(hmac, padded_hash, SHA384_BLOCK_LEN + SHA384_DIGEST_LEN);

    free(padded_msg);
    return FKO_SUCCESS;
}

int
hmac_sha512(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key, const int hmac_key_len)
{
    unsigned char inner_hash[SHA512_DIGEST_LEN] = {0};
    unsigned char block_inner_pad[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char block_outer_pad[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char final_key[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char padded_hash[SHA512_BLOCK_LEN + SHA512_DIGEST_LEN + 1] = {0};
    unsigned char *padded_msg = calloc(1, msg_len + MAX_DIGEST_BLOCK_LEN + 1);
    int final_len = hmac_key_len;

    if (padded_msg == NULL)
        return FKO_ERROR_MEMORY_ALLOCATION;

    if(SHA512_BLOCK_LEN < hmac_key_len)
    {
        /* Calculate the digest of the key
        */
        sha512(final_key, (unsigned char *)hmac_key, final_len);
        final_len = SHA512_DIGEST_LEN;
    }
    else
    {
        memcpy(final_key, hmac_key, hmac_key_len);
    }
    pad_init(block_inner_pad, block_outer_pad, final_key, final_len);

    //The first step is to hash the inner_pad + message
    memcpy(padded_msg, block_inner_pad, SHA512_BLOCK_LEN);
    memcpy(padded_msg + SHA512_BLOCK_LEN, msg, msg_len);

    //Calculate the inner hash
    sha512(inner_hash, padded_msg, msg_len + SHA512_BLOCK_LEN);

    //Then hash the outer pad + inner hash
    memcpy(padded_hash, block_outer_pad, SHA512_BLOCK_LEN);
    memcpy(padded_hash + SHA512_BLOCK_LEN, inner_hash, SHA512_DIGEST_LEN);

    //the outer hash is the final hmac
    sha512(hmac, padded_hash, SHA512_BLOCK_LEN + SHA512_DIGEST_LEN);

    free(padded_msg);
    return FKO_SUCCESS;
}

int
hmac_sha3_256(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key, const int hmac_key_len)
{
    unsigned char inner_hash[SHA3_256_DIGEST_LEN] = {0};
    unsigned char block_inner_pad[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char block_outer_pad[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char final_key[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char padded_hash[SHA3_256_BLOCK_LEN + SHA3_256_DIGEST_LEN + 1] = {0};
    unsigned char *padded_msg = calloc(1, msg_len + MAX_DIGEST_BLOCK_LEN + 1);
    int final_len = hmac_key_len;

    if (padded_msg == NULL)
        return FKO_ERROR_MEMORY_ALLOCATION;

    if(SHA3_256_BLOCK_LEN < hmac_key_len)
    {
        /* Calculate the digest of the key
        */
        FIPS202_SHA3_256((unsigned char *)hmac_key, final_len, final_key);
        final_len = SHA3_256_DIGEST_LEN;
    }
    else
    {
        memcpy(final_key, hmac_key, hmac_key_len);
    }
    pad_init(block_inner_pad, block_outer_pad, final_key, final_len);

    //The first step is to hash the inner_pad + message
    memcpy(padded_msg, block_inner_pad, SHA3_256_BLOCK_LEN);
    memcpy(padded_msg + SHA3_256_BLOCK_LEN, msg, msg_len);

    //Calculate the inner hash
    FIPS202_SHA3_256(padded_msg, msg_len + SHA3_256_BLOCK_LEN, inner_hash);

    //Then hash the outer pad + inner hash
    memcpy(padded_hash, block_outer_pad, SHA3_256_BLOCK_LEN);
    memcpy(padded_hash + SHA3_256_BLOCK_LEN, inner_hash, SHA3_256_DIGEST_LEN);

    //the outer hash is the final hmac
    FIPS202_SHA3_256(padded_hash, SHA3_256_BLOCK_LEN + SHA3_256_DIGEST_LEN, hmac);

    free(padded_msg);
    return FKO_SUCCESS;
}

int
hmac_sha3_512(const char *msg, const unsigned int msg_len,
    unsigned char *hmac, const char *hmac_key, const int hmac_key_len)
{
    unsigned char inner_hash[SHA3_512_DIGEST_LEN] = {0};
    unsigned char block_inner_pad[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char block_outer_pad[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char final_key[MAX_DIGEST_BLOCK_LEN] = {0};
    unsigned char padded_hash[SHA3_512_BLOCK_LEN + SHA3_512_DIGEST_LEN + 1] = {0};
    unsigned char *padded_msg = calloc(1, msg_len + MAX_DIGEST_BLOCK_LEN + 1);
    int final_len = hmac_key_len;

    if (padded_msg == NULL)
        return FKO_ERROR_MEMORY_ALLOCATION;

    if(SHA3_512_BLOCK_LEN < hmac_key_len)
    {
        /* Calculate the digest of the key
        */
        FIPS202_SHA3_512((unsigned char *)hmac_key, final_len, final_key);
        final_len = SHA3_512_DIGEST_LEN;
    }
    else
    {
        memcpy(final_key, hmac_key, hmac_key_len);
    }
    pad_init(block_inner_pad, block_outer_pad, final_key, final_len);

    //The first step is to hash the inner_pad + message
    memcpy(padded_msg, block_inner_pad, SHA3_512_BLOCK_LEN);
    memcpy(padded_msg + SHA3_512_BLOCK_LEN, msg, msg_len);

    //Calculate the inner hash
    FIPS202_SHA3_512(padded_msg, msg_len + SHA3_512_BLOCK_LEN, inner_hash);

    //Then hash the outer pad + inner hash
    memcpy(padded_hash, block_outer_pad, SHA3_512_BLOCK_LEN);
    memcpy(padded_hash + SHA3_512_BLOCK_LEN, inner_hash, SHA3_512_DIGEST_LEN);

    //the outer hash is the final hmac
    FIPS202_SHA3_512(padded_hash, SHA3_512_BLOCK_LEN + SHA3_512_DIGEST_LEN, hmac);

    free(padded_msg);
    return FKO_SUCCESS;
}

#ifdef HAVE_C_UNIT_TESTS

DECLARE_UTEST(test_hmac_md5, "hmac_md5 test vectors") // https://tools.ietf.org/html/rfc2202
{
    char msg[1024] = {0};
    unsigned char hmac[1024] = {0};
    char hmac_txt[1024] = {0};
    char hmac_key[1024] = {0};
    char expected_hmac1[1024] = {0};
    char expected_hmac2[1024] = {0};
    char expected_hmac3[1024] = {0};
    char expected_hmac4[1024] = {0};
    char expected_hmac5[1024] = {0};
    char expected_hmac6[1024] = {0};
    char expected_hmac7[1024] = {0};
    int msg_len, key_len;
    int i = 0;

    //vector 1
    for ( i = 0; i < 16; i++)
    {
        hmac_key[i] = 0x0b;
    }
    key_len = 16;
    strcpy(msg, "Hi There");
    msg_len = 8;
    strcpy(expected_hmac1, "9294727a3638bb1c13f48ef8158bfc9d");

    hmac_md5(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < MD5_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac1, MD5_DIGEST_LEN) == 0);

    //vector 2
    strcpy(hmac_key, "Jefe");
    key_len = 4;
    strcpy(msg, "what do ya want for nothing?");
    msg_len = 28;
    strcpy(expected_hmac2, "750c783e6ab0b503eaa86e310a5db738");

    hmac_md5(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac2, MD5_DIGEST_LEN) == 0);

    //vector 3
    for ( i = 0; i < 16; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 16;
    for ( i = 0; i < 50; i++)
    {
        msg[i] = 0xdd;
    }
    msg_len = 50;
    strcpy(expected_hmac3, "56be34521d144c88dbb8c733f0e8b3f6");

    hmac_md5(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac3, MD5_DIGEST_LEN) == 0);

    //vector 4
    strcpy(hmac_key, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19");
    key_len = 25;
    for ( i = 0; i < 50; i++)
    {
        msg[i] = 0xcd;
    }
    msg_len = 50;
    strcpy(expected_hmac4, "697eaf0aca3a3aea3a75164746ffaa79");

    hmac_md5(msg, 50, (unsigned char *)hmac, hmac_key, strlen(hmac_key));

    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac4, MD5_DIGEST_LEN) == 0);

    //vector 5
    for ( i = 0; i < 16; i++)
    {
        hmac_key[i] = 0x0c;
    }
    key_len = 16;
    strcpy(msg, "Test With Truncation");
    msg_len = 20;
    strcpy(expected_hmac5, "56461ef2342edc00f9bab995690efd4c");

    hmac_md5(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);
    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac5, MD5_DIGEST_LEN) == 0);

    //vector 6
    for ( i = 0; i < 80; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 80;
    strcpy(msg, "Test Using Larger Than Block-Size Key - Hash Key First");
    msg_len = 54;
    strcpy(expected_hmac6, "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd");

    hmac_md5(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);
    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac6, MD5_DIGEST_LEN) == 0);

    //vector 7
    for ( i = 0; i < 80; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 80;
    strcpy(msg, "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data");
    msg_len = 73;
    strcpy(expected_hmac7, "6f630fad67cda0ee1fb1f562db3aa53e");

    hmac_md5(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);
    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac7, MD5_DIGEST_LEN) == 0);

}

DECLARE_UTEST(test_hmac_sha1, "hmac_sha1 test vectors") // https://tools.ietf.org/html/rfc2202
{
    char msg[1024] = {0};
    unsigned char hmac[1024] = {0};
    char hmac_txt[1024] = {0};
    char hmac_key[1024] = {0};
    char expected_hmac1[1024] = {0};
    char expected_hmac2[1024] = {0};
    char expected_hmac3[1024] = {0};
    char expected_hmac4[1024] = {0};
    char expected_hmac5[1024] = {0};
    char expected_hmac6[1024] = {0};
    char expected_hmac7[1024] = {0};
    int msg_len, key_len;
    int i = 0;

    //vector 1
    for ( i = 0; i < 20; i++)
    {
        hmac_key[i] = 0x0b;
    }
    key_len = 20;
    strcpy(msg, "Hi There");
    msg_len = 8;
    strcpy(expected_hmac1, "b617318655057264e28bc0b6fb378c8ef146be00");

    hmac_sha1(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA1_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac1, SHA1_DIGEST_LEN) == 0);

    //vector 2
    strcpy(hmac_key, "Jefe");
    key_len = 4;
    strcpy(msg, "what do ya want for nothing?");
    msg_len = 28;
    strcpy(expected_hmac2, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");

    hmac_sha1(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA1_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac2, SHA1_DIGEST_LEN) == 0);

    //vector 3
    for ( i = 0; i < 20; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 20;
    for ( i = 0; i < 50; i++)
    {
        msg[i] = 0xdd;
    }
    msg_len = 50;
    strcpy(expected_hmac3, "125d7342b9ac11cd91a39af48aa17b4f63f175d3");

    hmac_sha1(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA1_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac3, SHA1_DIGEST_LEN) == 0);

    //vector 4
    strcpy(hmac_key, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19");
    key_len = 25;
    for ( i = 0; i < 50; i++)
    {
        msg[i] = 0xcd;
    }
    msg_len = 50;
    strcpy(expected_hmac4, "4c9007f4026250c6bc8414f9bf50c86c2d7235da");

    hmac_sha1(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA1_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac4, SHA1_DIGEST_LEN) == 0);

    //vector 5
    for ( i = 0; i < 20; i++)
    {
        hmac_key[i] = 0x0c;
    }
    key_len = 20;
    strcpy(msg, "Test With Truncation");
    msg_len = 20;
    strcpy(expected_hmac5, "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04");

    hmac_sha1(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA1_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac5, SHA1_DIGEST_LEN) == 0);

    //vector 6
    for ( i = 0; i < 80; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 80;
    strcpy(msg, "Test Using Larger Than Block-Size Key - Hash Key First");
    msg_len = 54;
    strcpy(expected_hmac6, "aa4ae5e15272d00e95705637ce8a3b55ed402112");

    hmac_sha1(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA1_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac6, SHA1_DIGEST_LEN) == 0);

    //vector 7
    for ( i = 0; i < 80; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 80;
    strcpy(msg, "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data");
    msg_len = 73;
    strcpy(expected_hmac7, "e8e99d0f45237d786d6bbaa7965c7808bbff1a91");

    hmac_sha1(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA1_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac7, SHA1_DIGEST_LEN) == 0);
}

DECLARE_UTEST(test_hmac_sha256, "hmac_sha256 test vectors") // https://tools.ietf.org/html/rfc4231
{
    char msg[1024] = {0};
    unsigned char hmac[1024] = {0};
    char hmac_txt[1024] = {0};
    char hmac_key[1024] = {0};
    char expected_hmac1[1024] = {0};
    char expected_hmac2[1024] = {0};
    char expected_hmac3[1024] = {0};
    char expected_hmac4[1024] = {0};
    char expected_hmac5[1024] = {0};
    char expected_hmac6[1024] = {0};
    char expected_hmac7[1024] = {0};
    int msg_len, key_len;
    int i = 0;

    //vector 1
    for ( i = 0; i < 20; i++)
    {
        hmac_key[i] = 0x0b;
    }
    key_len = 20;
    strcpy(msg, "Hi There");
    msg_len = 8;
    strcpy(expected_hmac1, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    hmac_sha256(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac1, SHA256_DIGEST_LEN) == 0);

    //vector 2
    strcpy(hmac_key, "Jefe");
    key_len = 4;
    strcpy(msg, "what do ya want for nothing?");
    msg_len = 28;
    strcpy(expected_hmac2, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    hmac_sha256(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac2, SHA256_DIGEST_LEN) == 0);

    //vector 3
    for ( i = 0; i < 20; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 20;
    for ( i = 0; i < 50; i++)
    {
        msg[i] = 0xdd;
    }
    msg_len = 50;
    strcpy(expected_hmac3, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    hmac_sha256(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac3, SHA256_DIGEST_LEN) == 0);

    //vector 4
    strcpy(hmac_key, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19");
    key_len = 25;
    for ( i = 0; i < 50; i++)
    {
        msg[i] = 0xcd;
    }
    msg_len = 50;
    strcpy(expected_hmac4, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");

    hmac_sha256(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac4, SHA256_DIGEST_LEN) == 0);

    //vector 5
    for ( i = 0; i < 20; i++)
    {
        hmac_key[i] = 0x0c;
    }
    key_len = 20;
    strcpy(msg, "Test With Truncation");
    msg_len = 20;
    strcpy(expected_hmac5, "a3b6167473100ee06e0c796c2955552b");

    hmac_sha256(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < 16; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac5, 16) == 0); //test specifies truncated output

    //vector 6
    for ( i = 0; i < 131; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 131;
    strcpy(msg, "Test Using Larger Than Block-Size Key - Hash Key First");
    msg_len = 54;
    strcpy(expected_hmac6, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

    hmac_sha256(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac6, SHA256_DIGEST_LEN) == 0);

    //vector 7
    for ( i = 0; i < 131; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 131;
    strcpy(msg, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.");
    msg_len = strlen(msg);
    strcpy(expected_hmac7, "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");

    hmac_sha256(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac7, SHA256_DIGEST_LEN) == 0);
}

DECLARE_UTEST(test_hmac_sha384, "hmac_sha384 test vectors")
{
    char msg[1024] = {0};
    unsigned char hmac[1024] = {0};
    char hmac_txt[1024] = {0};
    char hmac_key[1024] = {0};
    char expected_hmac1[1024] = {0};
    char expected_hmac2[1024] = {0};
    char expected_hmac3[1024] = {0};
    char expected_hmac4[1024] = {0};
    char expected_hmac5[1024] = {0};
    char expected_hmac6[1024] = {0};
    char expected_hmac7[1024] = {0};
    int msg_len, key_len;
    int i = 0;

    //vector 1
    for ( i = 0; i < 20; i++)
    {
        hmac_key[i] = 0x0b;
    }
    key_len = 20;
    strcpy(msg, "Hi There");
    msg_len = 8;
    strcpy(expected_hmac1, "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");

    hmac_sha384(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA384_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac1, SHA384_DIGEST_LEN) == 0);

    //vector 2
    strcpy(hmac_key, "Jefe");
    key_len = 4;
    strcpy(msg, "what do ya want for nothing?");
    msg_len = 28;
    strcpy(expected_hmac2, "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649");

    hmac_sha384(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA384_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac2, SHA384_DIGEST_LEN) == 0);

    //vector 3
    for ( i = 0; i < 20; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 20;
    for ( i = 0; i < 50; i++)
    {
        msg[i] = 0xdd;
    }
    msg_len = 50;
    strcpy(expected_hmac3, "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27");

    hmac_sha384(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA384_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac3, SHA384_DIGEST_LEN) == 0);

    //vector 4
    strcpy(hmac_key, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19");
    key_len = 25;
    for ( i = 0; i < 50; i++)
    {
        msg[i] = 0xcd;
    }
    msg_len = 50;
    strcpy(expected_hmac4, "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb");

    hmac_sha384(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA384_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac4, SHA384_DIGEST_LEN) == 0);

    //vector 5
    for ( i = 0; i < 20; i++)
    {
        hmac_key[i] = 0x0c;
    }
    key_len = 20;
    strcpy(msg, "Test With Truncation");
    msg_len = 20;
    strcpy(expected_hmac5, "3abf34c3503b2a23a46efc619baef897");

    hmac_sha384(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < 16; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac5, 16) == 0); //test specifies truncated output

    //vector 6
    for ( i = 0; i < 131; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 131;
    strcpy(msg, "Test Using Larger Than Block-Size Key - Hash Key First");
    msg_len = 54;
    strcpy(expected_hmac6, "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952");

    hmac_sha384(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA384_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac6, SHA384_DIGEST_LEN) == 0);

    //vector 7
    for ( i = 0; i < 131; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 131;
    strcpy(msg, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.");
    msg_len = strlen(msg);
    strcpy(expected_hmac7, "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e");

    hmac_sha384(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA384_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac7, SHA384_DIGEST_LEN) == 0);
}

DECLARE_UTEST(test_hmac_sha512, "hmac_sha512 test vectors")
{
    char msg[1024] = {0};
    unsigned char hmac[1024] = {0};
    char hmac_txt[1024] = {0};
    char hmac_key[1024] = {0};
    char expected_hmac1[1024] = {0};
    char expected_hmac2[1024] = {0};
    char expected_hmac3[1024] = {0};
    char expected_hmac4[1024] = {0};
    char expected_hmac5[1024] = {0};
    char expected_hmac6[1024] = {0};
    char expected_hmac7[1024] = {0};
    int msg_len, key_len;
    int i = 0;

    //vector 1
    for ( i = 0; i < 20; i++)
    {
        hmac_key[i] = 0x0b;
    }
    key_len = 20;
    strcpy(msg, "Hi There");
    msg_len = 8;
    strcpy(expected_hmac1, "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");

    hmac_sha512(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA512_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac1, SHA512_DIGEST_LEN) == 0);

    //vector 2
    strcpy(hmac_key, "Jefe");
    key_len = 4;
    strcpy(msg, "what do ya want for nothing?");
    msg_len = 28;
    strcpy(expected_hmac2, "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");

    hmac_sha512(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA512_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac2, SHA512_DIGEST_LEN) == 0);

    //vector 3
    for ( i = 0; i < 20; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 20;
    for ( i = 0; i < 50; i++)
    {
        msg[i] = 0xdd;
    }
    msg_len = 50;
    strcpy(expected_hmac3, "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb");

    hmac_sha512(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA512_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac3, SHA512_DIGEST_LEN) == 0);

    //vector 4
    strcpy(hmac_key, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19");
    key_len = 25;
    for ( i = 0; i < 50; i++)
    {
        msg[i] = 0xcd;
    }
    msg_len = 50;
    strcpy(expected_hmac4, "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd");

    hmac_sha512(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA512_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac4, SHA512_DIGEST_LEN) == 0);

    //vector 5
    for ( i = 0; i < 20; i++)
    {
        hmac_key[i] = 0x0c;
    }
    key_len = 20;
    strcpy(msg, "Test With Truncation");
    msg_len = 20;
    strcpy(expected_hmac5, "415fad6271580a531d4179bc891d87a6");

    hmac_sha512(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < 16; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac5, 16) == 0); //test specifies truncated output

    //vector 6
    for ( i = 0; i < 131; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 131;
    strcpy(msg, "Test Using Larger Than Block-Size Key - Hash Key First");
    msg_len = 54;
    strcpy(expected_hmac6, "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598");

    hmac_sha512(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA512_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac6, SHA512_DIGEST_LEN) == 0);

    //vector 7
    for ( i = 0; i < 131; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 131;
    strcpy(msg, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.");
    msg_len = strlen(msg);
    strcpy(expected_hmac7, "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58");

    hmac_sha512(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA512_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac7, SHA512_DIGEST_LEN) == 0);
}

DECLARE_UTEST(test_hmac_sha3_256, "hmac_sha3_256 test vectors") //http://wolfgang-ehrhardt.de/hmac-sha3-testvectors.html
{
    char msg[1024] = {0};
    unsigned char hmac[1024] = {0};
    char hmac_txt[1024] = {0};
    char hmac_key[1024] = {0};
    char expected_hmac1[1024] = {0};
    char expected_hmac2[1024] = {0};
    char expected_hmac3[1024] = {0};
    char expected_hmac4[1024] = {0};
    char expected_hmac5[1024] = {0};
    char expected_hmac6[1024] = {0};
    char expected_hmac6a[1024] = {0};
    char expected_hmac7[1024] = {0};
    char expected_hmac7a[1024] = {0};
    int msg_len, key_len;
    int i = 0;

    //vector 1
    for ( i = 0; i < 20; i++)
    {
        hmac_key[i] = 0x0b;
    }
    key_len = 20;
    strcpy(msg, "Hi There");
    msg_len = 8;
    strcpy(expected_hmac1, "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb");

    hmac_sha3_256(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac1, SHA3_256_DIGEST_LEN) == 0);

    //vector 2
    strcpy(hmac_key, "Jefe");
    key_len = 4;
    strcpy(msg, "what do ya want for nothing?");
    msg_len = 28;
    strcpy(expected_hmac2, "c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5");

    hmac_sha3_256(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac2, SHA3_256_DIGEST_LEN) == 0);

    //vector 3
    for ( i = 0; i < 20; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 20;
    for ( i = 0; i < 50; i++)
    {
        msg[i] = 0xdd;
    }
    msg_len = 50;
    strcpy(expected_hmac3, "84ec79124a27107865cedd8bd82da9965e5ed8c37b0ac98005a7f39ed58a4207");

    hmac_sha3_256(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac3, SHA3_256_DIGEST_LEN) == 0);

    //vector 4
    strcpy(hmac_key, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19");
    key_len = 25;
    for ( i = 0; i < 50; i++)
    {
        msg[i] = 0xcd;
    }
    msg_len = 50;
    strcpy(expected_hmac4, "57366a45e2305321a4bc5aa5fe2ef8a921f6af8273d7fe7be6cfedb3f0aea6d7");

    hmac_sha3_256(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac4, SHA3_256_DIGEST_LEN) == 0);

    //vector 5
    for ( i = 0; i < 20; i++)
    {
        hmac_key[i] = 0x0c;
    }
    key_len = 20;
    strcpy(msg, "Test With Truncation");
    msg_len = 20;
    strcpy(expected_hmac5, "6e02c64537fb118057abb7fb66a23b3c");

    hmac_sha3_256(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac5, 16) == 0); //test specifies truncated output

    //vector 6
    for ( i = 0; i < 131; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 131;
    strcpy(msg, "Test Using Larger Than Block-Size Key - Hash Key First");
    msg_len = 54;
    strcpy(expected_hmac6, "ed73a374b96c005235f948032f09674a58c0ce555cfc1f223b02356560312c3b");

    hmac_sha3_256(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac6, SHA3_256_DIGEST_LEN) == 0);

    //vector 6a
    for ( i = 0; i < 147; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 147;
    strcpy(msg, "Test Using Larger Than Block-Size Key - Hash Key First");
    msg_len = 54;
    strcpy(expected_hmac6a, "a6072f86de52b38bb349fe84cd6d97fb6a37c4c0f62aae93981193a7229d3467");

    hmac_sha3_256(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac6a, SHA3_256_DIGEST_LEN) == 0);

    //vector 7
    for ( i = 0; i < 131; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 131;
    strcpy(msg, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.");
    msg_len = strlen(msg);
    strcpy(expected_hmac7, "65c5b06d4c3de32a7aef8763261e49adb6e2293ec8e7c61e8de61701fc63e123");

    hmac_sha3_256(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac7, SHA3_256_DIGEST_LEN) == 0);

    //vector 7a
    for ( i = 0; i < 147; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 147;
    strcpy(msg, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.");
    msg_len = strlen(msg);
    strcpy(expected_hmac7a, "e6a36d9b915f86a093cac7d110e9e04cf1d6100d30475509c2475f571b758b5a");

    hmac_sha3_256(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac7a, SHA3_256_DIGEST_LEN) == 0);
}

DECLARE_UTEST(test_hmac_sha3_512, "hmac_sha3_512 test vectors")
{
    char msg[1024] = {0};
    unsigned char hmac[1024] = {0};
    char hmac_txt[1024] = {0};
    char hmac_key[1024] = {0};
    char expected_hmac1[1024] = {0};
    char expected_hmac2[1024] = {0};
    char expected_hmac3[1024] = {0};
    char expected_hmac4[1024] = {0};
    char expected_hmac5[1024] = {0};
    char expected_hmac6[1024] = {0};
    char expected_hmac6a[1024] = {0};
    char expected_hmac7[1024] = {0};
    char expected_hmac7a[1024] = {0};
    int msg_len, key_len;
    int i = 0;

    //vector 1
    for ( i = 0; i < 20; i++)
    {
        hmac_key[i] = 0x0b;
    }
    key_len = 20;
    strcpy(msg, "Hi There");
    msg_len = 8;
    strcpy(expected_hmac1, "eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e");

    hmac_sha3_512(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA3_512_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac1, SHA3_512_DIGEST_LEN) == 0);

    //vector 2
    strcpy(hmac_key, "Jefe");
    key_len = 4;
    strcpy(msg, "what do ya want for nothing?");
    msg_len = 28;
    strcpy(expected_hmac2, "5a4bfeab6166427c7a3647b747292b8384537cdb89afb3bf5665e4c5e709350b287baec921fd7ca0ee7a0c31d022a95e1fc92ba9d77df883960275beb4e62024");

    hmac_sha3_512(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA3_512_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac2, SHA3_512_DIGEST_LEN) == 0);

    //vector 3
    for ( i = 0; i < 20; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 20;
    for ( i = 0; i < 50; i++)
    {
        msg[i] = 0xdd;
    }
    msg_len = 50;
    strcpy(expected_hmac3, "309e99f9ec075ec6c6d475eda1180687fcf1531195802a99b5677449a8625182851cb332afb6a89c411325fbcbcd42afcb7b6e5aab7ea42c660f97fd8584bf03");

    hmac_sha3_512(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA3_512_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac3, SHA3_512_DIGEST_LEN) == 0);

    //vector 4
    strcpy(hmac_key, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19");
    key_len = 25;
    for ( i = 0; i < 50; i++)
    {
        msg[i] = 0xcd;
    }
    msg_len = 50;
    strcpy(expected_hmac4, "b27eab1d6e8d87461c29f7f5739dd58e98aa35f8e823ad38c5492a2088fa0281993bbfff9a0e9c6bf121ae9ec9bb09d84a5ebac817182ea974673fb133ca0d1d");

    hmac_sha3_512(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA3_512_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac4, SHA3_512_DIGEST_LEN) == 0);

    //vector 5
    for ( i = 0; i < 20; i++)
    {
        hmac_key[i] = 0x0c;
    }
    key_len = 20;
    strcpy(msg, "Test With Truncation");
    msg_len = 20;
    strcpy(expected_hmac5, "0fa7475948f43f48ca0516671e18978c");

    hmac_sha3_512(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < 16; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac5, 16) == 0); //test specifies truncated output

    //vector 6
    for ( i = 0; i < 131; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 131;
    strcpy(msg, "Test Using Larger Than Block-Size Key - Hash Key First");
    msg_len = 54;
    strcpy(expected_hmac6, "00f751a9e50695b090ed6911a4b65524951cdc15a73a5d58bb55215ea2cd839ac79d2b44a39bafab27e83fde9e11f6340b11d991b1b91bf2eee7fc872426c3a4");

    hmac_sha3_512(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA3_512_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac6, SHA3_512_DIGEST_LEN) == 0);

    //vector 6a
    for ( i = 0; i < 147; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 147;
    strcpy(msg, "Test Using Larger Than Block-Size Key - Hash Key First");
    msg_len = 54;
    strcpy(expected_hmac6a, "b14835c819a290efb010ace6d8568dc6b84de60bc49b004c3b13eda763589451e5dd74292884d1bdce64e6b919dd61dc9c56a282a81c0bd14f1f365b49b83a5b");

    hmac_sha3_512(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA3_512_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac6a, SHA3_512_DIGEST_LEN) == 0);

    //vector 7
    for ( i = 0; i < 131; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 131;
    strcpy(msg, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.");
    msg_len = strlen(msg);
    strcpy(expected_hmac7, "38a456a004bd10d32c9ab8336684112862c3db61adcca31829355eaf46fd5c73d06a1f0d13fec9a652fb3811b577b1b1d1b9789f97ae5b83c6f44dfcf1d67eba");

    hmac_sha3_512(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA3_512_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac7, SHA3_512_DIGEST_LEN) == 0);

    //vector 7a
    for ( i = 0; i < 147; i++)
    {
        hmac_key[i] = 0xaa;
    }
    key_len = 147;
    strcpy(msg, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.");
    msg_len = strlen(msg);
    strcpy(expected_hmac7a, "dc030ee7887034f32cf402df34622f311f3e6cf04860c6bbd7fa488674782b4659fdbdf3fd877852885cfe6e22185fe7b2ee952043629bc9d5f3298a41d02c66");

    hmac_sha3_512(msg, msg_len, (unsigned char *)hmac, hmac_key, key_len);

    for ( i = 0; i < SHA3_512_DIGEST_LEN; i++)
    {
        sprintf(hmac_txt + (2 * i), "%02x", hmac[i]);
    }
    CU_ASSERT(memcmp(hmac_txt, expected_hmac7a, SHA3_512_DIGEST_LEN) == 0);
}

int register_ts_hmac_test(void)
{
    ts_init(&TEST_SUITE(hmac_test), TEST_SUITE_DESCR(hmac_test), NULL, NULL);
    ts_add_utest(&TEST_SUITE(hmac_test), UTEST_FCT(test_hmac_md5), UTEST_DESCR(test_hmac_md5));
    ts_add_utest(&TEST_SUITE(hmac_test), UTEST_FCT(test_hmac_sha1), UTEST_DESCR(test_hmac_sha1));
    ts_add_utest(&TEST_SUITE(hmac_test), UTEST_FCT(test_hmac_sha256), UTEST_DESCR(test_hmac_sha256));
    ts_add_utest(&TEST_SUITE(hmac_test), UTEST_FCT(test_hmac_sha384), UTEST_DESCR(test_hmac_sha384));
    ts_add_utest(&TEST_SUITE(hmac_test), UTEST_FCT(test_hmac_sha512), UTEST_DESCR(test_hmac_sha512));
    ts_add_utest(&TEST_SUITE(hmac_test), UTEST_FCT(test_hmac_sha3_256), UTEST_DESCR(test_hmac_sha3_256));
    ts_add_utest(&TEST_SUITE(hmac_test), UTEST_FCT(test_hmac_sha3_512), UTEST_DESCR(test_hmac_sha3_512));

    return register_ts(&TEST_SUITE(hmac_test));
}

#endif /* HAVE_C_UNIT_TESTS */
