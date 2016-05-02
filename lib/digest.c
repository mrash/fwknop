/**
 * \file    lib/digest.c
 *
 * \brief   Roll-up of the digests used by fwknop.
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
 */

#include "fko_common.h"
#include "digest.h"
#include "base64.h"
#ifdef HAVE_C_UNIT_TESTS /* LCOV_EXCL_START */
DECLARE_TEST_SUITE(digest_test, "digest functions test suite");
#endif /* LCOV_EXCL_STOP */
/* Compute MD5 hash on in and store result in out.
*/
void
md5(unsigned char *out, unsigned char *in, size_t size)
{
    MD5Context ctx;

    MD5Init(&ctx);
    MD5Update(&ctx, (unsigned char*)in, size);
    MD5Final(out, &ctx);
}

/* Compute MD5 hash on in and store the base64 string result in out.
*/
void
md5_base64(char *out, unsigned char *in, size_t size)
{
    uint8_t      md[MD5_DIGEST_LEN];

    md5(md, in, size);
    b64_encode(md, out, MD5_DIGEST_LEN);

    strip_b64_eq(out);
}

/* Compute SHA1 hash on in and store result in out.
*/
void
sha1(unsigned char *out, unsigned char *in, size_t size)
{
    SHA1_INFO    sha1_info;

    sha1_init(&sha1_info);
    sha1_update(&sha1_info, (uint8_t*)in, size);
    sha1_final(out, &sha1_info);
}

/* Compute SHA1 hash on in and store the base64 string result in out.
*/
void
sha1_base64(char *out, unsigned char *in, size_t size)
{
    uint8_t       md[SHA1_DIGEST_LEN];

    sha1(md, in, size);
    b64_encode(md, out, SHA1_DIGEST_LEN);

    strip_b64_eq(out);
}

/* Compute SHA256 hash on in and store the hex string result in out.
*/
void
sha256(unsigned char *out, unsigned char *in, size_t size)
{
    SHA256_CTX    sha256_ctx;

    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, (const uint8_t*)in, size);
    SHA256_Final(out, &sha256_ctx);
}

/* Compute SHA256 hash on in and store the base64 string result in out.
*/
void
sha256_base64(char *out, unsigned char *in, size_t size)
{
    uint8_t       md[SHA256_DIGEST_LEN];

    sha256(md, in, size);
    b64_encode(md, out, SHA256_DIGEST_LEN);

    strip_b64_eq(out);
}

/* Compute SHA384 hash on in and store the hex string result in out.
*/
void
sha384(unsigned char *out, unsigned char *in, size_t size)
{
    SHA384_CTX    sha384_ctx;

    SHA384_Init(&sha384_ctx);
    SHA384_Update(&sha384_ctx, (const uint8_t*)in, size);
    SHA384_Final(out, &sha384_ctx);
}

/* Compute SHA384 hash on in and store the base64 string result in out.
*/
void
sha384_base64(char *out, unsigned char *in, size_t size)
{
    uint8_t       md[SHA384_DIGEST_LEN];

    sha384(md, in, size);
    b64_encode(md, out, SHA384_DIGEST_LEN);

    strip_b64_eq(out);
}

/* Compute SHA512 hash on in and store the hex string result in out.
*/
void
sha512(unsigned char *out, unsigned char *in, size_t size)
{
    SHA512_CTX    sha512_ctx;

    SHA512_Init(&sha512_ctx);
    SHA512_Update(&sha512_ctx, (const uint8_t*)in, size);
    SHA512_Final(out, &sha512_ctx);
}

/* Compute SHA512 hash on in and store the base64 string result in out.
*/
void
sha512_base64(char *out, unsigned char *in, size_t size)
{
    uint8_t       md[SHA512_DIGEST_LEN];

    sha512(md, in, size);
    b64_encode(md, out, SHA512_DIGEST_LEN);

    strip_b64_eq(out);
}

void
sha3_256(unsigned char *out, unsigned char *in, size_t size)
{
    FIPS202_SHA3_256(in, size, out);
}

void
sha3_256_base64(char *out, unsigned char *in, size_t size)
{
    uint8_t      md[SHA3_256_DIGEST_LEN];

    FIPS202_SHA3_256(in, size, md);
    b64_encode(md, out, SHA3_256_DIGEST_LEN);

    strip_b64_eq(out);

}
void
sha3_512(unsigned char *out, unsigned char *in, size_t size)
{
    FIPS202_SHA3_512(in, size, out);
}

void
sha3_512_base64(char *out, unsigned char *in, size_t size)
{
    uint8_t      md[SHA3_512_DIGEST_LEN];

    FIPS202_SHA3_512(in, size, md);
    b64_encode(md, out, SHA3_512_DIGEST_LEN);

    strip_b64_eq(out);

}

#ifdef HAVE_C_UNIT_TESTS /* LCOV_EXCL_START */

DECLARE_UTEST(test_md5, "md5 test vectors") //https://tools.ietf.org/html/rfc1321.html
{
    char msg[1024] = {0};
    unsigned char digest[1024] = {0};
    char digest_txt[1024] = {0};
    char expected_digest1[1024] = {0};
    char expected_digest2[1024] = {0};
    char expected_digest3[1024] = {0};
    char expected_digest4[1024] = {0};
    char expected_digest5[1024] = {0};
    char expected_digest6[1024] = {0};
    char expected_digest7[1024] = {0};
    int i = 0;

    strcpy(expected_digest1, "d41d8cd98f00b204e9800998ecf8427e");
    strcpy(expected_digest2, "0cc175b9c0f1b6a831c399e269772661");
    strcpy(expected_digest3, "900150983cd24fb0d6963f7d28e17f72");
    strcpy(expected_digest4, "f96b697d7cb7938d525a2f31aaf161d0");
    strcpy(expected_digest5, "c3fcd3d76192e4007dfb496cca67e13b");
    strcpy(expected_digest6, "d174ab98d277d9f5a5611c2c9f419d9f");
    strcpy(expected_digest7, "57edf4a22be3c955ac49da2e2107b67a");

    strcpy(msg, "");
    md5(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < MD5_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest1, MD5_DIGEST_LEN) == 0);

    strcpy(msg, "a");
    md5(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < MD5_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest2, MD5_DIGEST_LEN) == 0);

    strcpy(msg, "abc");
    md5(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < MD5_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest3, MD5_DIGEST_LEN) == 0);

    strcpy(msg, "message digest");
    md5(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < MD5_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest4, MD5_DIGEST_LEN) == 0);
    strcpy(msg, "abcdefghijklmnopqrstuvwxyz");
    md5(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < MD5_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest5, MD5_DIGEST_LEN) == 0);
    strcpy(msg, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    md5(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < MD5_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest6, MD5_DIGEST_LEN) == 0);
    strcpy(msg, "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
    md5(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < MD5_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest7, MD5_DIGEST_LEN) == 0);

}

DECLARE_UTEST(test_sha1, "sha1 test vectors") //http://www.di-mgt.com.au/sha_testvectors.html
{
    char msg[1024] = {0};
    unsigned char digest[1024] = {0};
    char digest_txt[1024] = {0};
    char expected_digest1[1024] = {0};
    char expected_digest2[1024] = {0};
    char expected_digest3[1024] = {0};
    char expected_digest4[1024] = {0};
    int i = 0;

    strcpy(msg, "abc");
    strcpy(expected_digest1, "a9993e364706816aba3e25717850c26c9cd0d89d");
    sha1(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA1_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest1, SHA1_DIGEST_LEN) == 0);

    strcpy(msg, "");
    strcpy(expected_digest2, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    sha1(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA1_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest2, SHA1_DIGEST_LEN) == 0);

    strcpy(msg, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    strcpy(expected_digest3, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    sha1(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA1_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest3, SHA1_DIGEST_LEN) == 0);

    strcpy(msg, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
    strcpy(expected_digest4, "a49b2446a02c645bf419f995b67091253a04a259");
    sha1(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA1_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest4, SHA1_DIGEST_LEN) == 0);

}
DECLARE_UTEST(test_sha256, "sha-256 test vectors") //http://www.di-mgt.com.au/sha_testvectors.html
{
    char msg[1024] = {0};
    unsigned char digest[1024] = {0};
    char digest_txt[1024] = {0};
    char expected_digest1[1024] = {0};
    char expected_digest2[1024] = {0};
    char expected_digest3[1024] = {0};
    char expected_digest4[1024] = {0};
    int i = 0;

    strcpy(msg, "abc");
    strcpy(expected_digest1, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    sha256(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA256_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest1, SHA256_DIGEST_LEN) == 0);

    strcpy(msg, "");
    strcpy(expected_digest2, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    sha256(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA256_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest2, SHA256_DIGEST_LEN) == 0);

    strcpy(msg, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    strcpy(expected_digest3, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    sha256(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA256_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest3, SHA256_DIGEST_LEN) == 0);

    strcpy(msg, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
    strcpy(expected_digest4, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
    sha256(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA256_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest4, SHA256_DIGEST_LEN) == 0);
}
DECLARE_UTEST(test_sha384, "sha-384 test vectors") //http://www.di-mgt.com.au/sha_testvectors.html
{
    char msg[1024] = {0};
    unsigned char digest[1024] = {0};
    char digest_txt[1024] = {0};
    char expected_digest1[1024] = {0};
    char expected_digest2[1024] = {0};
    char expected_digest3[1024] = {0};
    char expected_digest4[1024] = {0};
    int i = 0;

    strcpy(msg, "abc");
    strcpy(expected_digest1, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    sha384(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA384_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest1, SHA384_DIGEST_LEN) == 0);

    strcpy(msg, "");
    strcpy(expected_digest2, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    sha384(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA384_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest2, SHA384_DIGEST_LEN) == 0);

    strcpy(msg, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    strcpy(expected_digest3, "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");
    sha384(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA384_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest3, SHA384_DIGEST_LEN) == 0);

    strcpy(msg, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
    strcpy(expected_digest4, "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
    sha384(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA384_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest4, SHA384_DIGEST_LEN) == 0);

}
DECLARE_UTEST(test_sha512, "sha-512 test vectors") //http://www.di-mgt.com.au/sha_testvectors.html
{
    char msg[1024] = {0};
    unsigned char digest[1024] = {0};
    char digest_txt[1024] = {0};
    char expected_digest1[1024] = {0};
    char expected_digest2[1024] = {0};
    char expected_digest3[1024] = {0};
    char expected_digest4[1024] = {0};
    int i = 0;

    strcpy(msg, "abc");
    strcpy(expected_digest1, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    sha512(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA512_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest1, SHA512_DIGEST_LEN) == 0);

    strcpy(msg, "");
    strcpy(expected_digest2, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    sha512(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA512_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest2, SHA512_DIGEST_LEN) == 0);

    strcpy(msg, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    strcpy(expected_digest3, "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
    sha512(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA512_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest3, SHA512_DIGEST_LEN) == 0);

    strcpy(msg, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
    strcpy(expected_digest4, "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
    sha512(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA512_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest4, SHA512_DIGEST_LEN) == 0);

}

DECLARE_UTEST(test_sha3_256, "sha3_256 test vectors") //http://www.di-mgt.com.au/sha_testvectors.html
{
    char msg[1024] = {0};
    unsigned char digest[1024] = {0};
    char digest_txt[1024] = {0};
    char expected_digest1[1024] = {0};
    char expected_digest2[1024] = {0};
    char expected_digest3[1024] = {0};
    char expected_digest4[1024] = {0};
    int i = 0;

    strcpy(msg, "abc");
    strcpy(expected_digest1, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    sha3_256(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest1, SHA3_256_DIGEST_LEN) == 0);

    strcpy(msg, "");
    strcpy(expected_digest2, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    sha3_256(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest2, SHA3_256_DIGEST_LEN) == 0);

    strcpy(msg, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    strcpy(expected_digest3, "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");
    sha3_256(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest3, SHA3_256_DIGEST_LEN) == 0);

    strcpy(msg, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
    strcpy(expected_digest4, "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18");
    sha3_256(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA3_256_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest4, SHA3_256_DIGEST_LEN) == 0);

}

DECLARE_UTEST(test_sha3_512, "sha3_512 test vectors") //http://www.di-mgt.com.au/sha_testvectors.html
{
    char msg[1024] = {0};
    unsigned char digest[1024] = {0};
    char digest_txt[1024] = {0};
    char expected_digest1[1024] = {0};
    char expected_digest2[1024] = {0};
    char expected_digest3[1024] = {0};
    char expected_digest4[1024] = {0};
    int i = 0;

    strcpy(msg, "abc");
    strcpy(expected_digest1, "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
    sha3_512(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA3_512_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest1, SHA3_512_DIGEST_LEN) == 0);

    strcpy(msg, "");
    strcpy(expected_digest2, "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    sha3_512(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA3_512_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest2, SHA3_512_DIGEST_LEN) == 0);

    strcpy(msg, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    strcpy(expected_digest3, "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e");
    sha3_512(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA3_512_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest3, SHA3_512_DIGEST_LEN) == 0);

    strcpy(msg, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
    strcpy(expected_digest4, "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185");
    sha3_512(digest, (unsigned char *)msg, strlen(msg));
    for ( i = 0; i < SHA3_512_DIGEST_LEN; i++)
    {
        sprintf(digest_txt + (2 * i), "%02x", digest[i]);
    }
    CU_ASSERT(memcmp(digest_txt, expected_digest4, SHA3_512_DIGEST_LEN) == 0);

}

int register_ts_digest_test(void)
{
    ts_init(&TEST_SUITE(digest_test), TEST_SUITE_DESCR(digest_test), NULL, NULL);
    ts_add_utest(&TEST_SUITE(digest_test), UTEST_FCT(test_md5), UTEST_DESCR(test_md5));
    ts_add_utest(&TEST_SUITE(digest_test), UTEST_FCT(test_sha1), UTEST_DESCR(test_sha1));
    ts_add_utest(&TEST_SUITE(digest_test), UTEST_FCT(test_sha256), UTEST_DESCR(test_sha256));
    ts_add_utest(&TEST_SUITE(digest_test), UTEST_FCT(test_sha384), UTEST_DESCR(test_sha384));
    ts_add_utest(&TEST_SUITE(digest_test), UTEST_FCT(test_sha512), UTEST_DESCR(test_sha512));
    ts_add_utest(&TEST_SUITE(digest_test), UTEST_FCT(test_sha3_256), UTEST_DESCR(test_sha3_256));
    ts_add_utest(&TEST_SUITE(digest_test), UTEST_FCT(test_sha3_512), UTEST_DESCR(test_sha3_512));

    return register_ts(&TEST_SUITE(digest_test));
}

#endif /* HAVE_C_UNIT_TESTS */ /* LCOV_EXCL_STOP */
/***EOF***/
