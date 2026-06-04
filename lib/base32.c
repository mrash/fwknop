/**
 * \file lib/base32.c
 *
 * \brief Implementation of the Base32 encode/decode algorithms.
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
#include "base32.h"
#include "fko_common.h"

static unsigned char map3[] = {
    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0xff, 0xff, // starts from 50
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 
    0x19
};

#ifdef HAVE_C_UNIT_TESTS /* LCOV_EXCL_START */
#include "cunit_common.h"
DECLARE_TEST_SUITE(base32_test, "Utility functions test suite");
#endif /* LCOV_EXCL_STOP */

int
b32_encode(unsigned char *in, char *out, int in_len)
{
    static const char b32[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    unsigned i_bits = 0;
    int i_shift = 0;
    int bytes_remaining = in_len;

    char *dst = out;

    if (in_len > 0) {
        while (bytes_remaining) {
            i_bits = (i_bits << 8) + *in++;
            bytes_remaining--;
            i_shift += 8;

            /* concat 5 8-bit input groups */
            do {
                *dst++ = b32[(i_bits << 5 >> i_shift) & 0x1f];
                i_shift -= 5;
            } while (i_shift > 5 || (bytes_remaining == 0 && i_shift > 0));
        }
    }

    *dst = '\0';

    return(dst - out);
}

int
b32_decode(const char *in, unsigned char *out)
{
    int i, bits;
    unsigned long v;
    unsigned char *dst = out;

    v = 0, bits = 0;
    for (i = 0; in[i] && in[i] != '='; i++) {
        unsigned int index= in[i]-50;

        if (index>=(sizeof(map3)/sizeof(map3[0])) || map3[index] == 0xff)
            return(-1);

        v = (v << 5) + map3[index];
        bits += 5;

        /* a bit of a hacky way, but it works */
        while (bits >= 8) {
            *dst++ = (v >> (bits - 8)) & 0xff; 
            bits -= 8;
        }
    }

    *dst = '\0';

    return(dst - out);
}

#ifdef HAVE_C_UNIT_TESTS /* LCOV_EXCL_START */
DECLARE_UTEST(test_base32_encode, "test base32 encoding functions")
{
    char test_str[32] = {0};
    char test_out[32] = {0};
    char expected_out1[32] = {0};
    char expected_out2[32] = {0};
    char expected_out3[32] = {0};
    char expected_out4[32] = {0};
    char expected_out5[32] = {0};
    char expected_out6[32] = {0};
    char expected_out7[32] = {0};

    strcpy(expected_out1, "");
    strcpy(expected_out2, "MY");
    strcpy(expected_out3, "MZXQ");
    strcpy(expected_out4, "MZXW6");
    strcpy(expected_out5, "MZXW6YQ");
    strcpy(expected_out6, "MZXW6YTB");
    strcpy(expected_out7, "MZXW6YTBOI");

    strcpy(test_str, "");
    b32_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out1) == 0);

    strcpy(test_str, "f");
    b32_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out2) == 0);

    strcpy(test_str, "fo");
    b32_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out3) == 0);

    strcpy(test_str, "foo");
    b32_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out4) == 0);

    strcpy(test_str, "foob");
    b32_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out5) == 0);

    strcpy(test_str, "fooba");
    b32_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out6) == 0);

    strcpy(test_str, "foobar");
    b32_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out7) == 0);

}

DECLARE_UTEST(test_base32_decode, "test base32 decoding functions")
{
    char test_str[32] = {0};
    char test_out[32] = {0};
    char expected_out1[32] = {0};
    char expected_out2[32] = {0};
    char expected_out3[32] = {0};
    char expected_out4[32] = {0};
    char expected_out5[32] = {0};
    char expected_out6[32] = {0};
    char expected_out7[32] = {0};

    strcpy(expected_out1, "");
    strcpy(expected_out2, "f");
    strcpy(expected_out3, "fo");
    strcpy(expected_out4, "foo");
    strcpy(expected_out5, "foob");
    strcpy(expected_out6, "fooba");
    strcpy(expected_out7, "foobar");

    strcpy(test_str, "");
    b32_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out1) == 0);

    strcpy(test_str, "MY");
    b32_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out2) == 0);

    strcpy(test_str, "MZXQ");
    b32_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out3) == 0);

    strcpy(test_str, "MZXW6");
    b32_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out4) == 0);

    strcpy(test_str, "MZXW6YQ");
    b32_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out5) == 0);

    strcpy(test_str, "MZXW6YTB");
    b32_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out6) == 0);

    strcpy(test_str, "MZXW6YTBOI");
    b32_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out7) == 0);
}

int register_base32_test(void)
{
    ts_init(&TEST_SUITE(base32_test), TEST_SUITE_DESCR(base32_test), NULL, NULL);
    ts_add_utest(&TEST_SUITE(base32_test), UTEST_FCT(test_base32_encode), UTEST_DESCR(test_base32_encode));
    ts_add_utest(&TEST_SUITE(base32_test), UTEST_FCT(test_base32_decode), UTEST_DESCR(test_base32_decode));

    return register_ts(&TEST_SUITE(base32_test));
}
#endif /* LCOV_EXCL_STOP */
/***EOF***/
