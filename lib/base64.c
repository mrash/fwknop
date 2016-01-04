/**
 * \file lib/base64.c
 *
 * \brief Implementation of the Base64 encode/decode algorithim.
 */

/* This code was derived from the base64.c part of FFmpeg written
 * by Ryan Martell. (rdm4@martellventures.com).
 *
 * Copyright (C) Ryan Martell. (rdm4@martellventures.com)
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
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
#include "base64.h"
#include "fko_common.h"

#if !AFL_FUZZING
static unsigned char map2[] =
{
    0x3e, 0xff, 0xff, 0xff, 0x3f, 0x34, 0x35, 0x36,
    0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
    0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33
};
#endif

#ifdef HAVE_C_UNIT_TESTS
#include "cunit_common.h"
DECLARE_TEST_SUITE(base64_test, "Utility functions test suite");
#endif

int
b64_decode(const char *in, unsigned char *out)
{
    int i;
    unsigned char *dst = out;
#if ! AFL_FUZZING
    int v;
#endif

#if AFL_FUZZING
    /* short circuit base64 decoding in AFL fuzzing mode - just copy
     * data as-is.
    */
    for (i = 0; in[i]; i++)
        *dst++ = in[i];
#else
    v = 0;
    for (i = 0; in[i] && in[i] != '='; i++) {
        unsigned int index= in[i]-43;

        if (index>=(sizeof(map2)/sizeof(map2[0])) || map2[index] == 0xff)
            return(-1);

        v = (v << 6) + map2[index];

        if (i & 3)
            *dst++ = v >> (6 - 2 * (i & 3));
    }
#endif

    *dst = '\0';

    return(dst - out);
}

/*****************************************************************************
 * b64_encode: Stolen from VLC's http.c
 * Simplified by michael
 * fixed edge cases and made it work from data (vs. strings) by ryan.
 *****************************************************************************
*/
int
b64_encode(unsigned char *in, char *out, int in_len)
{
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned i_bits = 0;
    int i_shift = 0;
    int bytes_remaining = in_len;

    char *dst = out;

    if (in_len > 0) { /* Special edge case, what should we really do here? */
        while (bytes_remaining) {
            i_bits = (i_bits << 8) + *in++;
            bytes_remaining--;
            i_shift += 8;

            do {
                *dst++ = b64[(i_bits << 6 >> i_shift) & 0x3f];
                i_shift -= 6;
            } while (i_shift > 6 || (bytes_remaining == 0 && i_shift > 0));
        }
        while ((dst - out) & 3)
            *dst++ = '=';
    }

    *dst = '\0';

    return(dst - out);
}

/* Strip trailing equals ("=") charcters from a base64-encoded
 * message digest.
*/
void
strip_b64_eq(char *data)
{
    char *ndx;

    if((ndx = strchr(data, '=')) != NULL)
        *ndx = '\0';
}

#ifdef HAVE_C_UNIT_TESTS
DECLARE_UTEST(test_base64_encode, "test base64 encoding functions")
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
    strcpy(expected_out2, "Zg==");
    strcpy(expected_out3, "Zm8=");
    strcpy(expected_out4, "Zm9v");
    strcpy(expected_out5, "Zm9vYg==");
    strcpy(expected_out6, "Zm9vYmE=");
    strcpy(expected_out7, "Zm9vYmFy");

    strcpy(test_str, "");
    b64_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out1) == 0);

    strcpy(test_str, "f");
    b64_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out2) == 0);

    strcpy(test_str, "fo");
    b64_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out3) == 0);

    strcpy(test_str, "foo");
    b64_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out4) == 0);

    strcpy(test_str, "foob");
    b64_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out5) == 0);

    strcpy(test_str, "fooba");
    b64_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out6) == 0);

    strcpy(test_str, "foobar");
    b64_encode((unsigned char *)test_str, test_out, strlen(test_str));
    CU_ASSERT(strcmp(test_out, expected_out7) == 0);

}

DECLARE_UTEST(test_base64_decode, "test base64 decoding functions")
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
    b64_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out1) == 0);

    strcpy(test_str, "Zg==");
    b64_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out2) == 0);

    strcpy(test_str, "Zm8=");
    b64_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out3) == 0);

    strcpy(test_str, "Zm9v");
    b64_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out4) == 0);

    strcpy(test_str, "Zm9vYg==");
    b64_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out5) == 0);

    strcpy(test_str, "Zm9vYmE=");
    b64_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out6) == 0);

    strcpy(test_str, "Zm9vYmFy");
    b64_decode(test_str, (unsigned char *)test_out);
    CU_ASSERT(strcmp(test_out, expected_out7) == 0);
}

int register_base64_test(void)
{
    ts_init(&TEST_SUITE(base64_test), TEST_SUITE_DESCR(base64_test), NULL, NULL);
    ts_add_utest(&TEST_SUITE(base64_test), UTEST_FCT(test_base64_encode), UTEST_DESCR(test_base64_encode));
    ts_add_utest(&TEST_SUITE(base64_test), UTEST_FCT(test_base64_decode), UTEST_DESCR(test_base64_decode));

    return register_ts(&TEST_SUITE(base64_test));
}
#endif
/***EOF***/
