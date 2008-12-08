/* $Id$
 *****************************************************************************
 *
 * File:    fko_test.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Temp test program for libfwknop
 *
 * Copyright (C) 2008 Damien Stuart (dstuart@dstuart.org)
 *
 *  License (GNU Public License):
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program; if not, write to the Free Software
 *     Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *     USA
 *
 *****************************************************************************
*/
#include "fwknop.h"

int main(int argc, char **argv)
{
    spa_message_t    sm;
    //char             test_str[1024] = {0};

    /* Zero our SPA message struct.
    */
    memset(&sm, 0x0, sizeof(spa_message_t));

    /*********************************************************************
    * Get a random 16-byte string of hex values.
    */
    spa_random_number(&sm);
    printf("        SPA_RAND_VAL: %s\n", sm.rand_val);

    /*********************************************************************
     * Get the current user, then a spoofed user.
    */
    spa_user(&sm, NULL);
    printf("            SPA_USER: %s\n", sm.user);

    spa_user(&sm, "bubba");
    printf("    SPA_USER (spoof): %s\n", sm.user);

    /*********************************************************************
     * Get the timestamp, then with an positive and negative offset.
    */
    spa_timestamp(&sm, 0);
    printf("       SPA_TIMESTAMP: %u\n", sm.timestamp);
    spa_timestamp(&sm, 300);
    printf("SPA_TIMESTAMP (+300): %u\n", sm.timestamp);
    spa_timestamp(&sm, -600);
    printf("SPA_TIMESTAMP (-600): %u\n", sm.timestamp);

    /*********************************************************************
     * Get the version of fwknop.
    */
    printf("         SPA_Version: %s\n", spa_version(&sm));

    /*********************************************************************
     * Set and get the message type. set ACCESS, COMMAND, NAT, Then
     * invalid
    */
    spa_message_type(&sm, SPA_ACCESS_MSG);
    printf("    SPA Message Type: %u\n", sm.message_type);
    spa_message_type(&sm, SPA_COMMAND_MSG);
    printf("SPA CMD Message Type: %u\n", sm.message_type);
    spa_message_type(&sm, SPA_LOCAL_NAT_ACCESS_MSG);
    printf("SPA NAT Message Type: %u\n", sm.message_type);
    spa_message_type(&sm, 100);
    printf("SPA bad Message Type: %u\n\n", sm.message_type);

    /*********************************************************************
     * Various Base 64 tests.
    */
    char btest_raw[90] = {0};
    char btest_enc[120] = {0};
    uchar btest_dec[120] = {0};

/*
*/
    // 1 char
    strcpy(btest_raw, "1");
    b64_encode((uchar*)btest_raw, btest_enc, strlen(btest_raw));
    printf("----\n    B64 RAW: %s\n", btest_raw);
    printf("    B64 ENC: %s\n", btest_enc);
    b64_decode(btest_enc, btest_dec, strlen(btest_enc));
    printf("    B64 DEC: %s\n", btest_dec);

    // 2 chars
    strcpy(btest_raw, "22");
    b64_encode((uchar*)btest_raw, btest_enc, strlen(btest_raw));
    printf("----\n    B64 RAW: %s\n", btest_raw);
    printf("    B64 ENC: %s\n", btest_enc);
    b64_decode(btest_enc, btest_dec, strlen(btest_enc));
    printf("    B64 DEC: %s\n", btest_dec);

    // 3 chars
    strcpy(btest_raw, "333");
    b64_encode((uchar*)btest_raw, btest_enc, strlen(btest_raw));
    printf("----\n    B64 RAW: %s\n", btest_raw);
    printf("    B64 ENC: %s\n", btest_enc);
    b64_decode(btest_enc, btest_dec, strlen(btest_enc));
    printf("    B64 DEC: %s\n", btest_dec);

    // 4 chars
    strcpy(btest_raw, "4444");
    b64_encode((uchar*)btest_raw, btest_enc, strlen(btest_raw));
    printf("----\n    B64 RAW: %s\n", btest_raw);
    printf("    B64 ENC: %s\n", btest_enc);
    b64_decode(btest_enc, btest_dec, strlen(btest_enc));
    printf("    B64 DEC: %s\n", btest_dec);

    // Longer string
    strcpy(btest_raw, "The quick brown fox jumps over the lazy doq (1234567890).");
    b64_encode((uchar*)btest_raw, btest_enc, strlen(btest_raw));
    printf("----\n    B64 RAW: %s\n", btest_raw);
    printf("    B64 ENC: %s\n", btest_enc);
    b64_decode(btest_enc, btest_dec, strlen(btest_enc));
    printf("    B64 DEC: %s\n", btest_dec);

    // Binary data (yeah, I know.. pretty lame...
    memset(btest_raw, 0x07, 4);
    b64_encode((uchar*)btest_raw, btest_enc, 4);
    printf("----\n    B64 RAW: %02x %02x %02x %02x\n", btest_raw[0],btest_raw[1],btest_raw[2],btest_raw[3]);
    printf("    B64 ENC: %s\n", btest_enc);
    b64_decode(btest_enc, btest_dec, strlen(btest_enc));
    printf("    B64 DEC: %02x %02x %02x %02x\n", btest_dec[0],btest_dec[1],btest_dec[2],btest_dec[3]);

    printf("\n");
    
    /*********************************************************************
     * DIGEST tests.
     ********************************************************************/

    char tst_string[] = "This is a test.";

    /*********************************************************************
     * MD5 test.
    */
    char md5_digest[33]   = {0};
    char tst_md5_digest[] = "120ea8a25e5d487bf68b5f7096440019";

    md5_hex(md5_digest, (uchar*)tst_string, strlen(tst_string));

    printf(
        "\nMD5 of '%s':\n"
        "    Should be: %s\n"
        "  Computed as: %s\n",
        tst_string, tst_md5_digest, md5_digest
    );

    /*********************************************************************
     * SHA1 test.
    */
    char sha1_digest[41]   = {0};
    char tst_sha1_digest[] = "afa6c8b3a2fae95785dc7d9685a57835d703ac88";

    sha1_hex(sha1_digest, (uchar*)tst_string, strlen(tst_string));

    printf(
        "\nSHA1 of '%s':\n"
        "    Should be: %s\n"
        "  Computed as: %s\n",
        tst_string, tst_sha1_digest, sha1_digest
    );

    /*********************************************************************
     * SHA256 test.
    */
    char sha256_digest[65]   = {0};
    char tst_sha256_digest[] = "a8a2f6ebe286697c527eb35a58b5539532e9b3ae3b64d4eb0a46fb657b41562c";

    sha256_hex(sha256_digest, (uchar*)tst_string, strlen(tst_string));

    printf(
        "\nSHA256 of '%s':\n"
        "    Should be: %s\n"
        "  Computed as: %s\n",
        tst_string, tst_sha256_digest, sha256_digest
    );


    /*********************************************************************
     * Rijndael test.
    */
    char *pass = "bubba";
    char b64buf[1024] = {0};
    uchar encbuf[1024] = {0};
    uchar decbuf[1024] = {0};

    int len = strlen(tst_string);
    int enc_len, dec_len;

    /* Use our handy macro to predict the size of the encrypted data.
    */
    //int pred_len = PREDICT_ENCSIZE(len);

    enc_len = fko_encrypt((uchar*)tst_string, len, pass, encbuf);

    b64_encode(encbuf, b64buf, enc_len);

    dec_len = fko_decrypt(encbuf, enc_len, pass, decbuf);

    printf(
        "\n   Orig string is: '%s'\n"
        " Base64 of enc is: %s\n"
        "     Decrypted as: '%s'\n",
        tst_string, b64buf, decbuf
    );



    return(0);
} 

/***EOF***/
