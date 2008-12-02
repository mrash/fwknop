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
    char btest_dec[120] = {0};

/*
*/
    // 1 char
    strcpy(btest_raw, "1");
    b64_encode(btest_raw, btest_enc, strlen(btest_raw));
    printf("----\n    B64 RAW: %s\n", btest_raw);
    printf("    B64 ENC: %s\n", btest_enc);
    b64_decode(btest_enc, btest_dec, strlen(btest_enc));
    printf("    B64 DEC: %s\n", btest_dec);

    // 2 chars
    strcpy(btest_raw, "22");
    b64_encode(btest_raw, btest_enc, strlen(btest_raw));
    printf("----\n    B64 RAW: %s\n", btest_raw);
    printf("    B64 ENC: %s\n", btest_enc);
    b64_decode(btest_enc, btest_dec, strlen(btest_enc));
    printf("    B64 DEC: %s\n", btest_dec);

    // 3 chars
    strcpy(btest_raw, "333");
    b64_encode(btest_raw, btest_enc, strlen(btest_raw));
    printf("----\n    B64 RAW: %s\n", btest_raw);
    printf("    B64 ENC: %s\n", btest_enc);
    b64_decode(btest_enc, btest_dec, strlen(btest_enc));
    printf("    B64 DEC: %s\n", btest_dec);

    // 4 chars
    strcpy(btest_raw, "4444");
    b64_encode(btest_raw, btest_enc, strlen(btest_raw));
    printf("----\n    B64 RAW: %s\n", btest_raw);
    printf("    B64 ENC: %s\n", btest_enc);
    b64_decode(btest_enc, btest_dec, strlen(btest_enc));
    printf("    B64 DEC: %s\n", btest_dec);

    // Longer string
    strcpy(btest_raw, "The quick brown fox jumps over the lazy doq (1234567890).");
    b64_encode(btest_raw, btest_enc, strlen(btest_raw));
    printf("----\n    B64 RAW: %s\n", btest_raw);
    printf("    B64 ENC: %s\n", btest_enc);
    b64_decode(btest_enc, btest_dec, strlen(btest_enc));
    printf("    B64 DEC: %s\n", btest_dec);

    // Binary data (yeah, I know.. pretty lame...
    memset(btest_raw, 0x07, 4);
    b64_encode(btest_raw, btest_enc, 4);
    printf("----\n    B64 RAW: %02x %02x %02x %02x\n", btest_raw[0],btest_raw[1],btest_raw[2],btest_raw[3]);
    printf("    B64 ENC: %s\n", btest_enc);
    b64_decode(btest_enc, btest_dec, strlen(btest_enc));
    printf("    B64 DEC: %02x %02x %02x %02x\n", btest_dec[0],btest_dec[1],btest_dec[2],btest_dec[3]);

    printf("\n");
    
    /*********************************************************************
     * MD5 test.
    */
    char digest[33]   = {0};
    char tst_string[] = "This is a test.";
    char tst_digest[] = "120ea8a25e5d487bf68b5f7096440019";

    /* Use our convenient md5 function.
    */
    md5(tst_string, digest, strlen(tst_string));

    printf(
        "MD5 of '%s':\n"
        "    Should be: %s\n"
        "  Computed as: %s\n",
        tst_string, tst_digest, digest
    );


    return(0);
} 

/***EOF***/
