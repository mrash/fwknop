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

/* includes */
#include "fwknop.h"

static void display_ctx(fko_ctx_t ctx);
static void hex_dump(unsigned char *data, int size);
static void process_cmd_line(cmdl_opts *options, int argc, char **argv);
static void usage(void);

#define FKO_PW "BubbaWasHere"

int
main(int argc, char **argv)
{
    fko_ctx_t   ctx, ctx2;
    int         res;
    cmdl_opts    options;

    /* Handle command line
    */
    process_cmd_line(&options, argc, argv);

    /* Intialize the context
    */
    res = fko_new(&ctx);
    if(res != FKO_SUCCESS)
        fprintf(stderr, "Error #%i from fko_new: %s\n", res, fko_errstr(res));

    /* Set message type
    res = fko_set_spa_message_type(ctx, FKO_ACCESS_MSG);
    if(res != FKO_SUCCESS)
        fprintf(stderr, "Error #%i from fko_set_spa_message_type: %s\n", res, fko_errstr(res));
    */

    /* Set a message string
    */
    res = fko_set_spa_message(ctx, "0.0.0.0,tcp/22");
    if(res != FKO_SUCCESS)
        fprintf(stderr, "Error #%i from fko_set_spa_message: %s\n", res, fko_errstr(res));

    /* Set Digest type.
    fko_set_spa_digest_type(ctx, FKO_DIGEST_SHA1);
    */

    /* Set net access string.
    res = fko_set_spa_nat_access(ctx, "192.168.1.2,22");
    if(res != FKO_SUCCESS)
        fprintf(stderr, "Error #%i from fko_set_spa_nat_access: %s\n", res, fko_errstr(res));
    */

    /* Set client timeout value
    fko_set_spa_client_timeout(ctx, 120);
    */

    /* Set a serer auth string.
    res = fko_set_spa_server_auth(ctx, "crypt,SomePW");
    if(res != FKO_SUCCESS)
        fprintf(stderr, "Error #%i from fko_set_spa_server_auth: %s\n", res, fko_errstr(res));
    */

    /* Finalize the context data (encrypt and encode the SPA data)
    */
    res = fko_spa_data_final(ctx, FKO_PW);
    if(res != FKO_SUCCESS)
        fprintf(stderr, "Error #%i from fko_spa_data_final: %s\n", res, fko_errstr(res));

    /* Display the context data.
    */
    if (! options.quiet)
        display_ctx(ctx);

    /************** Decoding now *****************/

    /* Now we create a new context based on data from the first one.
    */
    //res = fko_new_with_data(&ctx2, ctx->encrypted_msg, FKO_PW);
    res = fko_new_with_data(&ctx2, fko_get_spa_data(ctx), FKO_PW);
    if(res != FKO_SUCCESS)
        fprintf(stderr, "Error #%i from fko_new_with_data: %s\n", res, fko_errstr(res));

    /* Simply call fko_decrypt_spa_data to do all decryption, decoding,
     * parsing, and populating the context.
    res = fko_decrypt_spa_data(ctx2, FKO_PW);
    if(res != FKO_SUCCESS)
        fprintf(stderr, "Error #%i from fko_decrypt_spa_data: %s\n", res, fko_errstr(res));
    */

    if (! options.quiet) {
        printf("\nDump of the Decoded Data\n");
        display_ctx(ctx2);
    }

    fko_destroy(ctx);
    fko_destroy(ctx2);

    return(0);
}

static void
display_ctx(fko_ctx_t ctx)
{
    printf("\nFKO Context Values:\n===================\n\n");

    printf(
        "   Random Value: %s\n"
        "       Username: %s\n"
        "      Timestamp: %u\n"
        "    FKO Version: %s\n"
        "   Message Type: %i\n"
        " Message String: %s\n"
        "     Nat Access: %s\n"
        "    Server Auth: %s\n"
        " Client Timeout: %u\n"
        "    Digest Type: %u\n"
        "\n   Encoded Data: %s\n"
        "\nSPA Data Digest: %s\n"
        "\nFinal Packed/Encrypted/Encoded Data:\n\n%s\n\n"
        ,
        fko_get_rand_value(ctx),
        (fko_get_username(ctx) == NULL) ? "<NULL>" : fko_get_username(ctx),
        fko_get_timestamp(ctx),
        fko_version(ctx),
        fko_get_spa_message_type(ctx),
        (fko_get_spa_message(ctx) == NULL) ? "<NULL>" : fko_get_spa_message(ctx),
        (fko_get_spa_nat_access(ctx) == NULL) ? "<NULL>" : fko_get_spa_nat_access(ctx),
        (fko_get_spa_server_auth(ctx) == NULL) ? "<NULL>" : fko_get_spa_server_auth(ctx),
        fko_get_spa_client_timeout(ctx),
        fko_get_spa_digest_type(ctx),
        (fko_get_encoded_data(ctx) == NULL) ? "<NULL>" : fko_get_encoded_data(ctx),
        (fko_get_spa_digest(ctx) == NULL) ? "<NULL>" : fko_get_spa_digest(ctx),

        (fko_get_spa_data(ctx) == NULL) ? "<NULL>" : fko_get_spa_data(ctx)
    );

}

static void
hex_dump(unsigned char *data, int size)
{
    int ln, i, j = 0;
    char ascii_str[17] = {0};

    for(i=0; i<size; i++)
    {
        if((i % 16) == 0)
        {
            printf(" %s\n  0x%.4x:  ", ascii_str, i);
            memset(ascii_str, 0x0, 17);
            j = 0;
        }

        printf("%.2x ", data[i]);

        ascii_str[j++] = (data[i] < 0x20 || data[i] > 0x7e) ? '.' : data[i];

        if(j == 8)
            printf(" ");
    }

    /* Remainder...
    */
    ln = strlen(ascii_str);
    if(ln > 0)
    {
        for(i=0; i < 16-ln; i++)
            printf("   ");

        printf(" %s\n\n", ascii_str);
    }
}

static void process_cmd_line(cmdl_opts *options, int argc, char **argv)
{
    int getopt_c = 0;
    int opt_index = 0;

    memset(options, 0x00, sizeof(cmdl_opts));

    while (1) {
        opt_index = 0;
        static struct option long_options[] = {
            {"quiet", 0, NULL, 'q'},
            {"verbose", 0, NULL, 'v'},
            {"Version", 0, NULL, 'V'},
            {"help", 0, NULL, 'h'},
            {0, 0, 0, 0}
        };
        getopt_c = getopt_long(argc, argv, "qhvV",
                long_options, &opt_index);
        if (getopt_c == -1)
            break;

        switch (getopt_c) {
            case 'q':
                options->quiet = 1;
                break;
            case 'v':
                options->verbose = 1;
                break;
            case 'V':
                fprintf(stdout, "[+] fwknop-%s\n", FWKNOP_VERSION);
                exit(0);
            case 'h':
                usage();
                exit(0);
           default:
               printf("?? getopt_long returned character code 0%o ??\n",
                    getopt_c);
        }
    }
    return;
}

static void usage(void)
{
    fprintf(stdout,
"fwknop; Single Packet Authorization client\n"
"\n"
"Usage: fwknop -A <port list> [-s|-R|-a] -D <spa_server> [options]\n"
"\n"
"Options:\n"
"    -A, --Access  <port list>  - Provide a list of ports/protocols to open\n"
"                                 on the server. The format is\n"
    );
    return;
}

/***EOF***/
