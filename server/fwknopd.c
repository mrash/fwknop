/* $Id$
 *****************************************************************************
 *
 * File:    fwknopd.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: An implementation of an fwknop server.
 *
 * Copyright (C) 2009 Damien Stuart (dstuart@dstuart.org)
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
#include "fwknopd.h"
#include "config_init.h"
#include "utils.h"

/* prototypes
*/
static void display_ctx(fko_ctx_t ctx);
void errmsg(char *msg, int err);

int
main(int argc, char **argv)
{
    fko_ctx_t           ctx;
    int                 res;
    char               *spa_data, *version;
    char                access_buf[MAX_LINE_LEN];

    fko_srv_options_t   options;

    /* Handle command line
    */
    config_init(&options, argc, argv);

    /* Display version info and exit.
    */
    if (options.version) {
        fko_get_version(ctx, &version);

        fprintf(stdout, "[+] fwknopd server %s\n", MY_VERSION);

        return(0);
    }

    return(0);
}

/* Display an FKO error message.
*/
void
errmsg(char *msg, int err) {
    fprintf(stderr, "[*] %s: %s: Error %i - %s\n",
        MY_NAME, msg, err, fko_errstr(err));
}

/* Show the fields of the FKO context.
*/
static void
display_ctx(fko_ctx_t ctx)
{
    char       *rand_val        = NULL;
    char       *username        = NULL;
    char       *version         = NULL;
    char       *spa_message     = NULL;
    char       *nat_access      = NULL;
    char       *server_auth     = NULL;
    char       *enc_data        = NULL;
    char       *spa_digest      = NULL;
    char       *spa_data        = NULL;

    time_t      timestamp       = 0;
    short       msg_type        = -1;
    short       digest_type     = -1;
    int         client_timeout  = -1;

    /* Should be checking return values, but this is temp code. --DSS
    */
    fko_get_rand_value(ctx, &rand_val);
    fko_get_username(ctx, &username);
    fko_get_timestamp(ctx, &timestamp);
    fko_get_version(ctx, &version);
    fko_get_spa_message_type(ctx, &msg_type);
    fko_get_spa_message(ctx, &spa_message);
    fko_get_spa_nat_access(ctx, &nat_access);
    fko_get_spa_server_auth(ctx, &server_auth);
    fko_get_spa_client_timeout(ctx, &client_timeout);
    fko_get_spa_digest_type(ctx, &digest_type);
    fko_get_encoded_data(ctx, &enc_data);
    fko_get_spa_digest(ctx, &spa_digest);
    fko_get_spa_data(ctx, &spa_data);

    printf("\nFKO Field Values:\n=================\n\n");
    printf("   Random Value: %s\n", rand_val == NULL ? "<NULL>" : rand_val);
    printf("       Username: %s\n", username == NULL ? "<NULL>" : username);
    printf("      Timestamp: %u\n", (unsigned int) timestamp);
    printf("    FKO Version: %s\n", version == NULL ? "<NULL>" : version);
    printf("   Message Type: %i\n", msg_type);
    printf(" Message String: %s\n", spa_message == NULL ? "<NULL>" : spa_message);
    printf("     Nat Access: %s\n", nat_access == NULL ? "<NULL>" : nat_access);
    printf("    Server Auth: %s\n", server_auth == NULL ? "<NULL>" : server_auth);
    printf(" Client Timeout: %u\n", client_timeout);
    printf("    Digest Type: %u\n", digest_type);
    printf("\n   Encoded Data: %s\n", enc_data == NULL ? "<NULL>" : enc_data);
    printf("\nSPA Data Digest: %s\n", spa_digest == NULL ? "<NULL>" : spa_digest);
    printf("\nFinal Packed/Encrypted/Encoded Data:\n\n%s\n\n", spa_data);
}

/***EOF***/
