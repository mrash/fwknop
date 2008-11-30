/* $Id$
 *****************************************************************************
 *
 * File:    fwknop.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: fwknop client program.
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

/* Local prototypes
*/
void init_spa_message(spa_message_t *sm);
void dump_spa_message_data(spa_message_t *sm);

int main(int argc, char **argv)
{
    spa_message_t    sm;

    init_spa_message(&sm);

    /* Timestamp */
    spa_timestamp(&sm, 0);

    dump_spa_message_data(&sm);

    return(0);
} 

/* Initialize the spa_message data struct, and set some default/preliminary
 * values.
*/
void init_spa_message(spa_message_t *sm)
{
    /* Zero our SPA message struct.
    */
    memset(sm, 0x0, sizeof(spa_message_t));

    /* Initialize default values.
    */
    sm->digest_type     = DEFAULT_DIGEST;
    sm->enc_pcap_port   = DEFAULT_PORT;
    sm->message_type    = DEFAULT_MSG_TYPE;
    sm->client_timeout  = DEFAULT_CLIENT_TIMEOUT;

    /* Go ahead and and setup the random and user fields.
    */
    spa_random_number(sm);
    spa_user(sm, NULL);

    /* Version is static, so we add it here as well.
    */
    spa_version(sm);
}

/* Pretty print the data in the spa_message data struct.
*/
void dump_spa_message_data(spa_message_t *sm)
{
    printf(
        "\nCurrent SPA Message Data:\n\n"
        "      Random Val: %s\n"
        "            User: %s\n"
        "       Timestamp: %u\n"
        "         Version: %s\n"
        "    Message Type: %u\n"
        "  Message String: %s\n"
        "      Nat Access: %s\n"
        "     Server Auth: %s\n"
        "  Client Timeout: %u\n"
        "          Digest: %s\n"
        "\n"
        "     Digest Type: %u\n"
        "            Port: %u\n"
        "\n",
            sm->rand_val,
            sm->user,
            sm->timestamp,
            sm->version,
            sm->message_type,
            sm->message,
            sm->nat_access,
            sm->server_auth,
            sm->client_timeout,
            sm->digest,
            sm->digest_type,
            sm->enc_pcap_port
    );
}

/***EOF***/
