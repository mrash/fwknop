/* $Id$
 *****************************************************************************
 *
 * File:    incoming_spa.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: The pcap capture routines for fwknopd.
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
#include "fwknopd_common.h"
#include "incoming_spa.h"
#include "log_msg.h"

/* The pcap capture routine.
*/
int
incoming_spa(fko_srv_options_t *opts)
{
    fko_ctx_t       ctx;
    int             res;

    spa_pkt_info_t *spa_pkt = &(opts->spa_pkt);

    /* Sanity check
    */
    if(spa_pkt->packet_data_len <= 0)
        return;

fprintf(stderr, "SPA Packet: '%s'\n", spa_pkt->packet_data);

    /* Get the decryption key
    */
    // TODO: finish me

    /* Decode the packet data
     * --DSS TEMP note using the hard-coded "sdf" as the password.
     *            this is just for dev testing until I get the 
     *            access.conf handling in.
    */
    res = fko_new_with_data(&ctx, spa_pkt->packet_data, "sdf");

    /* Reset the packet data length to 0.
    */
    spa_pkt->packet_data_len = 0;

    if(res != FKO_SUCCESS)
    {
        fprintf(stderr, "Error creating fko context: %s\n", fko_errstr(res));
        return(-1);
    }

fprintf(stderr, "Decode res = %i\n", res);


    display_ctx(ctx);

    res = replay_check(opts, ctx);

    fko_destroy(ctx);

    return(res);
}

/***EOF***/
