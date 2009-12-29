/* $Id$
 *****************************************************************************
 *
 * File:    incoming_spa.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Process an incoming SPA data packet for fwknopd.
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

/* Process the SPA packet data
*/
int
incoming_spa(fko_srv_options_t *opts)
{
    fko_ctx_t       ctx;
    int             res;
    time_t          spa_ts, now_ts;
    int             ts_diff;

    spa_pkt_info_t *spa_pkt = &(opts->spa_pkt);

    /* Sanity check
    */
    if(spa_pkt->packet_data_len <= 0)
        return(SPA_MSG_BAD_DATA);

/* --DSS temp */
fprintf(stderr, "SPA Packet: '%s'\n", spa_pkt->packet_data);
/* --DSS temp */

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
        log_msg(LOG_WARNING|LOG_STDERR, "Error creating fko context: %s",
            fko_errstr(res));
        return(SPA_MSG_FKO_CTX_ERROR);
    }

/* --DSS temp */
fprintf(stderr, "Decode res = %i\n", res);
display_ctx(ctx);
/* --DSS temp */

    if(strncasecmp(opts->config[CONF_ENABLE_DIGEST_PERSISTENCE], "Y", 1) == 0)
    {
        res = replay_check(opts, ctx);
        if(res != SPA_MSG_SUCCESS)
            goto clean_and_bail;
    }

    /* Check packet age if so configured.
    */
    if(strncasecmp(opts->config[CONF_ENABLE_SPA_PACKET_AGING], "Y", 1) == 0)
    {
        if(fko_get_timestamp(ctx, &spa_ts) != FKO_SUCCESS)
        {
            log_msg(LOG_WARNING|LOG_STDERR, "Error getting SPA timestamp: %s",
                fko_errstr(res));
            res = SPA_MSG_ERROR;
            goto clean_and_bail;
        }

        time(&now_ts);

        ts_diff = now_ts - spa_ts;

        if(ts_diff > atoi(opts->config[CONF_MAX_SPA_PACKET_AGE]))
        {
            log_msg(LOG_WARNING|LOG_STDERR, "SPA data is too old (%i seconds).",
                ts_diff);
            res = SPA_MSG_TOO_OLD;
            goto clean_and_bail;
        }
    }

    /* Additional access checks
    */
    // TODO: Finish me


    /* Send to the firewall rule processor.
    */
    // TODO: Finish me


clean_and_bail:
    fko_destroy(ctx);
    return(res);
}

/***EOF***/
