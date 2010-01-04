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
#include "access.h"
#include "log_msg.h"

/* Process the SPA packet data
*/
int
incoming_spa(fko_srv_options_t *opts)
{
    fko_ctx_t       ctx;
    char            *ndx;
    char            spa_src_ip[16];
    char            spa_protoport[128];
    time_t          now_ts;
    int             res;
    int             ts_diff;
    int             got_spa_error = 0;

    spa_pkt_info_t *spa_pkt = &(opts->spa_pkt);

    /* SPA data fields we will want to pull:
    */
    time_t          spa_ts;
    short           spa_msg_type;
    char            *spa_msg;
    char            *spa_nat_access;
    int             spa_client_timeout;

    /* Get the access.conf data for the stanza that matches this incoming
     * source IP address.
    */
    acc_stanza_t   *acc = acc_check_source(opts, spa_pkt->packet_src_ip);

    if(acc == NULL)
    {
        log_msg(LOG_WARNING|LOG_STDERR,
            "No access data found for source IP: %u", spa_pkt->packet_src_ip
        );

        return(SPA_MSG_ACCESS_DENIED);
    }

    /* Sanity check
    */
    if(spa_pkt->packet_data_len <= 0)
        return(SPA_MSG_BAD_DATA);

/* --DSS temp */
fprintf(stderr, "SPA Packet: '%s'\n", spa_pkt->packet_data);
/* --DSS temp */

    /* Decode the packet data
    */
    res = fko_new_with_data(&ctx, spa_pkt->packet_data, acc->key);

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

    /* Ok, we can pull the rest of the spa data we are interested in.
    */
    if(fko_get_spa_message_type(ctx, &spa_msg_type) != FKO_SUCCESS)
    {
        log_msg(LOG_WARNING|LOG_STDERR, "Error getting SPA message type: %s",
            fko_errstr(res));
        got_spa_error++;
    }
    if(fko_get_spa_message(ctx, &spa_msg) != FKO_SUCCESS)
    {
        log_msg(LOG_WARNING|LOG_STDERR, "Error getting SPA message string: %s",
            fko_errstr(res));
        got_spa_error++;
    }
    if(fko_get_spa_nat_access(ctx, &spa_nat_access) != FKO_SUCCESS)
    {
        log_msg(LOG_WARNING|LOG_STDERR, "Error getting SPA nat access string: %s",
            fko_errstr(res));
        got_spa_error++;
    }
    if(fko_get_spa_client_timeout(ctx, &spa_client_timeout) != FKO_SUCCESS)
    {
        log_msg(LOG_WARNING|LOG_STDERR, "Error getting SPA client_timeout: %s",
            fko_errstr(res));
        got_spa_error++;
    }

    if(got_spa_error > 0)
    {
        res = SPA_MSG_ERROR;
        goto clean_and_bail;
    }

    /* Take action based on SPA message type.
    */
    switch(spa_msg_type)
    {
        /* Command messages.
        */
        case FKO_COMMAND_MSG:
            if(!acc->enable_cmd_exec)
            {
                log_msg(LOG_WARNING|LOG_STDERR,
                    "SPA Command message are not allowed or supported."
                );
                res = SPA_MSG_ACCESS_DENIED;
            }
            else
            {
                /* --DSS TODO: Finish Me */
                log_msg(LOG_WARNING|LOG_STDERR,
                    "SPA Command message are not yet supported."
                );
                res = SPA_MSG_NOT_SUPPORTED;
            }
            break;

        /* NAT access messages.
        */
        case FKO_NAT_ACCESS_MSG:
        case FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG:
            log_msg(LOG_WARNING|LOG_STDERR,
                "SPA NAT access messages are not yet supported."
            );
            res = SPA_MSG_NOT_SUPPORTED;
            /* --DSS TODO: Finish Me */
            break;

        /* Local NAT access messages.
        */
        case FKO_LOCAL_NAT_ACCESS_MSG:
        case FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG:
            log_msg(LOG_WARNING|LOG_STDERR,
                "SPA Local NAT access messages are not yet supported."
            );
            res = SPA_MSG_NOT_SUPPORTED;
            /* --DSS TODO: Finish Me */
            break;

        /* Standard access messages.
        */
        case FKO_ACCESS_MSG:
        case FKO_CLIENT_TIMEOUT_ACCESS_MSG:
            /* Parse it into its components (source IP and proto/port list).
            */
            ndx = strchr(spa_msg, ',');
            if(ndx == NULL)
            {
                log_msg(LOG_WARNING|LOG_STDERR, "Error parsing SPA message string: %s",
                    fko_errstr(res));
                res = SPA_MSG_ERROR;
                break;
            }

            strlcpy(spa_src_ip, spa_msg, (ndx-spa_msg)+1);
            strlcpy(spa_protoport, ndx+1, 128);

            /* Check access against restrict_ports and open_ports.
            */
            res = acc_check_port_access(acc, spa_protoport);

            // --DSS temp
            log_msg(LOG_WARNING|LOG_STDERR,
                "This SPA access msg would%s be allowed.\n Either way we need code to implement it. :)",
                res ? "":" *NOT*"
            );
            res = SPA_MSG_NOT_SUPPORTED;

            /* --DSS TODO: Finish Me */
            break;
    }

    /* Send to the firewall rule processor.
    */
    // TODO: Finish me


clean_and_bail:
    fko_destroy(ctx);
    return(res);
}

/***EOF***/
