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

/* Popluate a spa_data struct from an initialized (and populated) FKO context.
*/
int
get_spa_data_fields(fko_ctx_t ctx, spa_data_t *spdat)
{
    int res = FKO_SUCCESS;

    res = fko_get_username(ctx, &(spdat->username));
    if(res != FKO_SUCCESS)
        return(res);

    res = fko_get_timestamp(ctx, &(spdat->timestamp));
    if(res != FKO_SUCCESS)
        return(res);

    res = fko_get_version(ctx, &(spdat->version));
    if(res != FKO_SUCCESS)
        return(res);
 
    res = fko_get_spa_message_type(ctx, &(spdat->message_type));
    if(res != FKO_SUCCESS)
        return(res);

    res = fko_get_spa_message(ctx, &(spdat->spa_message));
    if(res != FKO_SUCCESS)
        return(res);

    res = fko_get_spa_nat_access(ctx, &(spdat->nat_access));
    if(res != FKO_SUCCESS)
        return(res);

    res = fko_get_spa_server_auth(ctx, &(spdat->server_auth));
    if(res != FKO_SUCCESS)
        return(res);

    res = fko_get_spa_client_timeout(ctx, &(spdat->client_timeout));
    if(res != FKO_SUCCESS)
        return(res);

    return(res);
}

/* Process the SPA packet data
*/
int
incoming_spa(fko_srv_options_t *opts)
{
    /* Always a good idea to initialize ctx to null if it will be used
     * repeatedly (especially when using fko_new_with_data().
    */
    fko_ctx_t       ctx = NULL;

    char            *spa_ip_demark;
    time_t          now_ts;
    int             res, ts_diff, enc_type;

    spa_pkt_info_t *spa_pkt = &(opts->spa_pkt);

    /* This will hold our pertinent SPA data.
    */
    spa_data_t spadat;

    /* Get the access.conf data for the stanza that matches this incoming
     * source IP address.
    */
    acc_stanza_t   *acc = acc_check_source(opts, spa_pkt->packet_src_ip);

    inet_ntop(AF_INET, &(spa_pkt->packet_src_ip),
        spadat.pkt_source_ip, sizeof(spadat.pkt_source_ip));

    log_msg(LOG_INFO, "SPA packet from IP: %s received.", spadat.pkt_source_ip);

    if(acc == NULL)
    {
        log_msg(LOG_WARNING|LOG_STDERR,
            "No access data found for source IP: %s", spadat.pkt_source_ip
        );

        return(SPA_MSG_ACCESS_DENIED);
    }

    /* Sanity check
    */
    if(spa_pkt->packet_data_len <= 0)
        return(SPA_MSG_BAD_DATA);

/* --DSS temp */
//fprintf(stderr, "SPA Packet: '%s'\n", spa_pkt->packet_data);
/* --DSS temp */

    /* Reset the packet data length to 0.  This our indicator to the rest of
     * the program that we do not have a current spa packet to process
     * (which we won't by the time we return from this function for whatever
     * reason).
    */
    spa_pkt->packet_data_len = 0;

    /* Get encryption type and try its decoding routine first (if the key
     * for that type is set)
    */
    enc_type = fko_encryption_type(spa_pkt->packet_data);

    if(enc_type == FKO_ENCRYPTION_RIJNDAEL)
    {
        if(acc->key != NULL)
            res = fko_new_with_data(&ctx, spa_pkt->packet_data, acc->key);
        else 
        {
            log_msg(LOG_ERR|LOG_STDERR,
                "No KEY for RIJNDAEL encrypted messages");
            return(SPA_MSG_FKO_CTX_ERROR);
        }
    }
    else if(enc_type == FKO_ENCRYPTION_GPG)
    {
        /* For GPG we create the new context without decrypting on the fly
         * so we can set some  GPG parameters first.
        */
        if(acc->gpg_decrypt_pw != NULL)
        {
            res = fko_new_with_data(&ctx, spa_pkt->packet_data, NULL);
            if(res != FKO_SUCCESS)
            {
                log_msg(LOG_WARNING|LOG_STDERR,
                    "Error creating fko context (before decryption): %s",
                    fko_errstr(res)
                );
                return(SPA_MSG_FKO_CTX_ERROR);
            }

            /* Set whatever GPG parameters we have.
            */
            if(acc->gpg_home_dir != NULL)
                fko_set_gpg_home_dir(ctx, acc->gpg_home_dir);

            if(acc->gpg_decrypt_id != NULL)
                fko_set_gpg_recipient(ctx, acc->gpg_decrypt_id);

            /* If REMOTE_ID is set, validate and check the signer.  Otherwise,
             * skip and ignore verify errors.
             *
             * TODO: At present we are not checking signatures.
            */
            if(acc->gpg_remote_id != NULL)
            {
                /* TODO: Add sig verify code */

            /**  --DSS replace these with the real code     **/
            /**/  fko_set_gpg_signature_verify(ctx, 0);    /**/
            /**/  fko_set_gpg_ignore_verify_error(ctx, 1); /**/
            /**  --DSS replace these with the real code     **/

            }
            else
            {
                fko_set_gpg_signature_verify(ctx, 0);
                fko_set_gpg_ignore_verify_error(ctx, 1);
            }

            /* Now decrypt the data.
            */
            res = fko_decrypt_spa_data(ctx, acc->gpg_decrypt_pw);
        }
        else
        {
            log_msg(LOG_ERR|LOG_STDERR,
                "No GPG_DECRYPT_PW for GPG encrypted messages");
            return(SPA_MSG_FKO_CTX_ERROR);
        }
    }
    else
    {
        log_msg(LOG_ERR|LOG_STDERR, "Unable to determing encryption type. Got type=%i.",
            enc_type);
        return(SPA_MSG_FKO_CTX_ERROR);
    }

    /* Do we have a valid FKO context?
    */
    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_WARNING|LOG_STDERR, "Error creating fko context: %s",
            fko_errstr(res));

        if(IS_GPG_ERROR(res))
            log_msg(LOG_WARNING|LOG_STDERR, " - GPG ERROR: %s",
                fko_gpg_errstr(ctx));

        goto clean_and_bail;
    }

    /* At this point, we assume the SPA data is valid.  Now we need to see
     * if it meets our access criteria.
    */
/* --DSS temp */
//fprintf(stderr, "Decode res = %i\n", res);
//display_ctx(ctx);
/* --DSS temp */

    /* Check for replays if so configured.
    */
    if(strncasecmp(opts->config[CONF_ENABLE_DIGEST_PERSISTENCE], "Y", 1) == 0)
    {
        res = replay_check(opts, ctx);
        if(res != 0) /* non-zero means we have seen this packet before. */
            goto clean_and_bail;
    }

    /* Populate our spa data struct for future reference.
    */
    res = get_spa_data_fields(ctx, &spadat);

    spadat.fw_access_timeout = (acc->fw_access_timeout > 0)
        ? acc->fw_access_timeout : DEF_FW_ACCESS_TIMEOUT;

    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_ERR|LOG_STDERR, "Unexpected error pulling SPA data from the context: %s",
            fko_errstr(res));
        res = SPA_MSG_ERROR;
        goto clean_and_bail;
    }

    /* Check packet age if so configured.
    */
    if(strncasecmp(opts->config[CONF_ENABLE_SPA_PACKET_AGING], "Y", 1) == 0)
    {
        time(&now_ts);

        ts_diff = now_ts - spadat.timestamp;

        if(ts_diff > atoi(opts->config[CONF_MAX_SPA_PACKET_AGE]))
        {
            log_msg(LOG_WARNING|LOG_STDERR, "SPA data is too old (%i seconds).",
                ts_diff);
            res = SPA_MSG_TOO_OLD;
            goto clean_and_bail;
        }
    }

    /* At this point, we have enough to check the embedded (or packet source)
     * IP address against the defined access rights.  We start by splitting
     * the spa msg source IP from the remainder of the message.
    */
    spa_ip_demark = strchr(spadat.spa_message, ',');
    if(spa_ip_demark == NULL)
    {
        log_msg(LOG_WARNING|LOG_STDERR, "Error parsing SPA message string: %s",
            fko_errstr(res));
        res = SPA_MSG_ERROR;
        goto clean_and_bail;
    }

    strlcpy(spadat.spa_message_src_ip, spadat.spa_message, (spa_ip_demark - spadat.spa_message) + 1);
    strlcpy(spadat.spa_message_remain, spa_ip_demark+1, 1024);

    /* If use source IP was requested (embedded IP of 0.0.0.0), make sure it
     * is allowed.
    */
    if(strcmp(spadat.spa_message_src_ip, "0.0.0.0") == 0)
    {
        if(acc->require_source_address)
        {
            log_msg(LOG_WARNING|LOG_STDERR,
                "Got 0.0.0.0 when valid source IP was required."
            );
            res = SPA_MSG_ACCESS_DENIED;
            goto clean_and_bail;
        }

        spadat.use_src_ip = spadat.pkt_source_ip;
    }
    else
        spadat.use_src_ip = spadat.spa_message_src_ip;

    /* If REQUIRE_USERNAME is set, make sure the username in this SPA data
     * matches.
    */
    if(acc->require_username != NULL)
    {
        if(strcmp(spadat.username, acc->require_username) != 0)
        {
            log_msg(LOG_WARNING|LOG_STDERR,
                "Username in SPA data (%s) does not match required username: %s",
                spadat.username, acc->require_username
            );
            res = SPA_MSG_ACCESS_DENIED;
            goto clean_and_bail;
        }
    }

    /* Take action based on SPA message type.
    */
    switch(spadat.message_type)
    {
        /* Command messages.
        */
        case FKO_COMMAND_MSG:
            if(!acc->enable_cmd_exec)
            {
                log_msg(LOG_WARNING|LOG_STDERR,
                    "SPA Command message are not allowed in the current configuration."
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
            /* Check access against restrict_ports and open_ports.
            */
            res = acc_check_port_access(acc, spadat.spa_message_remain);

            if(!res)
            {
                log_msg(LOG_WARNING|LOG_STDERR,
                    "One or more requested protocol/ports was denied per access.conf."
                );
                res = SPA_MSG_ACCESS_DENIED;
            }
            else
            {
                /* Process the access message.
                */
                /* --DSS temp
                log_msg(LOG_WARNING|LOG_STDERR,
                    "<<<< This SPA access msg would be %s >>>>",
                    res ? "allowed":"DENIED due to port restictions"
                );
                res = SPA_MSG_NOT_SUPPORTED;
                */ 
                res = process_access_request(opts, &spadat);
            }
            break;
    }

    /* Send to the firewall rule processor.
    */
    // TODO: Finish me


clean_and_bail:
    if(ctx != NULL)
        fko_destroy(ctx);

    return(res);
}

/***EOF***/
