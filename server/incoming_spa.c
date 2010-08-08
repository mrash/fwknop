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
#include "netinet_common.h"

#if HAVE_SYS_WAIT_H
  #include <sys/wait.h>
#endif

#include "incoming_spa.h"
#include "access.h"
#include "extcmd.h"
#include "log_msg.h"
#include "utils.h"
#include "fw_util.h"
#include "fwknopd_errors.h"
#include "replay_dbm.h"

/* Validate and in some cases preprocess/reformat the SPA data.  Return an
 * error code value if there is any indication the data is not valid spa data.
*/
static int
preprocess_spa_data(fko_srv_options_t *opts, char *src_ip)
{
    spa_pkt_info_t *spa_pkt = &(opts->spa_pkt);

    char    *ndx = (char *)&(spa_pkt->packet_data);
    int      pkt_data_len = spa_pkt->packet_data_len;
    int      i;

    /* At this point, we can reset the packet data length to 0.  This our
     * indicator to the rest of the program that we do not have a current
     * spa packet to process (after this one that is).
    */
    spa_pkt->packet_data_len = 0;

    /* Expect the data to be at least the minimum required size.
    */
    if(pkt_data_len < MIN_SPA_DATA_SIZE)
        return(SPA_MSG_LEN_TOO_SMALL);

    /* Detect and parse out SPA data from an HTTP reqest. If the SPA data
     * starts with "GET /" and the user agent starts with "Fwknop", then
     * assume it is a SPA over HTTP request.
    */
    if(strncasecmp(ndx, "GET /", 5) == 0
      && strstr(ndx, "User-Agent: Fwknop") != NULL)
    {
        /* This looks like an HTTP request, so let's see if we are
         * configured to accept such request and if so, find the SPA
         * data.
        */
        if(strncasecmp(opts->config[CONF_ENABLE_SPA_OVER_HTTP], "N", 1) == 0)
        {
            log_msg(LOG_WARNING,
                "HTTP request from %s detected, but not enabled.", src_ip
            );
            return(SPA_MSG_HTTP_NOT_ENABLED);
        }

        /* Now extract, adjust (convert characters translated by the fwknop
         * client), and reset the SPA message itself.
        */
        strlcpy((char *)spa_pkt->packet_data, ndx+5, pkt_data_len);

        for(i=0; i<pkt_data_len; i++)
        {
            if(isspace(*ndx)) /* The first space marks the end of the req */
            {
                *ndx = '\0';
                break;
            }
            else if(*ndx == '-') /* Convert '-' to '+' */
                *ndx = '+';
            else if(*ndx == '_') /* Convert '_' to '/' */
                *ndx = '/';
            /* Make sure it is a valid base64 char. */
            else if(!(isalnum(*ndx) || *ndx == '/' || *ndx == '+' || *ndx == '='))
                return(SPA_MSG_NOT_SPA_DATA);

            ndx++;
        }
    }
    else
    {
        /* Make sure the data is valid Base64-encoded characters
        * (at least the first MIN_SPA_DATA_SIZE bytes).
        */
        ndx = (char *)spa_pkt->packet_data;
        for(i=0; i<MIN_SPA_DATA_SIZE; i++)
        {
            if(!(isalnum(*ndx) || *ndx == '/' || *ndx == '+' || *ndx == '='))
                return(SPA_MSG_NOT_SPA_DATA);
            ndx++;
        }
    }

    /* --DSS:  Are there other checks we can do here ??? */

    /* If we made it here, we have no reason to assume this is not SPA data
     * (at least until we come up with more checks).
    */
    return(FKO_SUCCESS);
}

/* Popluate a spa_data struct from an initialized (and populated) FKO context.
*/
static int
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

    res = fko_get_spa_client_timeout(ctx, (int *)&(spdat->client_timeout));
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

    char            *spa_ip_demark, *gpg_id;
    time_t          now_ts;
    int             res, status, ts_diff, enc_type;

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

    /* At this point, we want to validate and (if needed) preprocess the
     * SPA data and/or to be reasonably sure we have a SPA packet (i.e
     * try to eliminate obvious non-spa packets).
    */
    res = preprocess_spa_data(opts, spadat.pkt_source_ip);
    if(res != FKO_SUCCESS)
        return(SPA_MSG_NOT_SPA_DATA);

    log_msg(LOG_INFO, "SPA Packet from IP: %s received.", spadat.pkt_source_ip);

    if(acc == NULL)
    {
        log_msg(LOG_WARNING,
            "No access data found for source IP: %s", spadat.pkt_source_ip
        );

        return(SPA_MSG_ACCESS_DENIED);
    }

    if(opts->verbose > 1)
        log_msg(LOG_INFO, "SPA Packet: '%s'\n", spa_pkt->packet_data);

    /* Get encryption type and try its decoding routine first (if the key
     * for that type is set)
    */
    enc_type = fko_encryption_type((char *)spa_pkt->packet_data);

    if(enc_type == FKO_ENCRYPTION_RIJNDAEL)
    {
        if(acc->key != NULL)
            res = fko_new_with_data(&ctx, (char *)spa_pkt->packet_data, acc->key);
        else 
        {
            log_msg(LOG_ERR,
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
            res = fko_new_with_data(&ctx, (char *)spa_pkt->packet_data, NULL);
            if(res != FKO_SUCCESS)
            {
                log_msg(LOG_WARNING,
                    "Error creating fko context (before decryption): %s",
                    fko_errstr(res)
                );
                return(SPA_MSG_FKO_CTX_ERROR);
            }

            /* Set whatever GPG parameters we have.
            */
            if(acc->gpg_home_dir != NULL)
                res = fko_set_gpg_home_dir(ctx, acc->gpg_home_dir);
                if(res != FKO_SUCCESS)
                {
                    log_msg(LOG_WARNING,
                        "Error setting GPG keyring path to %s: %s",
                        acc->gpg_home_dir,
                        fko_errstr(res)
                    );
                    return(SPA_MSG_FKO_CTX_ERROR);
                }

            if(acc->gpg_decrypt_id != NULL)
                fko_set_gpg_recipient(ctx, acc->gpg_decrypt_id);

            /* If GPG_REQUIRE_SIG is set for this acc stanza, then set
             * the FKO context accordingly and check the other GPG Sig-
             * related parameters. This also applies when REMOTE_ID is
             * set.
            */
            if(acc->gpg_require_sig)
            {
                fko_set_gpg_signature_verify(ctx, 1);

                /* Set whether or not to ignore signature verification errors.
                */
                fko_set_gpg_ignore_verify_error(ctx, acc->gpg_ignore_sig_error);
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
            log_msg(LOG_ERR,
                "No GPG_DECRYPT_PW for GPG encrypted messages");
            return(SPA_MSG_FKO_CTX_ERROR);
        }
    }
    else
    {
        log_msg(LOG_ERR, "Unable to determing encryption type. Got type=%i.",
            enc_type);
        return(SPA_MSG_FKO_CTX_ERROR);
    }

    /* Do we have a valid FKO context?
    */
    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_WARNING, "Error creating fko context: %s",
            fko_errstr(res));

        if(IS_GPG_ERROR(res))
            log_msg(LOG_WARNING, " - GPG ERROR: %s",
                fko_gpg_errstr(ctx));

        goto clean_and_bail;
    }

    /* At this point, we assume the SPA data is valid.  Now we need to see
     * if it meets our access criteria.
    */
    if(opts->verbose > 2)
        log_msg(LOG_INFO, "SPA Decode (res=%i):\n%s", res, dump_ctx(ctx));

    /* First, if this is a GPG message, and GPG_REMOTE_ID list is not empty,
     * then we need to make sure this incoming message is signer ID matches
     * an entry in the list.
    */
    if(enc_type == FKO_ENCRYPTION_GPG && acc->gpg_require_sig)
    {
        res = fko_get_gpg_signature_id(ctx, &gpg_id);
        if(res != FKO_SUCCESS)
        {
            log_msg(LOG_WARNING, "Error pulling the GPG signature ID from the context: %s",
                fko_gpg_errstr(ctx));
            goto clean_and_bail;
        }
 
        if(opts->verbose)
        log_msg(LOG_INFO, "Incoming SPA data signed by '%s'.", gpg_id);

        if(acc->gpg_remote_id != NULL && !acc_check_gpg_remote_id(acc, gpg_id))
        {
            log_msg(LOG_WARNING,
                "Incoming SPA packet signed by ID: %s, but that ID is not the GPG_REMOTE_ID list.",
                gpg_id);
            goto clean_and_bail;
        }
    }

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

    /* Figure out what our timeout will be. If it is specified in the SPA
     * data, then use that.  If not, try the FW_ACCESS_TIMEOUT from the
     * access.conf file (if there is one).  Otherwise use the default.
    */
    if(spadat.client_timeout > 0)
        spadat.fw_access_timeout = spadat.client_timeout;
    else if(acc->fw_access_timeout > 0)
        spadat.fw_access_timeout = acc->fw_access_timeout;
    else
        spadat.fw_access_timeout = DEF_FW_ACCESS_TIMEOUT;

    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "Unexpected error pulling SPA data from the context: %s",
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
            log_msg(LOG_WARNING, "SPA data is too old (%i seconds).",
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
        log_msg(LOG_WARNING, "Error parsing SPA message string: %s",
            fko_errstr(res));
        res = SPA_MSG_ERROR;
        goto clean_and_bail;
    }

    strlcpy(spadat.spa_message_src_ip, spadat.spa_message, (spa_ip_demark-spadat.spa_message)+1);
    strlcpy(spadat.spa_message_remain, spa_ip_demark+1, 1024);

    /* If use source IP was requested (embedded IP of 0.0.0.0), make sure it
     * is allowed.
    */
    if(strcmp(spadat.spa_message_src_ip, "0.0.0.0") == 0)
    {
        if(acc->require_source_address)
        {
            log_msg(LOG_WARNING,
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
            log_msg(LOG_WARNING,
                "Username in SPA data (%s) does not match required username: %s",
                spadat.username, acc->require_username
            );
            res = SPA_MSG_ACCESS_DENIED;
            goto clean_and_bail;
        }
    }

    /* Take action based on SPA message type.  */

    /* Command messages.
    */
    if(spadat.message_type == FKO_COMMAND_MSG)
    {
        if(!acc->enable_cmd_exec)
        {
            log_msg(LOG_WARNING,
                "SPA Command message are not allowed in the current configuration."
            );
            res = SPA_MSG_ACCESS_DENIED;
        }
        else
        {
            log_msg(LOG_INFO,
                "Processing SPA Command message: command='%s'.",
                spadat.spa_message_remain
            );

            /* Do we need to become another user? If so, we call
             * run_extcmd_as and pass the cmd_exec_uid.
            */
            if(acc->cmd_exec_user != NULL && strncasecmp(acc->cmd_exec_user, "root", 4) != 0)
            {
                if(opts->verbose)
                    log_msg(LOG_INFO, "Setting effective user to %s (UID=%i) before running command.",
                        acc->cmd_exec_user, acc->cmd_exec_uid);


                res = run_extcmd_as(acc->cmd_exec_uid,
                                    spadat.spa_message_remain, NULL, 0, 0);
            }
            else /* Just run it as we are (root that is). */
                res = run_extcmd(spadat.spa_message_remain, NULL, 0, 5);

            /* --DSS XXX: I have found that the status (and res for that
             *            matter) have been unreliable indicators of the
             *            actual exit status of some commands.  Not sure
             *            why yet.  For now, we will take what we get.
            */
            status = WEXITSTATUS(res);

            if(opts->verbose > 2)
                log_msg(LOG_WARNING,
                    "CMD_EXEC: command returned %i", status);

            if(status != 0)
                res = SPA_MSG_COMMAND_ERROR;
        }

        goto clean_and_bail;
    }

    /* From this point forward, we have some kind of access message. So
     * we first see if access is allowed by checking access against
     * restrict_ports and open_ports.
     *
     *  --DSS TODO: We should add BLACKLIST support here as well.
    */
    if(! acc_check_port_access(acc, spadat.spa_message_remain))
    {
        log_msg(LOG_WARNING,
            "One or more requested protocol/ports was denied per access.conf."
        );

        res = SPA_MSG_ACCESS_DENIED;

        goto clean_and_bail;       
    }

    /* At this point, we can process the SPA request.
    */
    res = process_spa_request(opts, &spadat);

clean_and_bail:
    if(ctx != NULL)
        fko_destroy(ctx);

    return(res);
}

/***EOF***/
