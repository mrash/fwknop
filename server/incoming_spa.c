/*
 *****************************************************************************
 *
 * File:    incoming_spa.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Process an incoming SPA data packet for fwknopd.
 *
 * Copyright 2010 Damien Stuart (dstuart@dstuart.org)
 *
 *  License (GNU Public License):
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
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
#include "replay_cache.h"

/* Validate and in some cases preprocess/reformat the SPA data.  Return an
 * error code value if there is any indication the data is not valid spa data.
*/
static int
preprocess_spa_data(fko_srv_options_t *opts, const char *src_ip)
{
    spa_pkt_info_t *spa_pkt = &(opts->spa_pkt);

    char    *ndx = (char *)&(spa_pkt->packet_data);
    int      pkt_data_len = spa_pkt->packet_data_len;
    int      i;

    /* At this point, we can reset the packet data length to 0.  This is our
     * indicator to the rest of the program that we do not have a current
     * spa packet to process (after this one that is).
    */
    spa_pkt->packet_data_len = 0;

    /* Ignore any SPA packets that contain the Rijndael or GnuPG prefixes
     * since an attacker might have tacked them on to a previously seen
     * SPA packet in an attempt to get past the replay check.  And, we're
     * no worse off since a legitimate SPA packet that happens to include
     * a prefix after the outer one is stripped off won't decrypt properly
     * anyway because libfko would not add a new one.
    */
    if(strncmp(ndx, B64_RIJNDAEL_SALT, B64_RIJNDAEL_SALT_STR_LEN) == 0)
        return(SPA_MSG_BAD_DATA);

    if(pkt_data_len > MIN_GNUPG_MSG_SIZE
            && strncmp(ndx, B64_GPG_PREFIX, B64_GPG_PREFIX_STR_LEN) == 0)
        return(SPA_MSG_BAD_DATA);

    /* Detect and parse out SPA data from an HTTP request. If the SPA data
     * starts with "GET /" and the user agent starts with "Fwknop", then
     * assume it is a SPA over HTTP request.
    */
    if(strncasecmp(opts->config[CONF_ENABLE_SPA_OVER_HTTP], "N", 1) == 0
      && strncasecmp(ndx, "GET /", 5) == 0
      && strstr(ndx, "User-Agent: Fwknop") != NULL)
    {
        /* This looks like an HTTP request, so let's see if we are
         * configured to accept such request and if so, find the SPA
         * data.
        */

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

            ndx++;
        }
    }

    /* Require base64-encoded data
    */
    if(! is_base64(spa_pkt->packet_data, pkt_data_len))
        return(SPA_MSG_NOT_SPA_DATA);


    /* --DSS:  Are there other checks we can do here ??? */

    /* If we made it here, we have no reason to assume this is not SPA data
     * (at least until we come up with more checks).
    */
    return(FKO_SUCCESS);
}

/* For replay attack detection
*/
static int
get_raw_digest(char **digest, char *pkt_data)
{
    fko_ctx_t    ctx = NULL;
    char        *tmp_digest = NULL;
    int          res = FKO_SUCCESS;

    /* initialize an FKO context with no decryption key just so
     * we can get the outer message digest
    */
    res = fko_new_with_data(&ctx, (char *)pkt_data, NULL);
    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_WARNING, "Error initializing FKO context from SPA data: %s",
            fko_errstr(res));
        fko_destroy(ctx);
        return(SPA_MSG_FKO_CTX_ERROR);
    }

    res = fko_set_raw_spa_digest_type(ctx, FKO_DEFAULT_DIGEST);
    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_WARNING, "Error setting digest type for SPA data: %s",
            fko_errstr(res));
        fko_destroy(ctx);
        return(SPA_MSG_DIGEST_ERROR);
    }

    res = fko_set_raw_spa_digest(ctx);
    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_WARNING, "Error setting digest for SPA data: %s",
            fko_errstr(res));
        fko_destroy(ctx);
        return(SPA_MSG_DIGEST_ERROR);
    }

    res = fko_get_raw_spa_digest(ctx, &tmp_digest);
    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_WARNING, "Error getting digest from SPA data: %s",
            fko_errstr(res));
        fko_destroy(ctx);
        return(SPA_MSG_DIGEST_ERROR);
    }

    *digest = strdup(tmp_digest);

    if (digest == NULL)
        return SPA_MSG_ERROR;

    fko_destroy(ctx);

    return res;
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

/* Check for access.conf stanza SOURCE match based on SPA packet
 * source IP
*/
static int
is_src_match(acc_stanza_t *acc, const uint32_t ip)
{
    while (acc)
    {
        if(compare_addr_list(acc->source_list, ip))
            return 1;

        acc = acc->next;
    }
    return 0;
}

/* Process the SPA packet data
*/
void
incoming_spa(fko_srv_options_t *opts)
{
    /* Always a good idea to initialize ctx to null if it will be used
     * repeatedly (especially when using fko_new_with_data()).
    */
    fko_ctx_t       ctx = NULL;

    char            *spa_ip_demark, *gpg_id, *raw_digest = NULL;
    time_t          now_ts;
    int             res, status, ts_diff, enc_type, stanza_num=0;
    int             added_replay_digest = 0;

    spa_pkt_info_t *spa_pkt = &(opts->spa_pkt);

    /* This will hold our pertinent SPA data.
    */
    spa_data_t spadat;

    /* Loop through all access stanzas looking for a match
    */
    acc_stanza_t    *acc = opts->acc_stanzas;

    inet_ntop(AF_INET, &(spa_pkt->packet_src_ip),
        spadat.pkt_source_ip, sizeof(spadat.pkt_source_ip));

    /* At this point, we want to validate and (if needed) preprocess the
     * SPA data and/or to be reasonably sure we have a SPA packet (i.e
     * try to eliminate obvious non-spa packets).
    */
    res = preprocess_spa_data(opts, spadat.pkt_source_ip);
    if(res != FKO_SUCCESS)
    {
        if(opts->verbose > 1)
            log_msg(LOG_INFO, "preprocess_spa_data() returned error %i: '%s' for incoming packet.",
                res, get_errstr(res));
        return;
    }

    if (is_src_match(opts->acc_stanzas, ntohl(spa_pkt->packet_src_ip)))
    {
        if(strncasecmp(opts->config[CONF_ENABLE_DIGEST_PERSISTENCE], "Y", 1) == 0)
            /* Check for a replay attack
            */
            res = get_raw_digest(&raw_digest, (char *)spa_pkt->packet_data);
            if(res != FKO_SUCCESS)
            {
                if (raw_digest != NULL)
                    free(raw_digest);
                return;
            }
            if (raw_digest == NULL)
                return;

            if (is_replay(opts, raw_digest) != SPA_MSG_SUCCESS)
            {
                free(raw_digest);
                return;
            }
    }
    else
    {
        log_msg(LOG_WARNING,
            "No access data found for source IP: %s", spadat.pkt_source_ip
        );
        return;
    }

    /* Now that we know there is a matching access.conf stanza and the
     * incoming SPA packet is not a replay, see if we should grant any
     * access
    */
    while(acc)
    {
        stanza_num++;

        /* Check for a match for the SPA source IP and the access stanza
        */
        if(! compare_addr_list(acc->source_list, ntohl(spa_pkt->packet_src_ip)))
        {
            acc = acc->next;
            continue;
        }

        log_msg(LOG_INFO, "(stanza #%d) SPA Packet from IP: %s received with access source match",
            stanza_num, spadat.pkt_source_ip);

        if(opts->verbose > 1)
            log_msg(LOG_INFO, "SPA Packet: '%s'\n", spa_pkt->packet_data);

        /* Make sure this access stanza has not expired
        */
        if(acc->access_expire_time > 0)
        {
            if(acc->expired)
            {
                acc = acc->next;
                continue;
            }
            else
            {
                if(time(NULL) > acc->access_expire_time)
                {
                    log_msg(LOG_INFO, "(stanza #%d) Access stanza has expired",
                        stanza_num);
                    acc->expired = 1;
                    acc = acc->next;
                    continue;
                }
            }
        }

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
                    "(stanza #%d) No KEY for RIJNDAEL encrypted messages",
                    stanza_num
                );
                acc = acc->next;
                continue;
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
                        "(stanza #%d) Error creating fko context (before decryption): %s",
                        stanza_num, fko_errstr(res)
                    );
                    acc = acc->next;
                    continue;
                }

                /* Set whatever GPG parameters we have.
                */
                if(acc->gpg_home_dir != NULL)
                    res = fko_set_gpg_home_dir(ctx, acc->gpg_home_dir);
                    if(res != FKO_SUCCESS)
                    {
                        log_msg(LOG_WARNING,
                            "(stanza #%d) Error setting GPG keyring path to %s: %s",
                            stanza_num, acc->gpg_home_dir, fko_errstr(res)
                        );
                        acc = acc->next;
                        continue;
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
                    "(stanza #%d) No GPG_DECRYPT_PW for GPG encrypted messages",
                    stanza_num
                );
                acc = acc->next;
                continue;
            }
        }
        else
        {
            log_msg(LOG_ERR, "(stanza #%d) Unable to determing encryption type. Got type=%i.",
                stanza_num, enc_type);
            acc = acc->next;
            continue;
        }

        /* Do we have a valid FKO context?  Did the SPA decrypt properly?
        */
        if(res != FKO_SUCCESS)
        {
            log_msg(LOG_WARNING, "(stanza #%d) Error creating fko context: %s",
                stanza_num, fko_errstr(res));

            if(IS_GPG_ERROR(res))
                log_msg(LOG_WARNING, "(stanza #%d) - GPG ERROR: %s",
                    stanza_num, fko_gpg_errstr(ctx));

            if(ctx != NULL)
                fko_destroy(ctx);
            acc = acc->next;
            continue;
        }

        /* Add this SPA packet into the replay detection cache
        */
        if (! added_replay_digest)
        {
            res = add_replay(opts, raw_digest);
            if (res != SPA_MSG_SUCCESS)
            {
                log_msg(LOG_WARNING, "(stanza #%d) Could not add digest to replay cache",
                    stanza_num);
                if(ctx != NULL)
                    fko_destroy(ctx);
                acc = acc->next;
                continue;
            }
            added_replay_digest = 1;
        }

        /* At this point, we assume the SPA data is valid.  Now we need to see
         * if it meets our access criteria.
        */
        if(opts->verbose > 1)
            log_msg(LOG_INFO, "(stanza #%d) SPA Decode (res=%i):\n%s",
                stanza_num, res, dump_ctx(ctx));

        /* First, if this is a GPG message, and GPG_REMOTE_ID list is not empty,
         * then we need to make sure this incoming message is signer ID matches
         * an entry in the list.
        */
        if(enc_type == FKO_ENCRYPTION_GPG && acc->gpg_require_sig)
        {
            res = fko_get_gpg_signature_id(ctx, &gpg_id);
            if(res != FKO_SUCCESS)
            {
                log_msg(LOG_WARNING, "(stanza #%d) Error pulling the GPG signature ID from the context: %s",
                    stanza_num, fko_gpg_errstr(ctx));
                if(ctx != NULL)
                    fko_destroy(ctx);
                acc = acc->next;
                continue;
            }

            if(opts->verbose)
                log_msg(LOG_INFO, "(stanza #%d) Incoming SPA data signed by '%s'.",
                    stanza_num, gpg_id);

            if(acc->gpg_remote_id != NULL && !acc_check_gpg_remote_id(acc, gpg_id))
            {
                log_msg(LOG_WARNING,
                    "(stanza #%d) Incoming SPA packet signed by ID: %s, but that ID is not the GPG_REMOTE_ID list.",
                    stanza_num, gpg_id);
                if(ctx != NULL)
                    fko_destroy(ctx);
                acc = acc->next;
                continue;
            }
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
            log_msg(LOG_ERR, "(stanza #%d) Unexpected error pulling SPA data from the context: %s",
                stanza_num, fko_errstr(res));

            if(ctx != NULL)
                fko_destroy(ctx);
            acc = acc->next;
            continue;
        }

        /* Check packet age if so configured.
        */
        if(strncasecmp(opts->config[CONF_ENABLE_SPA_PACKET_AGING], "Y", 1) == 0)
        {
            time(&now_ts);

            ts_diff = abs(now_ts - spadat.timestamp);

            if(ts_diff > atoi(opts->config[CONF_MAX_SPA_PACKET_AGE]))
            {
                log_msg(LOG_WARNING, "(stanza #%d) SPA data time difference is too great (%i seconds).",
                    stanza_num, ts_diff);

                if(ctx != NULL)
                    fko_destroy(ctx);
                acc = acc->next;
                continue;
            }
        }

        /* At this point, we have enough to check the embedded (or packet source)
         * IP address against the defined access rights.  We start by splitting
         * the spa msg source IP from the remainder of the message.
        */
        spa_ip_demark = strchr(spadat.spa_message, ',');
        if(spa_ip_demark == NULL)
        {
            log_msg(LOG_WARNING, "(stanza #%d) Error parsing SPA message string: %s",
                stanza_num, fko_errstr(res));

            if(ctx != NULL)
                fko_destroy(ctx);
            acc = acc->next;
            continue;
        }

        strlcpy(spadat.spa_message_src_ip,
            spadat.spa_message, (spa_ip_demark-spadat.spa_message)+1);

        if(strnlen(spadat.spa_message_src_ip,
                MIN_IPV4_STR_LEN) < MIN_IPV4_STR_LEN)
        {
            log_msg(LOG_WARNING, "(stanza #%d) Invalid source IP in SPA message, ignoring SPA packet",
                stanza_num, fko_errstr(res));

            if(ctx != NULL)
                fko_destroy(ctx);
            acc = acc->next;
            break;
        }

        strlcpy(spadat.spa_message_remain, spa_ip_demark+1, 1024);

        /* If use source IP was requested (embedded IP of 0.0.0.0), make sure it
         * is allowed.
        */
        if(strcmp(spadat.spa_message_src_ip, "0.0.0.0") == 0)
        {
            if(acc->require_source_address)
            {
                log_msg(LOG_WARNING,
                    "(stanza #%d) Got 0.0.0.0 when valid source IP was required.",
                    stanza_num
                );

                if(ctx != NULL)
                    fko_destroy(ctx);
                acc = acc->next;
                continue;
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
                    "(stanza #%d) Username in SPA data (%s) does not match required username: %s",
                    stanza_num, spadat.username, acc->require_username
                );

                if(ctx != NULL)
                    fko_destroy(ctx);
                acc = acc->next;
                continue;
            }
        }

        /* Take action based on SPA message type.
        */
        if(spadat.message_type == FKO_LOCAL_NAT_ACCESS_MSG
              || spadat.message_type == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG
              || spadat.message_type == FKO_NAT_ACCESS_MSG
              || spadat.message_type == FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG)
        {
#if FIREWALL_IPTABLES
            if(strncasecmp(opts->config[CONF_ENABLE_IPT_FORWARDING], "Y", 1)!=0)
            {
                log_msg(LOG_WARNING,
                    "(stanza #%d) SPA packet from %s requested NAT access, but is not enabled",
                    stanza_num, spadat.pkt_source_ip
                );

                if(ctx != NULL)
                    fko_destroy(ctx);
                acc = acc->next;
                continue;
            }
#else
            log_msg(LOG_WARNING,
                "(stanza #%d) SPA packet from %s requested unsupported NAT access",
                stanza_num, spadat.pkt_source_ip
            );

            if(ctx != NULL)
                fko_destroy(ctx);
            acc = acc->next;
            continue;
#endif
        }

        /* Command messages.
        */
        if(spadat.message_type == FKO_COMMAND_MSG)
        {
            if(!acc->enable_cmd_exec)
            {
                log_msg(LOG_WARNING,
                    "(stanza #%d) SPA Command message are not allowed in the current configuration.",
                    stanza_num
                );

                if(ctx != NULL)
                    fko_destroy(ctx);
                acc = acc->next;
                continue;
            }
            else
            {
                log_msg(LOG_INFO,
                    "(stanza #%d) Processing SPA Command message: command='%s'.",
                    stanza_num, spadat.spa_message_remain
                );

                /* Do we need to become another user? If so, we call
                 * run_extcmd_as and pass the cmd_exec_uid.
                */
                if(acc->cmd_exec_user != NULL && strncasecmp(acc->cmd_exec_user, "root", 4) != 0)
                {
                    if(opts->verbose)
                        log_msg(LOG_INFO, "(stanza #%d) Setting effective user to %s (UID=%i) before running command.",
                            stanza_num, acc->cmd_exec_user, acc->cmd_exec_uid);


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

                if(opts->verbose > 1)
                    log_msg(LOG_WARNING,
                        "(stanza #%d) CMD_EXEC: command returned %i",
                        stanza_num, status);

                if(status != 0)
                    res = SPA_MSG_COMMAND_ERROR;

                if(ctx != NULL)
                    fko_destroy(ctx);

                /* we processed the command on a matching access stanza, so we
                 * don't look for anything else to do with this SPA packet
                */
                break;
            }
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
                "(stanza #%d) One or more requested protocol/ports was denied per access.conf.",
                stanza_num
            );

            if(ctx != NULL)
                fko_destroy(ctx);
            acc = acc->next;
            continue;
        }

        /* At this point, we process the SPA request and break out of the
         * access stanza loop (first valid access stanza stops us looking
         * for others).
        */
        process_spa_request(opts, acc, &spadat);
        if(ctx != NULL)
            fko_destroy(ctx);
        break;
    }

    if (raw_digest != NULL)
        free(raw_digest);

    return;
}

/***EOF***/
