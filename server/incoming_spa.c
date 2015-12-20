/*
 *****************************************************************************
 *
 * File:    incoming_spa.c
 *
 * Purpose: Process an incoming SPA data packet for fwknopd.
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2014 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
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
#include "cmd_cycle.h"
#include "log_msg.h"
#include "utils.h"
#include "fw_util.h"
#include "fwknopd_errors.h"
#include "replay_cache.h"

#define CTX_DUMP_BUFSIZE            4096                /*!< Maximum size allocated to a FKO context dump */

/* Validate and in some cases preprocess/reformat the SPA data.  Return an
 * error code value if there is any indication the data is not valid spa data.
*/
static int
preprocess_spa_data(const fko_srv_options_t *opts, spa_pkt_info_t *spa_pkt, spa_data_t *spadat)
{

    char    *ndx = (char *)&(spa_pkt->packet_data);
    char    *xff;
    int      i, pkt_data_len = 0;

    pkt_data_len = spa_pkt->packet_data_len;

    /* At this point, we can reset the packet data length to 0.  This is our
     * indicator to the rest of the program that we do not have a current
     * spa packet to process (after this one that is).
    */
    spa_pkt->packet_data_len = 0;

    /* These two checks are already done in process_packet(), but this is a
     * defensive measure to run them again here
    */
    if(pkt_data_len < MIN_SPA_DATA_SIZE)
        return(SPA_MSG_BAD_DATA);

    if(pkt_data_len > MAX_SPA_PACKET_LEN)
        return(SPA_MSG_BAD_DATA);

    /* Ignore any SPA packets that contain the Rijndael or GnuPG prefixes
     * since an attacker might have tacked them on to a previously seen
     * SPA packet in an attempt to get past the replay check.  And, we're
     * no worse off since a legitimate SPA packet that happens to include
     * a prefix after the outer one is stripped off won't decrypt properly
     * anyway because libfko would not add a new one.
    */
    if(constant_runtime_cmp(ndx, B64_RIJNDAEL_SALT, B64_RIJNDAEL_SALT_STR_LEN) == 0)
        return(SPA_MSG_BAD_DATA);

    if(pkt_data_len > MIN_GNUPG_MSG_SIZE
            && constant_runtime_cmp(ndx, B64_GPG_PREFIX, B64_GPG_PREFIX_STR_LEN) == 0)
        return(SPA_MSG_BAD_DATA);

    /* Initialize X-Forwarded-For field */
    spadat->pkt_source_xff_ip[0] = '\0';

    /* Detect and parse out SPA data from an HTTP request. If the SPA data
     * starts with "GET /" and the user agent starts with "Fwknop", then
     * assume it is a SPA over HTTP request.
    */
    if(strncasecmp(opts->config[CONF_ENABLE_SPA_OVER_HTTP], "Y", 1) == 0
      && strncasecmp(ndx, "GET /", 5) == 0
      && strstr(ndx, "User-Agent: Fwknop") != NULL)
    {
        /* This looks like an HTTP request, so let's see if we are
         * configured to accept such request and if so, find the SPA
         * data.
        */

        /* Process X-Forwarded-For header */

        xff = strcasestr(ndx, "X-Forwarded-For: ");

        if (xff != NULL) {
            xff += 17;

            for (i = 0; *xff != '\0'; i++)
                if (isspace(*xff))
                   *xff = '\0';
                else
                   xff++;

            xff -= i - 1;

            if (!is_valid_ipv4_addr(xff))
                log_msg(LOG_WARNING,
                "Error parsing X-Forwarded-For header: value '%s' is not an IP address",
                xff);
            else
                strlcpy(spadat->pkt_source_xff_ip, xff, i);
        }

        /* Now extract, adjust (convert characters translated by the fwknop
         * client), and reset the SPA message itself.
        */
        strlcpy((char *)spa_pkt->packet_data, ndx+5, pkt_data_len);
        pkt_data_len -= 5;

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

        if(i < MIN_SPA_DATA_SIZE)
            return(SPA_MSG_BAD_DATA);

        spa_pkt->packet_data_len = pkt_data_len = i;
    }

    /* Require base64-encoded data
    */
    if(! is_base64(spa_pkt->packet_data, pkt_data_len))
        return(SPA_MSG_NOT_SPA_DATA);


    /* If we made it here, we have no reason to assume this is not SPA data.
     * The ultimate test will be whether the SPA data authenticates via an
     * HMAC anyway.
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
    short        raw_digest_type = -1;

    /* initialize an FKO context with no decryption key just so
     * we can get the outer message digest
    */
    res = fko_new_with_data(&ctx, (char *)pkt_data, NULL, 0,
            FKO_DEFAULT_ENC_MODE, NULL, 0, 0);

    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_WARNING, "Error initializing FKO context from SPA data: %s",
            fko_errstr(res));
        fko_destroy(ctx);
        ctx = NULL;
        return(SPA_MSG_FKO_CTX_ERROR);
    }

    res = fko_set_raw_spa_digest_type(ctx, FKO_DEFAULT_DIGEST);
    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_WARNING, "Error setting digest type for SPA data: %s",
            fko_errstr(res));
        fko_destroy(ctx);
        ctx = NULL;
        return(SPA_MSG_DIGEST_ERROR);
    }

    res = fko_get_raw_spa_digest_type(ctx, &raw_digest_type);
    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_WARNING, "Error getting digest type for SPA data: %s",
            fko_errstr(res));
        fko_destroy(ctx);
        ctx = NULL;
        return(SPA_MSG_DIGEST_ERROR);
    }

    /* Make sure the digest type is what we expect
    */
    if(raw_digest_type != FKO_DEFAULT_DIGEST)
    {
        log_msg(LOG_WARNING, "Error setting digest type for SPA data: %s",
            fko_errstr(res));
        fko_destroy(ctx);
        ctx = NULL;
        return(SPA_MSG_DIGEST_ERROR);
    }

    res = fko_set_raw_spa_digest(ctx);
    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_WARNING, "Error setting digest for SPA data: %s",
            fko_errstr(res));
        fko_destroy(ctx);
        ctx = NULL;
        return(SPA_MSG_DIGEST_ERROR);
    }

    res = fko_get_raw_spa_digest(ctx, &tmp_digest);
    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_WARNING, "Error getting digest from SPA data: %s",
            fko_errstr(res));
        fko_destroy(ctx);
        ctx = NULL;
        return(SPA_MSG_DIGEST_ERROR);
    }

    *digest = strdup(tmp_digest);

    if (*digest == NULL)
        res = SPA_MSG_ERROR;  /* really a strdup() memory allocation problem */

    fko_destroy(ctx);
    ctx = NULL;

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

static int
check_pkt_age(const fko_srv_options_t *opts, spa_data_t *spadat,
        const int stanza_num)
{
    int         ts_diff;
    time_t      now_ts;

    if(strncasecmp(opts->config[CONF_ENABLE_SPA_PACKET_AGING], "Y", 1) == 0)
    {
        time(&now_ts);

        ts_diff = labs(now_ts - spadat->timestamp);

        if(ts_diff > opts->max_spa_packet_age)
        {
            log_msg(LOG_WARNING, "[%s] (stanza #%d) SPA data time difference is too great (%i seconds).",
                spadat->pkt_source_ip, stanza_num, ts_diff);
            return 0;
        }
    }
    return 1;
}

static int
check_stanza_expiration(acc_stanza_t *acc, spa_data_t *spadat,
        const int stanza_num)
{
    if(acc->access_expire_time > 0)
    {
        if(acc->expired)
        {
            return 0;
        }
        else
        {
            if(time(NULL) > acc->access_expire_time)
            {
                log_msg(LOG_INFO, "[%s] (stanza #%d) Access stanza has expired",
                    spadat->pkt_source_ip, stanza_num);
                acc->expired = 1;
                return 0;
            }
        }
    }
    return 1;
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

static int
src_check(fko_srv_options_t *opts, spa_pkt_info_t *spa_pkt,
        spa_data_t *spadat, char **raw_digest)
{
    if (is_src_match(opts->acc_stanzas, ntohl(spa_pkt->packet_src_ip)))
    {
        if(strncasecmp(opts->config[CONF_ENABLE_DIGEST_PERSISTENCE], "Y", 1) == 0)
        {
            /* Check for a replay attack
            */
            if(get_raw_digest(raw_digest, (char *)spa_pkt->packet_data) != FKO_SUCCESS)
            {
                if (*raw_digest != NULL)
                    free(*raw_digest);
                return 0;
            }
            if (*raw_digest == NULL)
                return 0;

            if (is_replay(opts, *raw_digest) != SPA_MSG_SUCCESS)
            {
                free(*raw_digest);
                return 0;
            }
        }
    }
    else
    {
        log_msg(LOG_WARNING,
            "No access data found for source IP: %s", spadat->pkt_source_ip
        );
        return 0;
    }
    return 1;
}

static int
precheck_pkt(fko_srv_options_t *opts, spa_pkt_info_t *spa_pkt,
        spa_data_t *spadat, char **raw_digest)
{
    int res = 0, packet_data_len = 0;

    packet_data_len = spa_pkt->packet_data_len;

    res = preprocess_spa_data(opts, spa_pkt, spadat);
    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_DEBUG, "[%s] preprocess_spa_data() returned error %i: '%s' for incoming packet.",
            spadat->pkt_source_ip, res, get_errstr(res));
        return 0;
    }

    if(opts->foreground == 1 && opts->verbose > 2)
    {
        printf("[+] candidate SPA packet payload:\n");
        hex_dump(spa_pkt->packet_data, packet_data_len);
    }

    if(! src_check(opts, spa_pkt, spadat, raw_digest))
        return 0;

    return 1;
}

static int
src_dst_check(acc_stanza_t *acc, spa_pkt_info_t *spa_pkt,
        spa_data_t *spadat, const int stanza_num)
{
    if(! compare_addr_list(acc->source_list, ntohl(spa_pkt->packet_src_ip)) ||
       (acc->destination_list != NULL
        && ! compare_addr_list(acc->destination_list, ntohl(spa_pkt->packet_dst_ip))))
    {
        log_msg(LOG_DEBUG,
                "(stanza #%d) SPA packet (%s -> %s) filtered by SOURCE and/or DESTINATION criteria",
                stanza_num, spadat->pkt_source_ip, spadat->pkt_destination_ip);
        return 0;
    }
    return 1;
}

/* Process command messages
*/
static int
process_cmd_msg(fko_srv_options_t *opts, acc_stanza_t *acc,
        spa_data_t *spadat, const int stanza_num, int *res)
{
    int             pid_status=0;
    char            cmd_buf[MAX_SPA_CMD_LEN] = {0};

    if(!acc->enable_cmd_exec)
    {
        log_msg(LOG_WARNING,
            "[%s] (stanza #%d) SPA Command messages are not allowed in the current configuration.",
            spadat->pkt_source_ip, stanza_num
        );
        return 0;
    }
    else if(opts->test)
    {
        log_msg(LOG_WARNING,
            "[%s] (stanza #%d) --test mode enabled, skipping command execution.",
            spadat->pkt_source_ip, stanza_num
        );
        return 0;
    }
    else
    {
        log_msg(LOG_INFO,
            "[%s] (stanza #%d) Processing SPA Command message: command='%s'.",
            spadat->pkt_source_ip, stanza_num, spadat->spa_message_remain
        );

        memset(cmd_buf, 0x0, sizeof(cmd_buf));
        if(acc->enable_cmd_sudo_exec)
        {
            /* Run the command via sudo - this allows sudo filtering
             * to apply to the incoming command
            */
            strlcpy(cmd_buf, opts->config[CONF_SUDO_EXE],
                    sizeof(cmd_buf));
            if(acc->cmd_sudo_exec_user != NULL
                    && strncasecmp(acc->cmd_sudo_exec_user, "root", 4) != 0)
            {
                strlcat(cmd_buf, " -u ", sizeof(cmd_buf));
                strlcat(cmd_buf, acc->cmd_sudo_exec_user, sizeof(cmd_buf));
            }
            if(acc->cmd_exec_group != NULL
                    && strncasecmp(acc->cmd_sudo_exec_group, "root", 4) != 0)
            {
                strlcat(cmd_buf, " -g ", sizeof(cmd_buf));
                strlcat(cmd_buf,
                        acc->cmd_sudo_exec_group, sizeof(cmd_buf));
            }
            strlcat(cmd_buf, " ",  sizeof(cmd_buf));
            strlcat(cmd_buf, spadat->spa_message_remain, sizeof(cmd_buf));
        }
        else
            strlcpy(cmd_buf, spadat->spa_message_remain, sizeof(cmd_buf));

        if(acc->cmd_exec_user != NULL
                && strncasecmp(acc->cmd_exec_user, "root", 4) != 0)
        {
            log_msg(LOG_INFO,
                    "[%s] (stanza #%d) Running command '%s' setuid/setgid user/group to %s/%s (UID=%i,GID=%i)",
                spadat->pkt_source_ip, stanza_num, cmd_buf, acc->cmd_exec_user,
                acc->cmd_exec_group == NULL ? acc->cmd_exec_user : acc->cmd_exec_group,
                acc->cmd_exec_uid, acc->cmd_exec_gid);

            *res = run_extcmd_as(acc->cmd_exec_uid, acc->cmd_exec_gid,
                    cmd_buf, NULL, 0, WANT_STDERR, NO_TIMEOUT,
                    &pid_status, opts);
        }
        else /* Just run it as we are (root that is). */
        {
            log_msg(LOG_INFO,
                    "[%s] (stanza #%d) Running command '%s'",
                spadat->pkt_source_ip, stanza_num, cmd_buf);
            *res = run_extcmd(cmd_buf, NULL, 0, WANT_STDERR,
                    5, &pid_status, opts);
        }

        /* should only call WEXITSTATUS() if WIFEXITED() is true
        */
        log_msg(LOG_INFO,
            "[%s] (stanza #%d) CMD_EXEC: command returned %i, pid_status: %d",
            spadat->pkt_source_ip, stanza_num, *res,
            WIFEXITED(pid_status) ? WEXITSTATUS(pid_status) : pid_status);

        if(WIFEXITED(pid_status))
        {
            if(WEXITSTATUS(pid_status) != 0)
                *res = SPA_MSG_COMMAND_ERROR;
        }
        else
            *res = SPA_MSG_COMMAND_ERROR;
    }
    return 1;
}

static int
check_mode_ctx(spa_data_t *spadat, fko_ctx_t *ctx, int attempted_decrypt,
        const int enc_type, const int stanza_num, const int res)
{
    if(attempted_decrypt == 0)
    {
        log_msg(LOG_ERR,
            "[%s] (stanza #%d) No stanza encryption mode match for encryption type: %i.",
            spadat->pkt_source_ip, stanza_num, enc_type);
        return 0;
    }

    /* Do we have a valid FKO context?  Did the SPA decrypt properly?
    */
    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_WARNING, "[%s] (stanza #%d) Error creating fko context: %s",
            spadat->pkt_source_ip, stanza_num, fko_errstr(res));

        if(IS_GPG_ERROR(res))
            log_msg(LOG_WARNING, "[%s] (stanza #%d) - GPG ERROR: %s",
                spadat->pkt_source_ip, stanza_num, fko_gpg_errstr(*ctx));
        return 0;
    }

    return 1;
}

static void
handle_rijndael_enc(acc_stanza_t *acc, spa_pkt_info_t *spa_pkt,
        spa_data_t *spadat, fko_ctx_t *ctx, int *attempted_decrypt,
        int *cmd_exec_success, const int enc_type, const int stanza_num,
        int *res)
{
    if(enc_type == FKO_ENCRYPTION_RIJNDAEL || acc->enable_cmd_exec)
    {
        *res = fko_new_with_data(ctx, (char *)spa_pkt->packet_data,
            acc->key, acc->key_len, acc->encryption_mode, acc->hmac_key,
            acc->hmac_key_len, acc->hmac_type);
        *attempted_decrypt = 1;
        if(*res == FKO_SUCCESS)
            *cmd_exec_success = 1;
    }
    return;
}

static int
handle_gpg_enc(acc_stanza_t *acc, spa_pkt_info_t *spa_pkt,
        spa_data_t *spadat, fko_ctx_t *ctx, int *attempted_decrypt,
        const int cmd_exec_success, const int enc_type,
        const int stanza_num, int *res)
{
    if(acc->use_gpg && enc_type == FKO_ENCRYPTION_GPG && cmd_exec_success == 0)
    {
        /* For GPG we create the new context without decrypting on the fly
         * so we can set some GPG parameters first.
        */
        if(acc->gpg_decrypt_pw != NULL || acc->gpg_allow_no_pw)
        {
            *res = fko_new_with_data(ctx, (char *)spa_pkt->packet_data, NULL,
                    0, FKO_ENC_MODE_ASYMMETRIC, acc->hmac_key,
                    acc->hmac_key_len, acc->hmac_type);

            if(*res != FKO_SUCCESS)
            {
                log_msg(LOG_WARNING,
                    "[%s] (stanza #%d) Error creating fko context (before decryption): %s",
                    spadat->pkt_source_ip, stanza_num, fko_errstr(*res)
                );
                return 0;
            }

            /* Set whatever GPG parameters we have.
            */
            if(acc->gpg_exe != NULL)
            {
                *res = fko_set_gpg_exe(*ctx, acc->gpg_exe);
                if(*res != FKO_SUCCESS)
                {
                    log_msg(LOG_WARNING,
                        "[%s] (stanza #%d) Error setting GPG path %s: %s",
                        spadat->pkt_source_ip, stanza_num, acc->gpg_exe,
                        fko_errstr(*res)
                    );
                    return 0;
                }
            }

            if(acc->gpg_home_dir != NULL)
            {
                *res = fko_set_gpg_home_dir(*ctx, acc->gpg_home_dir);
                if(*res != FKO_SUCCESS)
                {
                    log_msg(LOG_WARNING,
                        "[%s] (stanza #%d) Error setting GPG keyring path to %s: %s",
                        spadat->pkt_source_ip, stanza_num, acc->gpg_home_dir,
                        fko_errstr(*res)
                    );
                    return 0;
                }
            }

            if(acc->gpg_decrypt_id != NULL)
                fko_set_gpg_recipient(*ctx, acc->gpg_decrypt_id);

            /* If GPG_REQUIRE_SIG is set for this acc stanza, then set
             * the FKO context accordingly and check the other GPG Sig-
             * related parameters. This also applies when REMOTE_ID is
             * set.
            */
            if(acc->gpg_require_sig)
            {
                fko_set_gpg_signature_verify(*ctx, 1);

                /* Set whether or not to ignore signature verification errors.
                */
                fko_set_gpg_ignore_verify_error(*ctx, acc->gpg_ignore_sig_error);
            }
            else
            {
                fko_set_gpg_signature_verify(*ctx, 0);
                fko_set_gpg_ignore_verify_error(*ctx, 1);
            }

            /* Now decrypt the data.
            */
            *res = fko_decrypt_spa_data(*ctx, acc->gpg_decrypt_pw, 0);
            *attempted_decrypt = 1;
        }
    }
    return 1;
}

static int
handle_gpg_sigs(acc_stanza_t *acc, spa_data_t *spadat,
        fko_ctx_t *ctx, const int enc_type, const int stanza_num, int *res)
{
    char                *gpg_id, *gpg_fpr;
    acc_string_list_t   *gpg_id_ndx;
    acc_string_list_t   *gpg_fpr_ndx;
    unsigned char        is_gpg_match = 0;

    if(enc_type == FKO_ENCRYPTION_GPG && acc->gpg_require_sig)
    {
        *res = fko_get_gpg_signature_id(*ctx, &gpg_id);
        if(*res != FKO_SUCCESS)
        {
            log_msg(LOG_WARNING,
                "[%s] (stanza #%d) Error pulling the GPG signature ID from the context: %s",
                spadat->pkt_source_ip, stanza_num, fko_gpg_errstr(*ctx));
            return 0;
        }

        *res = fko_get_gpg_signature_fpr(*ctx, &gpg_fpr);
        if(*res != FKO_SUCCESS)
        {
            log_msg(LOG_WARNING,
                "[%s] (stanza #%d) Error pulling the GPG fingerprint from the context: %s",
                spadat->pkt_source_ip, stanza_num, fko_gpg_errstr(*ctx));
            return 0;
        }

        log_msg(LOG_INFO,
                "[%s] (stanza #%d) Incoming SPA data signed by '%s' (fingerprint '%s').",
                spadat->pkt_source_ip, stanza_num, gpg_id, gpg_fpr);

        /* prefer GnuPG fingerprint match if so configured
        */
        if(acc->gpg_remote_fpr != NULL)
        {
            is_gpg_match = 0;
            for(gpg_fpr_ndx = acc->gpg_remote_fpr_list;
                    gpg_fpr_ndx != NULL; gpg_fpr_ndx=gpg_fpr_ndx->next)
            {
                *res = fko_gpg_signature_fpr_match(*ctx,
                        gpg_fpr_ndx->str, &is_gpg_match);
                if(*res != FKO_SUCCESS)
                {
                    log_msg(LOG_WARNING,
                        "[%s] (stanza #%d) Error in GPG signature comparision: %s",
                        spadat->pkt_source_ip, stanza_num, fko_gpg_errstr(*ctx));
                    return 0;
                }
                if(is_gpg_match)
                    break;
            }
            if(! is_gpg_match)
            {
                log_msg(LOG_WARNING,
                    "[%s] (stanza #%d) Incoming SPA packet signed by: %s, but that fingerprint is not in the GPG_FINGERPRINT_ID list.",
                    spadat->pkt_source_ip, stanza_num, gpg_fpr);
                return 0;
            }
        }

        if(acc->gpg_remote_id != NULL)
        {
            is_gpg_match = 0;
            for(gpg_id_ndx = acc->gpg_remote_id_list;
                    gpg_id_ndx != NULL; gpg_id_ndx=gpg_id_ndx->next)
            {
                *res = fko_gpg_signature_id_match(*ctx,
                        gpg_id_ndx->str, &is_gpg_match);
                if(*res != FKO_SUCCESS)
                {
                    log_msg(LOG_WARNING,
                        "[%s] (stanza #%d) Error in GPG signature comparision: %s",
                        spadat->pkt_source_ip, stanza_num, fko_gpg_errstr(*ctx));
                    return 0;
                }
                if(is_gpg_match)
                    break;
            }

            if(! is_gpg_match)
            {
                log_msg(LOG_WARNING,
                    "[%s] (stanza #%d) Incoming SPA packet signed by ID: %s, but that ID is not in the GPG_REMOTE_ID list.",
                    spadat->pkt_source_ip, stanza_num, gpg_id);
                return 0;
            }
        }
    }
    return 1;
}

static int
check_src_access(acc_stanza_t *acc, spa_data_t *spadat, const int stanza_num)
{
    if(strcmp(spadat->spa_message_src_ip, "0.0.0.0") == 0)
    {
        if(acc->require_source_address)
        {
            log_msg(LOG_WARNING,
                "[%s] (stanza #%d) Got 0.0.0.0 when valid source IP was required.",
                spadat->pkt_source_ip, stanza_num
            );
            return 0;
        }

        if (spadat->pkt_source_xff_ip[0] != '\0')
            spadat->use_src_ip = spadat->pkt_source_xff_ip;
        else
            spadat->use_src_ip = spadat->pkt_source_ip;
    }
    else
        spadat->use_src_ip = spadat->spa_message_src_ip;

    return 1;
}

static int
check_username(acc_stanza_t *acc, spa_data_t *spadat, const int stanza_num)
{
    if(acc->require_username != NULL)
    {
        if(strcmp(spadat->username, acc->require_username) != 0)
        {
            log_msg(LOG_WARNING,
                "[%s] (stanza #%d) Username in SPA data (%s) does not match required username: %s",
                spadat->pkt_source_ip, stanza_num, spadat->username, acc->require_username
            );
            return 0;
        }
    }
    return 1;
}

static int
check_nat_access_types(fko_srv_options_t *opts, acc_stanza_t *acc,
        spa_data_t *spadat, const int stanza_num)
{
    int      unsupported=0, not_enabled=0;

    if(spadat->message_type == FKO_NAT_ACCESS_MSG
          || spadat->message_type == FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG)
    {
#if FIREWALL_FIREWALLD
        if(strncasecmp(opts->config[CONF_ENABLE_FIREWD_FORWARDING], "Y", 1)!=0)
            not_enabled = 1;
#elif FIREWALL_IPTABLES
        if(strncasecmp(opts->config[CONF_ENABLE_IPT_FORWARDING], "Y", 1)!=0)
            not_enabled = 1;
#else
        unsupported = 1;
#endif
    }
    else if(spadat->message_type == FKO_LOCAL_NAT_ACCESS_MSG
          || spadat->message_type == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
    {
#if FIREWALL_FIREWALLD
        if(strncasecmp(opts->config[CONF_ENABLE_FIREWD_LOCAL_NAT], "Y", 1)!=0)
            not_enabled = 1;
#elif FIREWALL_IPTABLES
        if(strncasecmp(opts->config[CONF_ENABLE_IPT_LOCAL_NAT], "Y", 1)!=0)
            not_enabled = 1;
#else
        unsupported = 1;
#endif
    }

    if(not_enabled)
    {
        log_msg(LOG_WARNING,
            "(stanza #%d) SPA packet from %s requested NAT access, but is not enabled",
            stanza_num, spadat->pkt_source_ip
        );
        return 0;
    }
    else if(unsupported)
    {
        log_msg(LOG_WARNING,
            "(stanza #%d) SPA packet from %s requested unsupported NAT access",
            stanza_num, spadat->pkt_source_ip
        );
        return 0;
    }

    return 1;
}

static int
add_replay_cache(fko_srv_options_t *opts, acc_stanza_t *acc,
        spa_data_t *spadat, char *raw_digest, int *added_replay_digest,
        const int stanza_num, int *res)
{
    if (!opts->test && *added_replay_digest == 0
            && strncasecmp(opts->config[CONF_ENABLE_DIGEST_PERSISTENCE], "Y", 1) == 0)
    {

        *res = add_replay(opts, raw_digest);
        if (*res != SPA_MSG_SUCCESS)
        {
            log_msg(LOG_WARNING, "[%s] (stanza #%d) Could not add digest to replay cache",
                spadat->pkt_source_ip, stanza_num);
            return 0;
        }
        *added_replay_digest = 1;
    }

    return 1;
}

static void
set_timeout(acc_stanza_t *acc, spa_data_t *spadat)
{
    if(spadat->client_timeout > 0)
        spadat->fw_access_timeout = spadat->client_timeout;
    else if(acc->fw_access_timeout > 0)
        spadat->fw_access_timeout = acc->fw_access_timeout;
    else
        spadat->fw_access_timeout = DEF_FW_ACCESS_TIMEOUT;
    return;
}

static int
check_port_proto(acc_stanza_t *acc, spa_data_t *spadat, const int stanza_num)
{
    if(! acc_check_port_access(acc, spadat->spa_message_remain))
    {
        log_msg(LOG_WARNING,
            "[%s] (stanza #%d) One or more requested protocol/ports was denied per access.conf.",
            spadat->pkt_source_ip, stanza_num
        );
        return 0;
    }
    return 1;
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

    char            *spa_ip_demark, *raw_digest = NULL;
    int             res, enc_type, stanza_num=0;
    int             added_replay_digest = 0;
    int             cmd_exec_success = 0, attempted_decrypt = 0;
    char            dump_buf[CTX_DUMP_BUFSIZE];

    spa_pkt_info_t *spa_pkt = &(opts->spa_pkt);

    /* This will hold our pertinent SPA data.
    */
    spa_data_t spadat;

    /* Loop through all access stanzas looking for a match
    */
    acc_stanza_t        *acc = opts->acc_stanzas;

    inet_ntop(AF_INET, &(spa_pkt->packet_src_ip),
        spadat.pkt_source_ip, sizeof(spadat.pkt_source_ip));

    inet_ntop(AF_INET, &(spa_pkt->packet_dst_ip),
        spadat.pkt_destination_ip, sizeof(spadat.pkt_destination_ip));

    /* At this point, we want to validate and (if needed) preprocess the
     * SPA data and/or to be reasonably sure we have a SPA packet (i.e
     * try to eliminate obvious non-spa packets).
    */
    if(!precheck_pkt(opts, spa_pkt, &spadat, &raw_digest))
        return;

    /* Now that we know there is a matching access.conf stanza and the
     * incoming SPA packet is not a replay, see if we should grant any
     * access
    */
    while(acc)
    {
        res = FKO_SUCCESS;
        cmd_exec_success  = 0;
        attempted_decrypt = 0;
        stanza_num++;

        /* Start access loop with a clean FKO context
        */
        if(ctx != NULL)
        {
            if(fko_destroy(ctx) == FKO_ERROR_ZERO_OUT_DATA)
                log_msg(LOG_WARNING,
                    "[%s] (stanza #%d) fko_destroy() could not zero out sensitive data buffer.",
                    spadat.pkt_source_ip, stanza_num
                );
            ctx = NULL;
        }

        /* Check for a match for the SPA source and destination IP and the access stanza
        */
        if(! src_dst_check(acc, spa_pkt, &spadat, stanza_num))
        {
            acc = acc->next;
            continue;
        }

        log_msg(LOG_INFO,
            "(stanza #%d) SPA Packet from IP: %s received with access source match",
            stanza_num, spadat.pkt_source_ip);

        log_msg(LOG_DEBUG, "SPA Packet: '%s'", spa_pkt->packet_data);

        /* Make sure this access stanza has not expired
        */
        if(! check_stanza_expiration(acc, &spadat, stanza_num))
        {
            acc = acc->next;
            continue;
        }

        /* Get encryption type and try its decoding routine first (if the key
         * for that type is set)
        */
        enc_type = fko_encryption_type((char *)spa_pkt->packet_data);

        if(acc->use_rijndael)
            handle_rijndael_enc(acc, spa_pkt, &spadat, &ctx,
                        &attempted_decrypt, &cmd_exec_success, enc_type,
                        stanza_num, &res);

        if(! handle_gpg_enc(acc, spa_pkt, &spadat, &ctx, &attempted_decrypt,
                    cmd_exec_success, enc_type, stanza_num, &res))
        {
            acc = acc->next;
            continue;
        }

        if(! check_mode_ctx(&spadat, &ctx, attempted_decrypt,
                    enc_type, stanza_num, res))
        {
            acc = acc->next;
            continue;
        }

        /* Add this SPA packet into the replay detection cache
        */
        if(! add_replay_cache(opts, acc, &spadat, raw_digest,
                    &added_replay_digest, stanza_num, &res))
        {
            acc = acc->next;
            continue;
        }

        /* At this point the SPA data is authenticated via the HMAC (if used
         * for now). Next we need to see if it meets our access criteria which
         * the server imposes regardless of the content of the SPA packet.
        */
        log_msg(LOG_DEBUG, "[%s] (stanza #%d) SPA Decode (res=%i):",
            spadat.pkt_source_ip, stanza_num, res);

        res = dump_ctx_to_buffer(ctx, dump_buf, sizeof(dump_buf));
        if (res == FKO_SUCCESS)
            log_msg(LOG_DEBUG, "%s", dump_buf);
        else
            log_msg(LOG_WARNING, "Unable to dump FKO context: %s", fko_errstr(res));

        /* First, if this is a GPG message, and GPG_REMOTE_ID list is not empty,
         * then we need to make sure this incoming message is signer ID matches
         * an entry in the list.
        */

        if(! handle_gpg_sigs(acc, &spadat, &ctx, enc_type, stanza_num, &res))
        {
            acc = acc->next;
            continue;
        }

        /* Populate our spa data struct for future reference.
        */
        res = get_spa_data_fields(ctx, &spadat);

        if(res != FKO_SUCCESS)
        {
            log_msg(LOG_ERR,
                "[%s] (stanza #%d) Unexpected error pulling SPA data from the context: %s",
                spadat.pkt_source_ip, stanza_num, fko_errstr(res));

            acc = acc->next;
            continue;
        }

        /* Figure out what our timeout will be. If it is specified in the SPA
         * data, then use that.  If not, try the FW_ACCESS_TIMEOUT from the
         * access.conf file (if there is one).  Otherwise use the default.
        */
        set_timeout(acc, &spadat);

        /* Check packet age if so configured.
        */
        if(! check_pkt_age(opts, &spadat, stanza_num))
        {
            acc = acc->next;
            continue;
        }

        /* At this point, we have enough to check the embedded (or packet source)
         * IP address against the defined access rights.  We start by splitting
         * the spa msg source IP from the remainder of the message.
        */
        spa_ip_demark = strchr(spadat.spa_message, ',');
        if(spa_ip_demark == NULL)
        {
            log_msg(LOG_WARNING,
                "[%s] (stanza #%d) Error parsing SPA message string: %s",
                spadat.pkt_source_ip, stanza_num, fko_errstr(res));

            acc = acc->next;
            continue;
        }

        if((spa_ip_demark-spadat.spa_message) < MIN_IPV4_STR_LEN-1
                || (spa_ip_demark-spadat.spa_message) > MAX_IPV4_STR_LEN)
        {
            log_msg(LOG_WARNING,
                "[%s] (stanza #%d) Invalid source IP in SPA message, ignoring SPA packet",
                spadat.pkt_source_ip, stanza_num);
            break;
        }

        strlcpy(spadat.spa_message_src_ip,
            spadat.spa_message, (spa_ip_demark-spadat.spa_message)+1);

        if(! is_valid_ipv4_addr(spadat.spa_message_src_ip))
        {
            log_msg(LOG_WARNING,
                "[%s] (stanza #%d) Invalid source IP in SPA message, ignoring SPA packet",
                spadat.pkt_source_ip, stanza_num, fko_errstr(res));
            break;
        }

        strlcpy(spadat.spa_message_remain, spa_ip_demark+1, MAX_DECRYPTED_SPA_LEN);

        /* If use source IP was requested (embedded IP of 0.0.0.0), make sure it
         * is allowed.
        */
        if(! check_src_access(acc, &spadat, stanza_num))
        {
            acc = acc->next;
            continue;
        }

        /* If REQUIRE_USERNAME is set, make sure the username in this SPA data
         * matches.
        */
        if(! check_username(acc, &spadat, stanza_num))
        {
            acc = acc->next;
            continue;
        }

        /* Take action based on SPA message type.
        */
        if(! check_nat_access_types(opts, acc, &spadat, stanza_num))
        {
            acc = acc->next;
            continue;
        }

        /* Command messages.
        */
        if(acc->cmd_cycle_open != NULL)
        {
            if(cmd_cycle_open(opts, acc, &spadat, stanza_num, &res))
                break; /* successfully processed a matching access stanza */
            else
            {
                acc = acc->next;
                continue;
            }
        }
        else if(spadat.message_type == FKO_COMMAND_MSG)
        {
            if(process_cmd_msg(opts, acc, &spadat, stanza_num, &res))
            {
                /* we processed the command on a matching access stanza, so we
                 * don't look for anything else to do with this SPA packet
                */
                break;
            }
            else
            {
                acc = acc->next;
                continue;
            }
        }

        /* From this point forward, we have some kind of access message. So
         * we first see if access is allowed by checking access against
         * restrict_ports and open_ports.
         *
         *  --DSS TODO: We should add BLACKLIST support here as well.
        */
        if(! check_port_proto(acc, &spadat, stanza_num))
        {
            acc = acc->next;
            continue;
        }

        /* At this point, we process the SPA request and break out of the
         * access stanza loop (first valid access stanza stops us looking
         * for others).
        */
        if(opts->test)  /* no firewall changes in --test mode */
        {
            log_msg(LOG_WARNING,
                "[%s] (stanza #%d) --test mode enabled, skipping firewall manipulation.",
                spadat.pkt_source_ip, stanza_num
            );
            acc = acc->next;
            continue;
        }
        else
        {
            if(acc->cmd_cycle_open != NULL)
            {
                if(cmd_cycle_open(opts, acc, &spadat, stanza_num, &res))
                    break; /* successfully processed a matching access stanza */
                else
                {
                    acc = acc->next;
                    continue;
                }
            }
            else
            {
                process_spa_request(opts, acc, &spadat);
            }
        }

        /* If we made it here, then the SPA packet was processed according
         * to a matching access.conf stanza, so we're done with this packet.
        */
        break;
    }

    if (raw_digest != NULL)
        free(raw_digest);

    if(ctx != NULL)
    {
        if(fko_destroy(ctx) == FKO_ERROR_ZERO_OUT_DATA)
            log_msg(LOG_WARNING,
                "[%s] (stanza #%d) fko_destroy() could not zero out sensitive data buffer.",
                spadat.pkt_source_ip, stanza_num
            );
        ctx = NULL;
    }

    return;
}

/***EOF***/
