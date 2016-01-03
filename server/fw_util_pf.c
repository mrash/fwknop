/**
 * \file server/fw_util_pf.c
 *
 * \brief Fwknop routines for managing pf firewall rules.
 */

/*  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
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

#if FIREWALL_PF

#include "fw_util.h"
#include "utils.h"
#include "log_msg.h"
#include "extcmd.h"
#include "access.h"

static struct fw_config fwc;
static char   cmd_buf[CMD_BUFSIZE];
static char   err_buf[CMD_BUFSIZE];
static char   cmd_out[STANDARD_CMD_OUT_BUFSIZE];

static void
zero_cmd_buffers(void)
{
    memset(cmd_buf, 0x0, CMD_BUFSIZE);
    memset(err_buf, 0x0, CMD_BUFSIZE);
    memset(cmd_out, 0x0, STANDARD_CMD_OUT_BUFSIZE);
}

/* Print all firewall rules currently instantiated by the running fwknopd
 * daemon to stdout.
*/
int
fw_dump_rules(const fko_srv_options_t * const opts)
{
    int     res, got_err = 0, pid_status = 0;

    fprintf(stdout, "Listing fwknopd pf rules...\n");
    fflush(stdout);

    zero_cmd_buffers();

    /* Create the list command for active rules
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " PF_LIST_ANCHOR_RULES_ARGS,
        opts->fw_config->fw_command,
        opts->fw_config->anchor
    );

    fprintf(stdout, "\nActive Rules in PF anchor '%s':\n", opts->fw_config->anchor);
    fflush(stdout);

    /* exclude stderr because ALTQ may not be available
    */
    res = run_extcmd(cmd_buf, NULL, 0, NO_STDERR, NO_TIMEOUT, &pid_status, opts);

    /* Expect full success on this */
    if(! EXTCMD_IS_SUCCESS(res))
    {
        log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);
        got_err++;
    }

    return(got_err);
}

/* Check to see if the fwknop anchor is linked into the main policy.  If not,
 * any rules added/deleted by fwknopd will have no effect on real traffic.
*/
static int
anchor_active(const fko_srv_options_t *opts)
{
    int    pid_status = 0;
    char   anchor_search_str[MAX_PF_ANCHOR_SEARCH_LEN] = {0};

    /* Build our anchor search string
    */
    snprintf(anchor_search_str, MAX_PF_ANCHOR_SEARCH_LEN-1, "%s\n",
        opts->fw_config->anchor);

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " PF_ANCHOR_CHECK_ARGS,
        opts->fw_config->fw_command
    );

    /* Check to see if the anchor exists and is linked into the main policy
    */
    if(search_extcmd(cmd_buf, WANT_STDERR, NO_TIMEOUT,
            anchor_search_str, &pid_status, opts) > 0)
        return 1;

    return 0;
}

static void
delete_all_anchor_rules(const fko_srv_options_t *opts)
{
    int res = 0, pid_status = 0;

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " PF_DEL_ALL_ANCHOR_RULES,
        fwc.fw_command,
        fwc.anchor
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
                WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

    /* Expect full success on this */
    if(! EXTCMD_IS_SUCCESS(res))
        log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);

    return;
}

int
fw_config_init(fko_srv_options_t * const opts)
{
    memset(&fwc, 0x0, sizeof(struct fw_config));

    /* Set our firewall exe command path
    */
    strlcpy(fwc.fw_command, opts->config[CONF_FIREWALL_EXE], sizeof(fwc.fw_command));

    /* Set the PF anchor name
    */
    strlcpy(fwc.anchor, opts->config[CONF_PF_ANCHOR_NAME], sizeof(fwc.anchor));
    
    if(strncasecmp(opts->config[CONF_ENABLE_DESTINATION_RULE], "Y", 1)==0)
    {
        fwc.use_destination = 1;
    }

    /* Let us find it via our opts struct as well.
    */
    opts->fw_config = &fwc;

    return 1;
}

int
fw_initialize(const fko_srv_options_t * const opts)
{

    if (! anchor_active(opts))
    {
        log_msg(LOG_WARNING,
                "Warning: the fwknop anchor is not active in the pf policy");
        return 0;
    }

    /* Delete any existing rules in the fwknop anchor
    */
    delete_all_anchor_rules(opts);

    return 1;
}

int
fw_cleanup(const fko_srv_options_t * const opts)
{
    delete_all_anchor_rules(opts);
    return(0);
}

/****************************************************************************/

/* Rule Processing - Create an access request...
*/
int
process_spa_request(const fko_srv_options_t * const opts,
        const acc_stanza_t * const acc, spa_data_t * const spadat)
{
    char             new_rule[MAX_PF_NEW_RULE_LEN] = {0};
    char             write_cmd[CMD_BUFSIZE] = {0};

    acc_port_list_t *port_list = NULL;
    acc_port_list_t *ple;

    int             res = 0, pid_status = 0;
    time_t          now;
    unsigned int    exp_ts;

    /* Parse and expand our access message.
    */
    expand_acc_port_list(&port_list, spadat->spa_message_remain);

    /* Start at the top of the proto-port list...
    */
    ple = port_list;

    /* Set our expire time value.
    */
    time(&now);
    exp_ts = now + spadat->fw_access_timeout;

    /* For straight access requests, we currently support multiple proto/port
     * request.
    */
    if(spadat->message_type == FKO_ACCESS_MSG
      || spadat->message_type == FKO_CLIENT_TIMEOUT_ACCESS_MSG)
    {
        /* Create an access command for each proto/port for the source ip.
        */
        while(ple != NULL)
        {
            zero_cmd_buffers();

            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " PF_LIST_ANCHOR_RULES_ARGS,
                opts->fw_config->fw_command,
                opts->fw_config->anchor
            );

            /* Cache the current anchor rule set
            */
            res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE,
                        WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

            /* Build the new rule string
            */
            memset(new_rule, 0x0, MAX_PF_NEW_RULE_LEN);
            snprintf(new_rule, MAX_PF_NEW_RULE_LEN-1, PF_ADD_RULE_ARGS "\n",
                ple->proto,
                spadat->use_src_ip,
                (fwc.use_destination ? spadat->pkt_destination_ip : PF_ANY_IP),
                ple->port,
                exp_ts
            );

            if (strlen(cmd_out) + strlen(new_rule) < STANDARD_CMD_OUT_BUFSIZE)
            {
                /* We add the rule to the running policy
                */
                strlcat(cmd_out, new_rule, STANDARD_CMD_OUT_BUFSIZE);

                memset(write_cmd, 0x0, CMD_BUFSIZE);

                snprintf(write_cmd, CMD_BUFSIZE-1, "%s " PF_WRITE_ANCHOR_RULES_ARGS,
                    opts->fw_config->fw_command,
                    opts->fw_config->anchor
                );

                res = run_extcmd_write(write_cmd, cmd_out, &pid_status, opts);

                if(EXTCMD_IS_SUCCESS(res))
                {
                    log_msg(LOG_INFO, "Added Rule for %s, %s expires at %u",
                        spadat->use_src_ip,
                        spadat->spa_message_remain,
                        exp_ts
                    );

                    fwc.active_rules++;

                    /* Reset the next expected expire time for this chain if it
                     * is warranted.
                    */
                    if(fwc.next_expire < now || exp_ts < fwc.next_expire)
                        fwc.next_expire = exp_ts;
                }
                else
                {
                    log_msg(LOG_WARNING, "Could not write rule to pf anchor");
                    free_acc_port_list(port_list);
                    return(-1);
                }
            }
            else
            {
                /* We don't have enough room to add the new firewall rule,
                 * so throw a warning and bail.  Once some of the existing
                 * rules are expired the user will once again be able to gain
                 * access.  Note that we don't expect to really ever hit this
                 * limit because of STANDARD_CMD_OUT_BUFSIZE is quite a number
                 * of anchor rules.
                */
                log_msg(LOG_WARNING, "Max anchor rules reached, try again later.");
                free_acc_port_list(port_list);
                return 0;
            }

            ple = ple->next;
        }

    }
    else
    {
        /* No other SPA request modes are supported yet.
        */
        if(spadat->message_type == FKO_LOCAL_NAT_ACCESS_MSG
          || spadat->message_type == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
        {
            log_msg(LOG_WARNING, "Local NAT requests are not currently supported.");
        }
        else if(spadat->message_type == FKO_NAT_ACCESS_MSG
          || spadat->message_type == FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG)
        {
            log_msg(LOG_WARNING, "Forwarding/NAT requests are not currently supported.");
        }

        free_acc_port_list(port_list);
        return(-1);
    }

    free_acc_port_list(port_list);
    return(res);
}

/* Iterate over the configure firewall access chains and purge expired
 * firewall rules.
*/
void
check_firewall_rules(const fko_srv_options_t * const opts,
        const int chk_rm_all)
{
    char            exp_str[12] = {0};
    char            anchor_rules_copy[STANDARD_CMD_OUT_BUFSIZE] = {0};
    char            write_cmd[CMD_BUFSIZE] = {0};
    char           *ndx, *tmp_mark, *tmp_ndx, *newline_tmp_ndx;

    time_t          now, rule_exp, min_exp=0;
    int             i=0, res=0, anchor_ndx=0, is_delete=0, pid_status=0;

    /* If we have not yet reached our expected next expire
       time, continue.
    */
    if(fwc.next_expire == 0)
        return;

    time(&now);

    if (fwc.next_expire > now)
        return;

    zero_cmd_buffers();

    /* There should be a rule to delete.  Get the current list of
     * rules and delete the ones that are expired.
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " PF_LIST_ANCHOR_RULES_ARGS,
        opts->fw_config->fw_command,
        opts->fw_config->anchor
    );

    res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE,
                WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(cmd_out);

    if(!EXTCMD_IS_SUCCESS(res))
    {
        log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, cmd_out);
        return;
    }

    /* Find the first _exp_ string (if any).
    */
    ndx = strstr(cmd_out, EXPIRE_COMMENT_PREFIX);

    if(ndx == NULL)
    {
        /* we did not find an expected rule.
        */
        log_msg(LOG_ERR,
            "Did not find expire comment in rules list %i.", i);

        return;
    }

    memset(anchor_rules_copy, 0x0, STANDARD_CMD_OUT_BUFSIZE);

    /* Walk the list and process rules as needed.
    */
    while (ndx != NULL)
    {
        /* Jump forward and extract the timestamp
        */
        ndx += strlen(EXPIRE_COMMENT_PREFIX);

        /* remember this spot for when we look for the next
         * rule.
        */
        tmp_mark = ndx;

        strlcpy(exp_str, ndx, sizeof(exp_str));
        chop_spaces(exp_str);
        chop_char(exp_str, 0x22); /* there is a trailing quote */
        if(!is_digits(exp_str))
        {
            /* go to the next rule if it exists
            */
            ndx = strstr(tmp_mark, EXPIRE_COMMENT_PREFIX);
            continue;
        }

        rule_exp = (time_t)atoll(exp_str);

        if(rule_exp <= now)
        {
            /* We are going to delete this rule, and because we rebuild the
             * PF anchor to include all rules that haven't expired, to delete
             * this rule we just skip to the next one.
            */
            log_msg(LOG_INFO, "Deleting rule with expire time of %u.", rule_exp);

            if (fwc.active_rules > 0)
                fwc.active_rules--;

            is_delete = 1;
        }
        else
        {
            /* The rule has not expired, so copy it into the anchor string that
             * lists current rules and will be used to feed
             * 'pfctl -a <anchor> -f -'.
            */

            /* back up to the previous newline or the beginning of the rules
             * output string.
            */
            tmp_ndx = ndx;
            while(--tmp_ndx > cmd_out)
            {
                if(*tmp_ndx == '\n')
                    break;
            }

            if(*tmp_ndx == '\n')
                tmp_ndx++;

            /* may sure the rule begins with the string "pass", and make sure
             * it ends with a newline.  Bail if either test fails.
            */
            if (strlen(tmp_ndx) <= strlen("pass")
                    || strncmp(tmp_ndx, "pass", strlen("pass")) != 0)
                break;

            newline_tmp_ndx = tmp_ndx;

            while (*newline_tmp_ndx != '\n' && *newline_tmp_ndx != '\0')
                newline_tmp_ndx++;

            if (*newline_tmp_ndx != '\n')
                break;

            /* copy the whole rule to the next newline (includes the expiration
               time).
            */
            while (*tmp_ndx != '\n' && *tmp_ndx != '\0'
                && anchor_ndx < STANDARD_CMD_OUT_BUFSIZE)
            {
                anchor_rules_copy[anchor_ndx] = *tmp_ndx;
                tmp_ndx++;
                anchor_ndx++;
            }
            anchor_rules_copy[anchor_ndx] = '\n';
            anchor_ndx++;

            /* Track the minimum future rule expire time.
            */
            if(rule_exp > now)
                min_exp = (min_exp < rule_exp) ? min_exp : rule_exp;
        }

        /* Push our tracking index forward beyond (just processed) _exp_
         * string so we can continue to the next rule in the list.
        */
        ndx = strstr(tmp_mark, EXPIRE_COMMENT_PREFIX);
    }

    if (is_delete)
    {
        /* We re-instantiate the anchor rules with the new rules string that
         * has the rule(s) deleted.  If there isn't at least one "pass" rule,
         * then we just flush the anchor.
        */
        if (strlen(anchor_rules_copy) > strlen("pass")
            && strncmp(anchor_rules_copy, "pass", strlen("pass")) == 0)
        {
            memset(write_cmd, 0x0, CMD_BUFSIZE);

            snprintf(write_cmd, CMD_BUFSIZE-1, "%s " PF_WRITE_ANCHOR_RULES_ARGS,
                opts->fw_config->fw_command,
                opts->fw_config->anchor
            );

            res = run_extcmd_write(write_cmd, anchor_rules_copy, &pid_status, opts);
            if(! EXTCMD_IS_SUCCESS(res))
            {
                log_msg(LOG_WARNING, "Could not execute command: %s",
                        write_cmd);
                return;
            }
        }
        else
        {
            delete_all_anchor_rules(opts);
        }
    }

    /* Set the next pending expire time accordingly. 0 if there are no
     * more rules, or whatever the next expected (min_exp) time will be.
    */
    if(fwc.active_rules < 1)
        fwc.next_expire = 0;
    else if(min_exp)
        fwc.next_expire = min_exp;

    return;
}

#endif /* FIREWALL_PF */

/***EOF***/
