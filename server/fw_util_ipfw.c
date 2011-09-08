/*
 *****************************************************************************
 *
 * File:    fw_util_ipfw.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Fwknop routines for managing ipfw firewall rules.
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

#if FIREWALL_IPFW

#include "fw_util.h"
#include "utils.h"
#include "log_msg.h"
#include "extcmd.h"
#include "access.h"

static struct fw_config fwc;
static char   cmd_buf[CMD_BUFSIZE];
static char   err_buf[CMD_BUFSIZE];
static char   cmd_out[STANDARD_CMD_OUT_BUFSIZE];

static unsigned short
get_next_rule_num(void)
{
    unsigned short i;

    for(i=0; i < fwc.max_rules; i++)
    {
        if(fwc.rule_map[i] == RULE_FREE)
            return(fwc.start_rule_num + i);
    }

    return(0);
}

static void
zero_cmd_buffers(void)
{
    memset(cmd_buf, 0x0, CMD_BUFSIZE);
    memset(err_buf, 0x0, CMD_BUFSIZE);
    memset(cmd_out, 0x0, STANDARD_CMD_OUT_BUFSIZE);
}

static int
ipfw_set_exists(const char *fw_command, const unsigned short set_num)
{
    int res = 0;

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_LIST_SET_RULES_ARGS,
        fw_command,
        set_num
    );

    res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE, 0);

    if(!EXTCMD_IS_SUCCESS(res))
        return(0);

    if(cmd_out[0] == '\0')
        return(0);

    return(1);
}

/* Print all firewall rules currently instantiated by the running fwknopd
 * daemon to stdout.
*/
int
fw_dump_rules(fko_srv_options_t *opts)
{
    int     res, got_err = 0;

    zero_cmd_buffers();

    /* Create the list command for active rules
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_LIST_RULES_ARGS,
        opts->fw_config->fw_command,
        opts->fw_config->active_set_num
    );

    //printf("(%i) CMD: '%s'\n", i, cmd_buf);
    printf("\nActive Rules:\n");
    res = system(cmd_buf);

    /* Expect full success on this */
    if(! EXTCMD_IS_SUCCESS(res))
    {
        log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf); 
        got_err++;
    }

    /* Create the list command for expired rules
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_LIST_RULES_ARGS,
        opts->fw_config->fw_command,
        opts->fw_config->expire_set_num
    );

    //printf("(%i) CMD: '%s'\n", i, cmd_buf);
    printf("\nExpired Rules:\n");
    res = system(cmd_buf);

    /* Expect full success on this */
    if(! EXTCMD_IS_SUCCESS(res))
    {
        log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf); 
        got_err++;
    }

    return(got_err);
}

void
fw_config_init(fko_srv_options_t *opts)
{

    memset(&fwc, 0x0, sizeof(struct fw_config));

    /* Set our firewall exe command path (iptables in most cases).
    */
    strlcpy(fwc.fw_command, opts->config[CONF_FIREWALL_EXE], MAX_PATH_LEN);

    fwc.start_rule_num = atoi(opts->config[CONF_IPFW_START_RULE_NUM]);
    fwc.max_rules      = atoi(opts->config[CONF_IPFW_MAX_RULES]);
    fwc.active_set_num = atoi(opts->config[CONF_IPFW_ACTIVE_SET_NUM]);
    fwc.expire_set_num = atoi(opts->config[CONF_IPFW_EXPIRE_SET_NUM]);
    fwc.purge_interval = atoi(opts->config[CONF_IPFW_EXPIRE_PURGE_INTERVAL]);

    /* Let us find it via our opts struct as well.
    */
    opts->fw_config = &fwc;

    return;
}

void
fw_initialize(fko_srv_options_t *opts)
{
    int             res = 0;
    unsigned short  curr_rule;
    char           *ndx;

    /* For now, we just call fw_cleanup to start with clean slate.
    */
    res = fw_cleanup();

    if(res != 0)
    {
        fprintf(stderr, "Fatal: Errors detected during ipfw rules initialization.\n");
        exit(EXIT_FAILURE);
    }

    /* Allocate our rule_map array for tracking active (and expired) rules.
    */
    fwc.rule_map = calloc(fwc.max_rules, sizeof(char));

    if(fwc.rule_map == NULL)
    {
        fprintf(stderr, "Fatal: Memory allocation error in fw_initialize.\n");
        exit(EXIT_FAILURE);
    }

    /* Create a check-state rule if necessary.
    */
    if(strncasecmp(opts->config[CONF_IPFW_ADD_CHECK_STATE], "Y", 1) == 0)
    {
        zero_cmd_buffers();

        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_ADD_CHECK_STATE_ARGS,
            fwc.fw_command,
            fwc.start_rule_num,
            fwc.active_set_num
        );

        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, 0);

        if(EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_INFO, "Added check-state rule %u to set %u",
                fwc.start_rule_num,
                fwc.active_set_num
            );

            fwc.rule_map[0] = RULE_ACTIVE;
        }
        else
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf); 
    }

    /* Make sure our expire set is disabled.
    */
    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_DISABLE_SET_ARGS,
        fwc.fw_command,
        fwc.expire_set_num
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, 0);

    if(EXTCMD_IS_SUCCESS(res))
        log_msg(LOG_INFO, "Set ipfw set %u to disabled.",
            fwc.expire_set_num);
    else
        log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf); 

    /* Now read the expire set in case there are existing
     * rules to track.
    */
    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_LIST_EXP_SET_RULES_ARGS,
        opts->fw_config->fw_command,
        fwc.expire_set_num
    );

    res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE, 0);

    if(!EXTCMD_IS_SUCCESS(res))
    {
        log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, cmd_out); 
        return;
    }

    if(opts->verbose > 2)
        log_msg(LOG_INFO, "RES=%i, CMD_BUF: %s\nRULES LIST: %s", res, cmd_buf, cmd_out);

    /* Find the first "# DISABLED" string (if any).
    */
    ndx = strstr(cmd_out, "# DISABLED ");

    /* Assume no disabled rules if we did not see the string.
    */
    if(ndx == NULL)
        return;

    /* Otherwise we walk each line to pull the rule number and
     * set the appropriate rule map entries.
    */
    while(ndx != NULL)
    {
        /* Skip over the DISABLED string to the rule num.
        */
        ndx += 11;

        if(isdigit(*ndx))
        {
            curr_rule = atoi(ndx);

            if(curr_rule >= fwc.start_rule_num
              && curr_rule < fwc.start_rule_num + fwc.max_rules)
            {
                fwc.rule_map[curr_rule - fwc.start_rule_num] = RULE_EXPIRED;
                fwc.total_rules++;
            }
        }
        else
            log_msg(LOG_WARNING, "fw_initialize: No rule number found where expected.");

        /* Find the next "# DISABLED" string (if any).
        */
        ndx = strstr(ndx, "# DISABLED ");
    }
}


int
fw_cleanup(void)
{
    int     res, got_err = 0;

    zero_cmd_buffers();

    if(fwc.active_set_num > 0
        && ipfw_set_exists(fwc.fw_command, fwc.active_set_num))
    {
        /* Create the set delete command for active rules
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_DEL_RULE_SET_ARGS,
            fwc.fw_command,
            fwc.active_set_num
        );

        //printf("CMD: '%s'\n", cmd_buf);
        res = system(cmd_buf);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf); 
            got_err++;
        }
    }

/* --DSS Keep expired rule list so any existing established
         are not lost */
#if 0

    if(fwc.expire_set_num > 0)
    {
        /* Create the set delete command for expired rules
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_DEL_RULE_SET_ARGS,
            fwc.fw_command,
            fwc.expire_set_num
        );
   
        //printf("CMD: '%s'\n", cmd_buf);
        res = system(cmd_buf);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf); 
            got_err++;
        }
    }
#endif

    /* Free the rule map.
    */
    if(fwc.rule_map != NULL)
        free(fwc.rule_map);

    return(got_err);
}

/****************************************************************************/

/* Rule Processing - Create an access request...
*/
int
process_spa_request(fko_srv_options_t *opts, spa_data_t *spadat)
{
    unsigned short   rule_num;

    acc_port_list_t *port_list = NULL;
    acc_port_list_t *ple;

    unsigned int    fst_proto;
    unsigned int    fst_port;

    int             res = 0;
    time_t          now;
    unsigned int    exp_ts;

    /* Parse and expand our access message.
    */
    expand_acc_port_list(&port_list, spadat->spa_message_remain);

    /* Start at the top of the proto-port list...
    */
    ple = port_list;

    /* Remember the first proto/port combo in case we need them
     * for NAT access requests.
    */
    fst_proto = ple->proto;
    fst_port  = ple->port;

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
        /* Pull the next available rule number.
        */
        rule_num = get_next_rule_num();

        /* If rule_num comes back as 0, we aready have the maximum number
         * of active rules allowed so we reject and bail here.
        */
        if(rule_num == 0)
        {
            log_msg(LOG_WARNING, "Access request rejected: Maximum allowed number of rules has been reached.");
            return(-1);
        }

        /* Create an access command for each proto/port for the source ip.
        */
        while(ple != NULL)
        {
            zero_cmd_buffers();

            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_ADD_RULE_ARGS,
                fwc.fw_command,
                rule_num,
                fwc.active_set_num,
                ple->proto,
                spadat->use_src_ip,
                ple->port,
                exp_ts
            );

//--DSS tmp
//fprintf(stderr, "ADD CMD: %s\n", cmd_buf);
            res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, 0);
            if(EXTCMD_IS_SUCCESS(res))
            {
                log_msg(LOG_INFO, "Added Rule %u for %s, %s expires at %u",
                    rule_num,
                    spadat->use_src_ip,
                    spadat->spa_message_remain, exp_ts
                );

                fwc.rule_map[rule_num - fwc.start_rule_num] = RULE_ACTIVE;

                fwc.active_rules++;
                fwc.total_rules++;

                /* Reset the next expected expire time for this chain if it
                 * is warranted.
                */
                if(fwc.next_expire < now || exp_ts < fwc.next_expire)
                    fwc.next_expire = exp_ts;
            }
            else
                log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf); 

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

        return(-1);
    }

    return(res);
}

/* Iterate over the current rule set and purge expired
 * firewall rules.
*/
void
check_firewall_rules(fko_srv_options_t *opts)
{
    char            exp_str[12];
    char            rule_num_str[6];
    char           *ndx, *rn_start, *rn_end, *tmp_mark;

    int             i=0, res=0;
    time_t          now, rule_exp, min_exp = 0;
    unsigned short  curr_rule;

    time(&now);

    /* Just in case we somehow lose track and fall out-of-whack.
    */
    if(fwc.active_rules > fwc.max_rules)
        fwc.active_rules = 0;

    /* If there are no active rules or we have not yet
     * reached our expected next expire time, continue.
    */
    if(fwc.active_rules == 0 || fwc.next_expire > now)
        return;

    zero_cmd_buffers();

    /* There should be a rule to delete.  Get the current list of
     * rules for this chain and delete the ones that are expired.
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_LIST_SET_RULES_ARGS,
        opts->fw_config->fw_command,
        fwc.active_set_num
    );

    res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE, 0);

    if(!EXTCMD_IS_SUCCESS(res))
    {
        log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, cmd_out); 
        return;
    }

    if(opts->verbose > 2)
        log_msg(LOG_INFO, "RES=%i, CMD_BUF: %s\nRULES LIST: %s", res, cmd_buf, cmd_out);

    /* Find the first _exp_ string (if any).
    */
    ndx = strstr(cmd_out, EXPIRE_COMMENT_PREFIX);

    if(ndx == NULL)
    {
        /* we did not find an expected rule.
        */
        log_msg(LOG_ERR,
            "Did not find expire comment in rules list %i.\n", i);

        fwc.active_rules--;
        return;
    }

    /* Walk the list and process rules as needed.
    */
    while (ndx != NULL) {
        /* Jump forward and extract the timestamp
        */
        ndx += strlen(EXPIRE_COMMENT_PREFIX);

        /* remember this spot for when we look for the next
         * rule.
        */
        tmp_mark = ndx;

        strlcpy(exp_str, ndx, 11);
        rule_exp = (time_t)atoll(exp_str);

//fprintf(stderr, "RULE_EXP=%u, NOW=%u\n", rule_exp, now);
        if(rule_exp <= now)
        {
            /* Backtrack and get the rule number and delete it.
            */
            rn_start = ndx;
            while(--rn_start > cmd_out)
            {
                if(*rn_start == '\n')
                    break;
            }
            
            if(*rn_start == '\n')
            {
                rn_start++;
            }
            else if(rn_start > cmd_out)
            {
                /* This should not happen. But if it does, complain,
                 * decrement the active rule value, and go on.
                */
                log_msg(LOG_ERR,
                    "Rule parse error while finding rule line start.");

                fwc.active_rules--;
                break;
            }

            rn_end = strchr(rn_start, ' ');

            if(rn_end == NULL)
            {
                /* This should not happen. But if it does, complain,
                 * decrement the active rule value, and go on.
                */
                log_msg(LOG_ERR,
                    "Rule parse error while finding rule number.");

                fwc.active_rules--;
                break;
            }
             
            strlcpy(rule_num_str, rn_start, (rn_end - rn_start)+1);

            curr_rule = atoi(rule_num_str);

            zero_cmd_buffers();

            /* Move the rule to the expired rules set.
            */
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_MOVE_RULE_ARGS,
                opts->fw_config->fw_command,
                curr_rule,
                fwc.expire_set_num
            );

//fprintf(stderr, "MOVE RULE CMD: %s\n", cmd_buf);
            res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, 0);
            if(EXTCMD_IS_SUCCESS(res))
            {
                log_msg(LOG_INFO, "Moved rule %s with expire time of %u to set %u.",
                    rule_num_str, rule_exp, fwc.expire_set_num
                );

                fwc.active_rules--;
                fwc.rule_map[curr_rule - fwc.start_rule_num] = RULE_EXPIRED;
            }
            else
                log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf); 
        }
        else
        {
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

    /* Set the next pending expire time accordingly. 0 if there are no
     * more rules, or whatever the next expected (min_exp) time will be.
    */
    if(fwc.active_rules < 1)
        fwc.next_expire = 0;
    else if(min_exp)
        fwc.next_expire = min_exp;
}

/* Iterate over the expired rule set and purge those that no longer have
 * corresponding dynamic rules.
*/
void
ipfw_purge_expired_rules(fko_srv_options_t *opts)
{
    char           *ndx, *co_end;

    int             i, res;

    unsigned short  curr_rule;

    /* First, we get the current active dynamic rules for the expired rule
     * set. Then we compare it to the expired rules in the rule_map. Any
     * rules in the map that do not have a dynamic rule, can be deleted.
    */
    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_LIST_SET_DYN_RULES_ARGS,
        opts->fw_config->fw_command,
        fwc.expire_set_num
    );

    res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE, 0);

    if(!EXTCMD_IS_SUCCESS(res))
    {
        log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, cmd_out); 
        return;
    }

    /* We may not have any dynamic rules at all - someone might not have
     * initiated a connection (for example)
    */
    if (cmd_out[0] != '\0')
    {
        co_end = cmd_out + strlen(cmd_out);

        if(opts->verbose > 2)
            log_msg(LOG_INFO, "RES=%i, CMD_BUF: %s\nEXP RULES LIST: %s", res, cmd_buf, cmd_out);

        /* Find the "## Dynamic rules" string.
        */
        ndx = strcasestr(cmd_out, "## Dynamic rules");

        if(ndx == NULL)
        {
            log_msg(LOG_ERR,
                "Unexpected error: did not find 'Dynamic rules' string in list output."
            );
            return;
        }

        /* Jump to the next newline char.
        */
        ndx = strchr(ndx, '\n');

        if(ndx == NULL)
        {
            log_msg(LOG_ERR,
                "Unexpected error: did not find 'Dynamic rules' line terminating newline."
            );
            return;
        }

        /* Walk the list of dynamic rules (if any).
        */
        while(ndx != NULL)
        {
            ndx++;

            while(!isdigit(*ndx) && ndx < co_end)
                ndx++;

            if(ndx >= co_end)
                break;

            /* If we are at a digit, assume it is a rule number, extract it,
             * and if it falls in the correct range, mark it (so it is not
             * removed in the next step.
            */
            if(isdigit(*ndx))
            {
                curr_rule = atoi(ndx);

                if(curr_rule >= fwc.start_rule_num
                  && curr_rule < fwc.start_rule_num + fwc.max_rules)
                    fwc.rule_map[curr_rule - fwc.start_rule_num] = RULE_TMP_MARKED;
            }

            ndx = strchr(ndx, '\n');
        }
    }

    /* Now, walk the rule map and remove any still marked as expired.
    */
    for(i=0; i<fwc.max_rules; i++)
    {
        /* If it is TMP_MARKED, set it back to EXPIRED and move on.
        */
        if(fwc.rule_map[i] == RULE_TMP_MARKED)
        {
            fwc.rule_map[i] = RULE_EXPIRED;
            continue;
        }

        /* If it is not expired, move on.
        */
        if(fwc.rule_map[i] != RULE_EXPIRED)
            continue;

        /* This rule is ready to go away.
        */
        zero_cmd_buffers();

        curr_rule = fwc.start_rule_num + i;

        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPFW_DEL_RULE_ARGS,
            opts->fw_config->fw_command,
            fwc.expire_set_num,
            curr_rule
        );

        res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE, 0);

        if(!EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, cmd_out); 
            continue;
        }

        log_msg(LOG_INFO, "Purged rule %u from set %u", curr_rule, fwc.expire_set_num); 

        fwc.rule_map[curr_rule - fwc.start_rule_num] = RULE_FREE;

        fwc.total_rules--;
    }
}

#endif /* FIREWALL_IPFW */

/***EOF***/
