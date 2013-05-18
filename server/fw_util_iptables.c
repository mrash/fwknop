/*
 *****************************************************************************
 *
 * File:    fw_util_iptables.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Fwknop routines for managing iptables firewall rules.
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

#ifdef FIREWALL_IPTABLES

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

static void
chop_newline(char *str)
{
    if(str[0] != 0x0 && str[strlen(str)-1] == 0x0a)
        str[strlen(str)-1] = 0x0;
    return;
}

static int
comment_match_exists(const fko_srv_options_t * const opts)
{
    int               res = 1;
    char             *ndx = NULL;
    struct fw_chain  *in_chain  = &(opts->fw_config->chain[IPT_INPUT_ACCESS]);

    zero_cmd_buffers();

    /* Add a harmless rule to the iptables INPUT chain that uses the comment
     * match and make sure it exists.  If not, return zero.  Otherwise, delete
     * the rule and return true.
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_TMP_COMMENT_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->to_chain,
        1,   /* first rule */
        in_chain->target
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, 0);
    chop_newline(err_buf);

    if (opts->verbose)
        log_msg(LOG_INFO, "comment_match_exists() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_LIST_RULES_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->to_chain
    );

    res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE, 0);
    chop_newline(cmd_out);

    if(!EXTCMD_IS_SUCCESS(res))
        log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, cmd_out);

    ndx = strstr(cmd_out, TMP_COMMENT);
    if(ndx == NULL)
        res = 0;  /* did not find the tmp comment */
    else
        res = 1;

    if(res == 1)
    {
        /* Delete the tmp comment rule
        */
        zero_cmd_buffers();

        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_DEL_RULE_ARGS,
            opts->fw_config->fw_command,
            in_chain->table,
            in_chain->to_chain,
            1
        );
        run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, 0);
    }

    return res;
}

static int
add_jump_rule(const fko_srv_options_t * const opts, const int chain_num)
{
    int res = 0;

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_ADD_JUMP_RULE_ARGS,
        fwc.fw_command,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].from_chain,
        fwc.chain[chain_num].jump_rule_pos,
        fwc.chain[chain_num].to_chain
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, 0);

    if (opts->verbose)
        log_msg(LOG_INFO, "add_jump_rule() CMD: '%s' (res: %d, err: %s)",
            cmd_buf, res, err_buf);

    if(EXTCMD_IS_SUCCESS(res))
        log_msg(LOG_INFO, "Added jump rule from chain: %s to chain: %s",
            fwc.chain[chain_num].from_chain,
            fwc.chain[chain_num].to_chain);
    else
        log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);

    return res;
}

static int
chain_exists(const fko_srv_options_t * const opts, const int chain_num)
{
    int res = 0;

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_CHAIN_EXISTS_ARGS,
        fwc.fw_command,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].to_chain
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, 0);
    chop_newline(err_buf);

    if (opts->verbose)
        log_msg(LOG_INFO, "chain_exists() CMD: '%s' (res: %d, err: %s)",
            cmd_buf, res, err_buf);

    if(EXTCMD_IS_SUCCESS(res))
        log_msg(LOG_INFO, "'%s' table '%s' chain exists",
            fwc.chain[chain_num].table,
            fwc.chain[chain_num].to_chain);
    else
        log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);

    return res;
}

static int
jump_rule_exists(const fko_srv_options_t * const opts, const int chain_num)
{
    int     num, pos = 0;
    char    cmd_buf[CMD_BUFSIZE] = {0};
    char    target[CMD_BUFSIZE] = {0};
    char    line_buf[CMD_BUFSIZE] = {0};
    FILE   *ipt;

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_LIST_RULES_ARGS,
        fwc.fw_command,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].from_chain
    );

    ipt = popen(cmd_buf, "r");

    if(ipt == NULL)
    {
        log_msg(LOG_ERR,
            "Got error %i trying to get rules list.\n", errno);
        return(-1);
    }

    while((fgets(line_buf, CMD_BUFSIZE-1, ipt)) != NULL)
    {
        /* Get past comments and empty lines (note: we only look at the
         * first character).
        */
        if(IS_EMPTY_LINE(line_buf[0]))
            continue;

        if(sscanf(line_buf, "%i %s ", &num, target) == 2)
        {
            if(strcmp(target, fwc.chain[chain_num].to_chain) == 0)
            {
                pos = num;
                break;
            }
        }
    }

    pclose(ipt);

    if (opts->verbose)
    {
        if(pos > 0)
            log_msg(LOG_INFO, "jump_rule_exists() jump rule position: %d", pos);
        else
            log_msg(LOG_INFO, "jump_rule_exists() jump rule not found");
    }

    return(pos);
}

/* Print all firewall rules currently instantiated by the running fwknopd
 * daemon to stdout.
*/
int
fw_dump_rules(const fko_srv_options_t * const opts)
{
    int     i;
    int     res, got_err = 0;

    struct fw_chain *ch = opts->fw_config->chain;

    if (opts->fw_list_all == 1)
    {
        fprintf(stdout, "Listing all iptables rules in applicable tables...\n");
        fflush(stdout);

        for(i=0; i<(NUM_FWKNOP_ACCESS_TYPES); i++)
        {

            if(fwc.chain[i].target[0] == '\0')
                continue;

            zero_cmd_buffers();

            /* Create the list command
            */
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_LIST_ALL_RULES_ARGS,
                opts->fw_config->fw_command,
                ch[i].table
            );

            res = system(cmd_buf);

            if (opts->verbose)
                log_msg(LOG_INFO, "fw_dump_rules() CMD: '%s' (res: %d)",
                    cmd_buf, res);

            /* Expect full success on this */
            if(! EXTCMD_IS_SUCCESS(res))
            {
                log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf); 
                got_err++;
            }
        }
    }
    else
    {
        fprintf(stdout, "Listing rules in fwknopd iptables chains...\n");
        fflush(stdout);

        for(i=0; i<(NUM_FWKNOP_ACCESS_TYPES); i++)
        {

            if(fwc.chain[i].target[0] == '\0')
                continue;

            zero_cmd_buffers();

            /* Create the list command
            */
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_LIST_RULES_ARGS,
                opts->fw_config->fw_command,
                ch[i].table,
                ch[i].to_chain
            );

            fprintf(stdout, "\n");
            fflush(stdout);
            res = system(cmd_buf);

            if (opts->verbose)
                log_msg(LOG_INFO, "fw_dump_rules() CMD: '%s' (res: %d)",
                    cmd_buf, res);

            /* Expect full success on this */
            if(! EXTCMD_IS_SUCCESS(res))
            {
                log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);
                got_err++;
            }
        }
    }

    return(got_err);
}

/* Quietly flush and delete all fwknop custom chains.
*/
static void
delete_all_chains(const fko_srv_options_t * const opts)
{
    int     i, res;
    int     jump_rule_num;

    for(i=0; i<(NUM_FWKNOP_ACCESS_TYPES); i++)
    {
        if(fwc.chain[i].target[0] == '\0')
            continue;

        /* First look for a jump rule to this chain and remove it if it
         * is there.
        */
        if((jump_rule_num = jump_rule_exists(opts, i)) > 0)
        {
            zero_cmd_buffers();

            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_DEL_RULE_ARGS,
                fwc.fw_command,
                fwc.chain[i].table,
                fwc.chain[i].from_chain,
                jump_rule_num
            );

            res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, 0);
            chop_newline(err_buf);

            if (opts->verbose)
                log_msg(LOG_INFO, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
                    cmd_buf, res, err_buf);

            /* Expect full success on this */
            if(! EXTCMD_IS_SUCCESS(res))
                log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);
        }

        zero_cmd_buffers();

        /* Now flush and remove the chain.
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1,
            "(%s " IPT_FLUSH_CHAIN_ARGS "; %s " IPT_DEL_CHAIN_ARGS ")", // > /dev/null 2>&1",
            fwc.fw_command,
            fwc.chain[i].table,
            fwc.chain[i].to_chain,
            fwc.fw_command,
            fwc.chain[i].table,
            fwc.chain[i].to_chain
        );

        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, 0);
        chop_newline(err_buf);

        if (opts->verbose)
            log_msg(LOG_INFO, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);
    }
}

static int
create_chain(const fko_srv_options_t * const opts, const int chain_num)
{
    int res = 0;

    zero_cmd_buffers();

    /* Create the custom chain.
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_NEW_CHAIN_ARGS,
        fwc.fw_command,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].to_chain
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, 0);
    chop_newline(err_buf);

    if (opts->verbose)
        log_msg(LOG_INFO, "create_chain() CMD: '%s' (res: %d, err: %s)",
            cmd_buf, res, err_buf);

    /* Expect full success on this */
    if(! EXTCMD_IS_SUCCESS(res))
        log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);

    return res;
}

/* Create the fwknop custom chains (at least those that are configured).
*/
static int
create_fw_chains(const fko_srv_options_t * const opts)
{
    int     i, got_err = 0;

    for(i=0; i<(NUM_FWKNOP_ACCESS_TYPES); i++)
    {
        if(fwc.chain[i].target[0] == '\0')
            continue;

        if(chain_exists(opts, i) == 0)
        {

            /* Create the chain
            */
            if(! EXTCMD_IS_SUCCESS(create_chain(opts, i)))
                got_err++;

            /* Then create the jump rule to that chain if it
             * doesn't already exist (which is possible)
            */
            if(jump_rule_exists(opts, i) == 0)
                if(! EXTCMD_IS_SUCCESS(add_jump_rule(opts, i)))
                    got_err++;
        }
    }

    return(got_err);
}

static void
set_fw_chain_conf(const int type, const char * const conf_str)
{
    int i, j, is_err;
    char tbuf[1024]     = {0};
    const char *ndx     = conf_str;

    char *chain_fields[FW_NUM_CHAIN_FIELDS];

    struct fw_chain *chain = &(fwc.chain[type]);

    if(conf_str == NULL)
    {
        fprintf(stderr, "[*] NULL conf_str.\n");
        exit(EXIT_FAILURE);
    }

    chain->type = type;

    if(ndx != NULL)
        chain_fields[0] = tbuf;

    i = 0;
    j = 1;
    while(*ndx != '\0')
    {
        if(*ndx != ' ')
        {
            if(*ndx == ',')
            {
                tbuf[i] = '\0';
                chain_fields[j++] = &(tbuf[++i]);
            }
            else
                tbuf[i++] = *ndx;
        }
        ndx++;
    }

    /* Sanity check - j should be the number of chain fields
     * (excluding the type).
    */
    if(j != FW_NUM_CHAIN_FIELDS)
    {
        fprintf(stderr, "[*] Custom Chain config parse error.\n"
            "Wrong number of fields for chain type %i\n"
            "Line: %s\n", type, conf_str);
        exit(EXIT_FAILURE);
    }

    /* Pull and set Target */
    strlcpy(chain->target, chain_fields[0], sizeof(chain->target));

    /* Pull and set Table */
    strlcpy(chain->table, chain_fields[1], sizeof(chain->table));

    /* Pull and set From_chain */
    strlcpy(chain->from_chain, chain_fields[2], sizeof(chain->from_chain));

    /* Pull and set Jump_rule_position */
    chain->jump_rule_pos = strtol_wrapper(chain_fields[3],
            0, RCHK_MAX_IPT_RULE_NUM, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] invalid jump rule position in Line: %s\n",
            conf_str);
        exit(EXIT_FAILURE);
    }

    /* Pull and set To_chain */
    strlcpy(chain->to_chain, chain_fields[4], sizeof(chain->to_chain));

    /* Pull and set to_chain rule position */
    chain->rule_pos = strtol_wrapper(chain_fields[5],
            0, RCHK_MAX_IPT_RULE_NUM, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] invalid to_chain rule position in Line: %s\n",
            conf_str);
        exit(EXIT_FAILURE);
    }
}

void
fw_config_init(fko_srv_options_t * const opts)
{

    memset(&fwc, 0x0, sizeof(struct fw_config));

    /* Set our firewall exe command path (iptables in most cases).
    */
    strlcpy(fwc.fw_command, opts->config[CONF_FIREWALL_EXE], sizeof(fwc.fw_command));

    /* Pull the fwknop chain config info and setup our internal
     * config struct.  The IPT_INPUT is the only one that is
     * required. The rest are optional.
    */
    set_fw_chain_conf(IPT_INPUT_ACCESS, opts->config[CONF_IPT_INPUT_ACCESS]);

    /* The FWKNOP_OUTPUT_ACCESS requires ENABLE_IPT_OUTPUT_ACCESS be Y
    */
    if(strncasecmp(opts->config[CONF_ENABLE_IPT_OUTPUT], "Y", 1)==0)
        set_fw_chain_conf(IPT_OUTPUT_ACCESS, opts->config[CONF_IPT_OUTPUT_ACCESS]);

    /* The remaining access chains require ENABLE_IPT_FORWARDING = Y
    */
    if(strncasecmp(opts->config[CONF_ENABLE_IPT_FORWARDING], "Y", 1)==0)
    {

        set_fw_chain_conf(IPT_FORWARD_ACCESS, opts->config[CONF_IPT_FORWARD_ACCESS]);
        set_fw_chain_conf(IPT_DNAT_ACCESS, opts->config[CONF_IPT_DNAT_ACCESS]);

        /* SNAT (whichever mode) requires ENABLE_IPT_SNAT = Y
        */
        if(strncasecmp(opts->config[CONF_ENABLE_IPT_SNAT], "Y", 1)==0)
        {
            /* If an SNAT_TRANSLATE_IP is specified use the SNAT_ACCESS mode.
             * Otherwise, use MASQUERADE_ACCESS.
             *
             * XXX: --DSS: Not sure if using the TRANSLATE_IP parameter as
             *             the determining factor is the best why to handle
             *             this.
             *
            */
            if(opts->config[CONF_SNAT_TRANSLATE_IP] != NULL
              && strncasecmp(opts->config[CONF_SNAT_TRANSLATE_IP], "__CHANGEME__", 10)!=0)
                set_fw_chain_conf(IPT_SNAT_ACCESS, opts->config[CONF_IPT_SNAT_ACCESS]);
            else
                set_fw_chain_conf(IPT_MASQUERADE_ACCESS, opts->config[CONF_IPT_MASQUERADE_ACCESS]);
        }
    }

    /* Let us find it via our opts struct as well.
    */
    opts->fw_config = &fwc;

    return;
}

void
fw_initialize(const fko_srv_options_t * const opts)
{
    int res;

    /* Flush the chains (just in case) so we can start fresh.
    */
    if(strncasecmp(opts->config[CONF_FLUSH_IPT_AT_INIT], "Y", 1) == 0)
        delete_all_chains(opts);

    /* Now create any configured chains.
    */
    res = create_fw_chains(opts);

    if(res != 0)
    {
        fprintf(stderr, "Warning: Errors detected during fwknop custom chain creation.\n");
        exit(EXIT_FAILURE);
    }

    /* Make sure that the 'comment' match is available
    */
    if((strncasecmp(opts->config[CONF_ENABLE_IPT_COMMENT_CHECK], "Y", 1) == 0)
            && (comment_match_exists(opts) != 1))
    {
        fprintf(stderr, "Warning: Could not use the 'comment' match.\n");
        exit(EXIT_FAILURE);
    }
}

int
fw_cleanup(const fko_srv_options_t * const opts)
{
    if(strncasecmp(opts->config[CONF_FLUSH_IPT_AT_EXIT], "N", 1) == 0
            && opts->fw_flush == 0)
        return(0);

    delete_all_chains(opts);
    return(0);
}

static int
rule_exists(const fko_srv_options_t * const opts,
        const char * const fw_chain, const char * const fw_rule)
{
    int     rule_exists = 0;
    int     res = 0;

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s -C %s %s",
            opts->fw_config->fw_command, fw_chain, fw_rule);

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, 0);
    chop_newline(err_buf);

    if (opts->verbose)
        log_msg(LOG_INFO, "rule_exists() CMD: '%s' (res: %d, err: %s)",
            cmd_buf, res, err_buf);

    if(EXTCMD_IS_SUCCESS(res) && strlen(err_buf))
    {
        rule_exists = 0;
        log_msg(LOG_INFO, "rule_exists() Rule : '%s' in %s does not exist.",
                fw_rule, fw_chain);
    }
    else
    {
        rule_exists = 1;
        if (opts->verbose)
            log_msg(LOG_INFO, "rule_exists() Rule : '%s' in %s already exist.",
                    fw_rule, fw_chain);
    }

    return rule_exists;
}

static int
create_rule(const fko_srv_options_t * const opts,
        const char * const fw_chain, const char * const fw_rule)
{
    int res;

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s -A %s %s", opts->fw_config->fw_command, fw_chain, fw_rule);

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, 0);
    chop_newline(err_buf);

    if (opts->verbose)
        log_msg(LOG_INFO, "create_rule() CMD: '%s' (res: %d, err: %s)",
            cmd_buf, res, err_buf);

    if(EXTCMD_IS_SUCCESS(res))
    {
        res = 0;
        if (opts->verbose)
            log_msg(LOG_INFO, "create_rule() Rule: '%s' added to %s", fw_rule, fw_chain);
    }
    else
    {
        res = 1;
        log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);
    }

    return res;
}

/****************************************************************************/

/* Rule Processing - Create an access request...
*/
int
process_spa_request(const fko_srv_options_t * const opts,
        const acc_stanza_t * const acc, spa_data_t * const spadat)
{
    char             nat_ip[MAX_IPV4_STR_LEN] = {0};
    char             snat_target[SNAT_TARGET_BUFSIZE] = {0};
    char            *ndx;
    char             rule_buf[CMD_BUFSIZE];

    unsigned int     nat_port = 0;

    acc_port_list_t *port_list = NULL;
    acc_port_list_t *ple = NULL;

    unsigned int    fst_proto;
    unsigned int    fst_port;

    struct fw_chain * const in_chain   = &(opts->fw_config->chain[IPT_INPUT_ACCESS]);
    struct fw_chain * const out_chain  = &(opts->fw_config->chain[IPT_OUTPUT_ACCESS]);
    struct fw_chain * const fwd_chain  = &(opts->fw_config->chain[IPT_FORWARD_ACCESS]);
    struct fw_chain * const dnat_chain = &(opts->fw_config->chain[IPT_DNAT_ACCESS]);
    struct fw_chain *snat_chain; /* We assign this later (if we need to). */

    int             res = 0, is_err;
    time_t          now;
    unsigned int    exp_ts;

    /* Parse and expand our access message.
    */
    if(expand_acc_port_list(&port_list, spadat->spa_message_remain) != 1)
    {
        /* technically we would already have exited with an error if there were
         * any memory allocation errors (see the add_port_list() function), but
         * for completeness...
        */
        free_acc_port_list(port_list);
        return res;
    }

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
    if((spadat->message_type == FKO_ACCESS_MSG
      || spadat->message_type == FKO_CLIENT_TIMEOUT_ACCESS_MSG) && !acc->force_nat)
    {

        /* Check to make sure that the jump rules exist for each
         * required chain
        */
        if(chain_exists(opts, IPT_INPUT_ACCESS) == 0)
            create_chain(opts, IPT_INPUT_ACCESS);

        if(jump_rule_exists(opts, IPT_INPUT_ACCESS) == 0)
            add_jump_rule(opts, IPT_INPUT_ACCESS);

        if(strlen(out_chain->to_chain))
        {
            if(chain_exists(opts, IPT_OUTPUT_ACCESS) == 0)
                create_chain(opts, IPT_OUTPUT_ACCESS);

            if(jump_rule_exists(opts, IPT_OUTPUT_ACCESS) == 0)
                add_jump_rule(opts, IPT_OUTPUT_ACCESS);
        }

        /* Create an access command for each proto/port for the source ip.
        */
        while(ple != NULL)
        {
            memset(rule_buf, 0, CMD_BUFSIZE);

            snprintf(rule_buf, CMD_BUFSIZE-1, IPT_RULE_ARGS,
                in_chain->table,
                ple->proto,
                spadat->use_src_ip,
                ple->port,
                exp_ts,
                in_chain->target
            );

            if(rule_exists(opts, in_chain->to_chain, rule_buf) == 0)
            {
                if (create_rule(opts, in_chain->to_chain, rule_buf) == 0)
                {
                    log_msg(LOG_INFO, "Added Rule to %s for %s, %s expires at %u",
                        in_chain->to_chain, spadat->use_src_ip,
                        spadat->spa_message_remain, exp_ts
                    );

                    in_chain->active_rules++;

                    /* Reset the next expected expire time for this chain if it
                    * is warranted.
                    */
                    if(in_chain->next_expire < now || exp_ts < in_chain->next_expire)
                        in_chain->next_expire = exp_ts;
                }
            }

            /* If we have to make an corresponding OUTPUT rule if out_chain target
            * is not NULL.
            */
            if(strlen(out_chain->to_chain))
            {
                memset(rule_buf, 0, CMD_BUFSIZE);

                snprintf(rule_buf, CMD_BUFSIZE-1, IPT_OUT_RULE_ARGS,
                    out_chain->table,
                    ple->proto,
                    spadat->use_src_ip,
                    ple->port,
                    exp_ts,
                    out_chain->target
                );

                if(rule_exists(opts, out_chain->to_chain, rule_buf) == 0)
                {
                    if (create_rule(opts, out_chain->to_chain, rule_buf) == 0)
                    {
                        log_msg(LOG_INFO, "Rule in %s for %s, %s expires at %u, does not exist.",
                            out_chain->to_chain, spadat->use_src_ip,
                            spadat->spa_message_remain, exp_ts
                        );

                        out_chain->active_rules++;

                        /* Reset the next expected expire time for this chain if it
                        * is warranted.
                        */
                        if(out_chain->next_expire < now || exp_ts < out_chain->next_expire)
                            out_chain->next_expire = exp_ts;
                    }
                }
            }
            ple = ple->next;
        }
    }
    /* NAT requests... */
    else if(spadat->message_type == FKO_LOCAL_NAT_ACCESS_MSG
      || spadat->message_type == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG
      || spadat->message_type == FKO_NAT_ACCESS_MSG
      || spadat->message_type == FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG
      || acc->force_nat)
    {
        /* Parse out the NAT IP and Port components.
        */
        if(acc->force_nat)
        {
            strlcpy(nat_ip, acc->force_nat_ip, sizeof(nat_ip));
            nat_port = acc->force_nat_port;
        }
        else
        {
            ndx = strchr(spadat->nat_access, ',');
            if(ndx != NULL)
            {
                strlcpy(nat_ip, spadat->nat_access, (ndx-spadat->nat_access)+1);
                nat_port = strtol_wrapper(ndx+1, 0, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
                if(is_err != FKO_SUCCESS)
                {
                    log_msg(LOG_INFO, "Invalid NAT port in SPA message");
                    free_acc_port_list(port_list);
                    return res;
                }
            }
        }

        if(spadat->message_type == FKO_LOCAL_NAT_ACCESS_MSG)
        {
            memset(rule_buf, 0, CMD_BUFSIZE);

            snprintf(rule_buf, CMD_BUFSIZE-1, IPT_RULE_ARGS,
                in_chain->table,
                fst_proto,
                spadat->use_src_ip,
                nat_port,
                exp_ts,
                in_chain->target
            );

            if(rule_exists(opts, in_chain->to_chain, rule_buf) == 0)
            {
                if (create_rule(opts, in_chain->to_chain, rule_buf) == 0)
                {
                    log_msg(LOG_INFO, "Added Rule to %s for %s, %s expires at %u",
                        in_chain->to_chain, spadat->use_src_ip,
                        spadat->spa_message_remain, exp_ts
                    );

                    in_chain->active_rules++;

                    /* Reset the next expected expire time for this chain if it
                    * is warranted.
                    */
                    if(in_chain->next_expire < now || exp_ts < in_chain->next_expire)
                        in_chain->next_expire = exp_ts;
                }
            }

        }
        else if(strlen(fwd_chain->to_chain))
        {
            /* Make our FORWARD and NAT rules, and make sure the
             * required chain and jump rule exists
            */
            if(chain_exists(opts, IPT_FORWARD_ACCESS) == 0)
                create_chain(opts, IPT_FORWARD_ACCESS);

            if (jump_rule_exists(opts, IPT_FORWARD_ACCESS) == 0)
                add_jump_rule(opts, IPT_FORWARD_ACCESS);

            memset(rule_buf, 0, CMD_BUFSIZE);

            snprintf(rule_buf, CMD_BUFSIZE-1, IPT_FWD_RULE_ARGS,
                fwd_chain->table,
                fst_proto,
                spadat->use_src_ip,
                nat_ip,
                nat_port,
                exp_ts,
                fwd_chain->target
            );

            if(rule_exists(opts, fwd_chain->to_chain, rule_buf) == 0)
            {
                if (create_rule(opts, fwd_chain->to_chain, rule_buf) == 0)
                {
                    log_msg(LOG_INFO, "Added FORWARD Rule to %s for %s, %s expires at %u",
                        fwd_chain->to_chain, spadat->use_src_ip,
                        spadat->spa_message_remain, exp_ts
                    );

                    fwd_chain->active_rules++;

                    /* Reset the next expected expire time for this chain if it
                    * is warranted.
                    */
                    if(fwd_chain->next_expire < now || exp_ts < fwd_chain->next_expire)
                        fwd_chain->next_expire = exp_ts;
                }
            }
        }

        if(strlen(dnat_chain->to_chain))
        {
            /* Make sure the required chain and jump rule exists
            */
            if(chain_exists(opts, IPT_DNAT_ACCESS) == 0)
                create_chain(opts, IPT_DNAT_ACCESS);

            if (jump_rule_exists(opts, IPT_DNAT_ACCESS) == 0)
                add_jump_rule(opts, IPT_DNAT_ACCESS);

            memset(rule_buf, 0, CMD_BUFSIZE);

            snprintf(rule_buf, CMD_BUFSIZE-1, IPT_DNAT_RULE_ARGS,
                dnat_chain->table,
                fst_proto,
                spadat->use_src_ip,
                fst_port,
                exp_ts,
                dnat_chain->target,
                nat_ip,
                nat_port
            );

            if(rule_exists(opts, dnat_chain->to_chain, rule_buf) == 0)
            {
                if (create_rule(opts, dnat_chain->to_chain, rule_buf) == 0)
                {
                    log_msg(LOG_INFO, "Added DNAT Rule to %s for %s, %s expires at %u",
                        dnat_chain->to_chain, spadat->use_src_ip,
                        spadat->spa_message_remain, exp_ts
                    );

                    dnat_chain->active_rules++;

                    /* Reset the next expected expire time for this chain if it
                    * is warranted.
                    */
                    if(dnat_chain->next_expire < now || exp_ts < dnat_chain->next_expire)
                        dnat_chain->next_expire = exp_ts;
                }
            }
        }

        /* If SNAT (or MASQUERADE) is wanted, then we add those rules here as well.
        */
        if(strncasecmp(opts->config[CONF_ENABLE_IPT_SNAT], "Y", 1) == 0)
        {
            /* Setup some parameter depending on whether we are using SNAT
             * or MASQUERADE.
            */
            if(strncasecmp(opts->config[CONF_SNAT_TRANSLATE_IP], "__CHANGEME__", 10)!=0)
            {
                /* Using static SNAT */
                snat_chain = &(opts->fw_config->chain[IPT_SNAT_ACCESS]);
                snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                    "--to-source %s:%i", opts->config[CONF_SNAT_TRANSLATE_IP],
                    fst_port);
            }
            else
            {
                /* Using MASQUERADE */
                snat_chain = &(opts->fw_config->chain[IPT_MASQUERADE_ACCESS]);
                snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                    "--to-ports %i", fst_port);
            }

            memset(rule_buf, 0, CMD_BUFSIZE);

            snprintf(rule_buf, CMD_BUFSIZE-1, IPT_SNAT_RULE_ARGS,
                snat_chain->table,
                fst_proto,
                nat_ip,
                nat_port,
                exp_ts,
                snat_chain->target,
                snat_target
            );

            if(rule_exists(opts, snat_chain->to_chain, rule_buf) == 0)
            {
                if(create_rule(opts, snat_chain->to_chain, rule_buf) == 0)
                {
                    log_msg(LOG_INFO, "Added Source NAT Rule to %s for %s, %s expires at %u",
                        snat_chain->to_chain, spadat->use_src_ip,
                        spadat->spa_message_remain, exp_ts
                    );

                    snat_chain->active_rules++;

                    /* Reset the next expected expire time for this chain if it
                    * is warranted.
                    */
                    if(snat_chain->next_expire < now || exp_ts < snat_chain->next_expire)
                            snat_chain->next_expire = exp_ts;
                }
            }
        }
    }

    /* Done with the port list for access rules.
    */
    free_acc_port_list(port_list);

    return(res);
}

/* Iterate over the configure firewall access chains and purge expired
 * firewall rules.
*/
void
check_firewall_rules(const fko_srv_options_t * const opts)
{
    char             exp_str[12];
    char             rule_num_str[6];
    char            *ndx, *rn_start, *rn_end, *tmp_mark;

    int             i, res, rn_offset, rule_num, is_err;
    time_t          now, rule_exp, min_exp = 0;

    struct fw_chain *ch = opts->fw_config->chain;

    time(&now);

    /* Iterate over each chain and look for active rules to delete.
    */
    for(i = 0; i < NUM_FWKNOP_ACCESS_TYPES; i++)
    {
        /* If there are no active rules or we have not yet
         * reached our expected next expire time, continue.
        */
        if(ch[i].active_rules == 0 || ch[i].next_expire > now)
            continue;

        zero_cmd_buffers();

        rn_offset = 0;

        /* There should be a rule to delete.  Get the current list of
         * rules for this chain and delete the ones that are expired.
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_LIST_RULES_ARGS,
            opts->fw_config->fw_command,
            ch[i].table,
            ch[i].to_chain
        );

        res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE, 0);
        chop_newline(cmd_out);

        if (opts->verbose)
            log_msg(LOG_INFO, "check_firewall_rules() CMD: '%s' (res: %d, cmd_out: %s)",
                cmd_buf, res, cmd_out);

        if(!EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, cmd_out);
            continue;
        }

        if(opts->verbose > 1)
            log_msg(LOG_INFO, "RES=%i, CMD_BUF: %s\nRULES LIST: %s", res, cmd_buf, cmd_out);

        ndx = strstr(cmd_out, EXPIRE_COMMENT_PREFIX);
        if(ndx == NULL)
        {
            /* we did not find an expected rule.
            */
            log_msg(LOG_ERR,
                "Did not find expire comment in rules list %i.\n", i);

            if (ch[i].active_rules > 0)
                ch[i].active_rules--;

            continue;
        }

        /* walk the list and process rules as needed.
        */
        while (ndx != NULL) {
            /* Jump forward and extract the timestamp
            */
            ndx += strlen(EXPIRE_COMMENT_PREFIX);

            /* remember this spot for when we look for the next
             * rule.
            */
            tmp_mark = ndx;

            strlcpy(exp_str, ndx, sizeof(exp_str));
            rule_exp = (time_t)atoll(exp_str);

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

                if(*rn_start != '\n')
                {
                    /* This should not happen. But if it does, complain,
                     * decrement the active rule value, and go on.
                    */
                    log_msg(LOG_ERR,
                        "Rule parse error while finding rule line start in chain %i", i);

                    if (ch[i].active_rules > 0)
                        ch[i].active_rules--;

                    break;
                }
                rn_start++;

                rn_end = strchr(rn_start, ' ');
                if(rn_end == NULL)
                {
                    /* This should not happen. But if it does, complain,
                     * decrement the active rule value, and go on.
                    */
                    log_msg(LOG_ERR,
                        "Rule parse error while finding rule number in chain %i", i);

                    if (ch[i].active_rules > 0)
                        ch[i].active_rules--;

                    break;
                }

                strlcpy(rule_num_str, rn_start, (rn_end - rn_start)+1);

                rule_num = strtol_wrapper(rule_num_str, rn_offset, RCHK_MAX_IPT_RULE_NUM,
                        NO_EXIT_UPON_ERR, &is_err);
                if(is_err != FKO_SUCCESS)
                {
                    log_msg(LOG_ERR,
                        "Rule parse error while finding rule number in chain %i", i);

                    if (ch[i].active_rules > 0)
                        ch[i].active_rules--;

                    break;
                }

                zero_cmd_buffers();

                snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_DEL_RULE_ARGS,
                    opts->fw_config->fw_command,
                    ch[i].table,
                    ch[i].to_chain,
                    rule_num - rn_offset
                );

                res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, 0);
                chop_newline(err_buf);

                if (opts->verbose)
                    log_msg(LOG_INFO, "check_firewall_rules() CMD: '%s' (res: %d, err: %s)",
                        cmd_buf, res, err_buf);

                if(EXTCMD_IS_SUCCESS(res))
                {
                    log_msg(LOG_INFO, "Removed rule %s from %s with expire time of %u.",
                        rule_num_str, ch[i].to_chain, rule_exp
                    );

                    rn_offset++;

                    if (ch[i].active_rules > 0)
                        ch[i].active_rules--;
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
        if(ch[i].active_rules < 1)
            ch[i].next_expire = 0;
        else if(min_exp)
            ch[i].next_expire = min_exp;
    }
}

#endif /* FIREWALL_IPTABLES */

/***EOF***/
