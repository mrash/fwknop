/*
 *****************************************************************************
 *
 * File:    fw_util_firewalld.c
 *
 * Purpose: Fwknop routines for managing firewalld firewall rules.
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

#ifdef FIREWALL_FIREWALLD

#include "fw_util.h"
#include "utils.h"
#include "log_msg.h"
#include "extcmd.h"
#include "access.h"

static struct fw_config fwc;
static char   cmd_buf[CMD_BUFSIZE];
static char   err_buf[CMD_BUFSIZE];
static char   cmd_out[STANDARD_CMD_OUT_BUFSIZE];

/* assume 'firewall-cmd --direct --passthrough ipv4 -C' is offered
 * (see firewd_chk_support()).
*/
static int have_firewd_chk_support = 1;

static void
zero_cmd_buffers(void)
{
    memset(cmd_buf, 0x0, CMD_BUFSIZE);
    memset(err_buf, 0x0, CMD_BUFSIZE);
    memset(cmd_out, 0x0, STANDARD_CMD_OUT_BUFSIZE);
}

static int pid_status = 0;

static void
chop_newline(char *str)
{
    if(str[0] != 0x0 && str[strlen(str)-1] == 0x0a)
        str[strlen(str)-1] = 0x0;
    return;
}

static int
rule_exists_no_chk_support(const fko_srv_options_t * const opts,
        const struct fw_chain * const fwc, const unsigned int proto,
        const char * const srcip, const char * const dstip, 
        const unsigned int port, const unsigned int exp_ts)
{
    int     rule_exists=0, rule_num=0, rtmp=0;
    char    cmd_buf[CMD_BUFSIZE]       = {0};
    char    target_search[CMD_BUFSIZE] = {0};
    char    proto_search[CMD_BUFSIZE]  = {0};
    char    srcip_search[CMD_BUFSIZE]  = {0};
    char    dstip_search[CMD_BUFSIZE]  = {0};
    char    port_search[CMD_BUFSIZE]   = {0};
    char    exp_ts_search[CMD_BUFSIZE] = {0};

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_LIST_RULES_ARGS,
        opts->fw_config->fw_command,
        fwc->table,
        fwc->to_chain
    );

    if(proto == IPPROTO_TCP)
        snprintf(proto_search, CMD_BUFSIZE-1, " tcp ");
    else if(proto == IPPROTO_UDP)
        snprintf(proto_search, CMD_BUFSIZE-1, " udp ");
    else if(proto == IPPROTO_ICMP)
        snprintf(proto_search, CMD_BUFSIZE-1, " icmp ");
    else
        snprintf(proto_search, CMD_BUFSIZE-1, " %u ", proto);

    snprintf(port_search, CMD_BUFSIZE-1, ":%u ", port);
    snprintf(target_search, CMD_BUFSIZE-1, " %s ", fwc->target);
    snprintf(srcip_search, CMD_BUFSIZE-1, " %s ", srcip);
    if (dstip != NULL)
    {
        snprintf(dstip_search, CMD_BUFSIZE-1, " %s ", dstip);
    }
    snprintf(exp_ts_search, CMD_BUFSIZE-1, "%u ", exp_ts);

    /* search for each of the substrings, and require the returned
     * rule number to be the same across all searches to return true
    */
    rtmp = search_extcmd(cmd_buf, WANT_STDERR,
            NO_TIMEOUT, exp_ts_search, &pid_status, opts);

    if(rtmp > 0)
    {
        rule_num = rtmp;
        rtmp = search_extcmd(cmd_buf, WANT_STDERR,
                NO_TIMEOUT, proto_search, &pid_status, opts);
        if(rtmp == rule_num)
            rtmp = search_extcmd(cmd_buf, WANT_STDERR,
                    NO_TIMEOUT, srcip_search, &pid_status, opts);
            if(rtmp == rule_num)
                rtmp = (dstip == NULL) ? rtmp : search_extcmd(cmd_buf, WANT_STDERR,
                        NO_TIMEOUT, dstip_search, &pid_status, opts);
                if(rtmp == rule_num)
                    rtmp = search_extcmd(cmd_buf, WANT_STDERR,
                            NO_TIMEOUT, target_search, &pid_status, opts);
                    if(rtmp == rule_num)
                        rtmp = search_extcmd(cmd_buf, WANT_STDERR,
                                NO_TIMEOUT, port_search, &pid_status, opts);
                        if(rtmp == rule_num)
                            rule_exists = 1;
    }

    if(rule_exists)
        log_msg(LOG_DEBUG,
                "rule_exists_no_chk_support() %s %u -> %s expires: %u rule (already exists",
                proto_search, port, srcip, exp_ts);
    else
        log_msg(LOG_DEBUG,
                "rule_exists_no_chk_support() %s %u -> %s expires: %u rule does not exist",
                proto_search, port, srcip, exp_ts);

   return(rule_exists);
}

static int
rule_exists_chk_support(const fko_srv_options_t * const opts,
        const char * const chain, const char * const rule)
{
    int     rule_exists = 0;
    int     res = 0;

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_CHK_RULE_ARGS,
            opts->fw_config->fw_command, chain, rule);

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "rule_exists_chk_support() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    if(strncmp(err_buf, "success", strlen("success")) == 0)
    {
        rule_exists = 1;
        log_msg(LOG_DEBUG, "rule_exists_chk_support() Rule : '%s' in %s already exists",
                rule, chain);
    }
    else
    {
        log_msg(LOG_DEBUG, "rule_exists_chk_support() Rule : '%s' in %s does not exist",
                rule, chain);
    }

    return(rule_exists);
}

static int
rule_exists(const fko_srv_options_t * const opts,
        const struct fw_chain * const fwc, const char * const rule,
        const unsigned int proto, const char * const srcip,
        const char * const dstip, const unsigned int port, 
        const unsigned int exp_ts)
{
    int rule_exists = 0;

    if(have_firewd_chk_support == 1)
        rule_exists = rule_exists_chk_support(opts, fwc->to_chain, rule);
    else
        rule_exists = rule_exists_no_chk_support(opts, fwc, proto, srcip, (opts->fw_config->use_destination ? dstip : NULL), port, exp_ts);

    if(rule_exists == 1)
        log_msg(LOG_DEBUG, "rule_exists() Rule : '%s' in %s already exists",
                rule, fwc->to_chain);
    else
        log_msg(LOG_DEBUG, "rule_exists() Rule : '%s' in %s does not exist",
                rule, fwc->to_chain);

    return(rule_exists);
}

static void
firewd_chk_support(const fko_srv_options_t * const opts)
{
    int               res = 1;
    struct fw_chain  *in_chain = &(opts->fw_config->chain[FIREWD_INPUT_ACCESS]);

    zero_cmd_buffers();

    /* Add a harmless rule to the firewalld INPUT chain and see if firewalld
     * supports '-C' to check for it.  Set "have_firewd_chk_support" accordingly,
     * delete the rule, and return.
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_TMP_CHK_RULE_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->from_chain,
        1,   /* first rule */
        in_chain->target
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "firewd_chk_support() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    zero_cmd_buffers();

    /* Now see if '-C' works
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_TMP_VERIFY_CHK_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->from_chain,
        in_chain->target
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "firewd_chk_support() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    if(strncmp(err_buf, "success", strlen("success")) == 0)
    {
        log_msg(LOG_DEBUG, "firewd_chk_support() -C supported");
        have_firewd_chk_support = 1;
    }
    else
    {
        log_msg(LOG_DEBUG, "firewd_chk_support() -C not supported");
        have_firewd_chk_support = 0;
    }

    /* Delete the tmp rule
    */
    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_DEL_RULE_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->from_chain,
        1
    );
    run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

    return;
}

static int
comment_match_exists(const fko_srv_options_t * const opts)
{
    int               res = 1;
    char             *ndx = NULL;
    struct fw_chain  *in_chain  = &(opts->fw_config->chain[FIREWD_INPUT_ACCESS]);

    zero_cmd_buffers();

    /* Add a harmless rule to the firewalld INPUT chain that uses the comment
     * match and make sure it exists.  If not, return zero.  Otherwise, delete
     * the rule and return true.
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_TMP_COMMENT_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->from_chain,
        1,   /* first rule */
        in_chain->target
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "comment_match_exists() CMD: '%s' (res: %d, err: %s)",
            cmd_buf, res, err_buf);

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_LIST_RULES_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->from_chain
    );

    res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
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

        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_DEL_RULE_ARGS,
            opts->fw_config->fw_command,
            in_chain->table,
            in_chain->from_chain,
            1
        );
        run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
                WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    }

    return res;
}

static int
add_jump_rule(const fko_srv_options_t * const opts, const int chain_num)
{
    int res = 0;

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_ADD_JUMP_RULE_ARGS,
        fwc.fw_command,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].from_chain,
        fwc.chain[chain_num].jump_rule_pos,
        fwc.chain[chain_num].to_chain
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

    log_msg(LOG_DEBUG, "add_jump_rule() CMD: '%s' (res: %d, err: %s)",
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

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_CHAIN_EXISTS_ARGS,
        fwc.fw_command,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].to_chain
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "chain_exists() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    if(EXTCMD_IS_SUCCESS(res))
        log_msg(LOG_DEBUG, "'%s' table '%s' chain exists",
            fwc.chain[chain_num].table,
            fwc.chain[chain_num].to_chain);
    else
        log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);

    return res;
}

static int
jump_rule_exists_chk_support(const fko_srv_options_t * const opts, const int chain_num)
{
    int    exists = 0;
    char   rule_buf[CMD_BUFSIZE] = {0};

    snprintf(rule_buf, CMD_BUFSIZE-1, FIREWD_CHK_JUMP_RULE_ARGS,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].to_chain
    );

    if(rule_exists_chk_support(opts, fwc.chain[chain_num].from_chain, rule_buf) == 1)
    {
        log_msg(LOG_DEBUG, "jump_rule_exists_chk_support() jump rule found");
        exists = 1;
    }
    else
        log_msg(LOG_DEBUG, "jump_rule_exists_chk_support() jump rule not found");

    return exists;
}

static int
jump_rule_exists_no_chk_support(const fko_srv_options_t * const opts, const int chain_num)
{
    int     exists = 0;
    char    cmd_buf[CMD_BUFSIZE]      = {0};
    char    chain_search[CMD_BUFSIZE] = {0};

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_LIST_RULES_ARGS,
        fwc.fw_command,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].from_chain
    );

    /* include spaces on either side as produced by 'firewalld -L' output
    */
    snprintf(chain_search, CMD_BUFSIZE-1, " %s ",
        fwc.chain[chain_num].to_chain);

    if(search_extcmd(cmd_buf, WANT_STDERR,
                NO_TIMEOUT, chain_search, &pid_status, opts) > 0)
        exists = 1;

    if(exists)
        log_msg(LOG_DEBUG, "jump_rule_exists_no_chk_support() jump rule found");
    else
        log_msg(LOG_DEBUG, "jump_rule_exists_no_chk_support() jump rule not found");

   return(exists);
}

static int
jump_rule_exists(const fko_srv_options_t * const opts, const int chain_num)
{
    int    exists = 0;

    if(have_firewd_chk_support == 1)
        exists = jump_rule_exists_chk_support(opts, chain_num);
    else
        exists = jump_rule_exists_no_chk_support(opts, chain_num);

    return exists;
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
        fprintf(stdout, "Listing all firewalld rules in applicable tables...\n");
        fflush(stdout);

        for(i=0; i<(NUM_FWKNOP_ACCESS_TYPES); i++)
        {

            if(fwc.chain[i].target[0] == '\0')
                continue;

            zero_cmd_buffers();

            /* Create the list command
            */
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_LIST_ALL_RULES_ARGS,
                opts->fw_config->fw_command,
                ch[i].table
            );

            res = run_extcmd(cmd_buf, NULL, 0, NO_STDERR,
                        NO_TIMEOUT, &pid_status, opts);

            log_msg(LOG_DEBUG, "fw_dump_rules() CMD: '%s' (res: %d)",
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
        fprintf(stdout, "Listing rules in fwknopd firewalld chains...\n");
        fflush(stdout);

        for(i=0; i<(NUM_FWKNOP_ACCESS_TYPES); i++)
        {

            if(fwc.chain[i].target[0] == '\0')
                continue;

            zero_cmd_buffers();

            /* Create the list command
            */
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_LIST_RULES_ARGS,
                opts->fw_config->fw_command,
                ch[i].table,
                ch[i].to_chain
            );

            fprintf(stdout, "\n");
            fflush(stdout);

            res = run_extcmd(cmd_buf, NULL, 0, NO_STDERR,
                        NO_TIMEOUT, &pid_status, opts);

            log_msg(LOG_DEBUG, "fw_dump_rules() CMD: '%s' (res: %d)",
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
    int     i, res, cmd_ctr = 0;

    for(i=0; i<(NUM_FWKNOP_ACCESS_TYPES); i++)
    {
        if(fwc.chain[i].target[0] == '\0')
            continue;

        /* First look for a jump rule to this chain and remove it if it
         * is there.
        */
        cmd_ctr = 0;
        while(cmd_ctr < CMD_LOOP_TRIES && (jump_rule_exists(opts, i) == 1))
        {
            zero_cmd_buffers();

            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_DEL_JUMP_RULE_ARGS,
                fwc.fw_command,
                fwc.chain[i].table,
                fwc.chain[i].from_chain,
                fwc.chain[i].to_chain
            );

            res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
                    WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
            chop_newline(err_buf);

            log_msg(LOG_DEBUG, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

            /* Expect full success on this */
            if(! EXTCMD_IS_SUCCESS(res))
                log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);

            cmd_ctr++;
        }

        zero_cmd_buffers();

        /* Now flush and remove the chain.
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_FLUSH_CHAIN_ARGS,
            fwc.fw_command,
            fwc.chain[i].table,
            fwc.chain[i].to_chain
        );

        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);
        chop_newline(err_buf);

        log_msg(LOG_DEBUG, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
            cmd_buf, res, err_buf);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);

        zero_cmd_buffers();

        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_DEL_CHAIN_ARGS,
            fwc.fw_command,
            fwc.chain[i].table,
            fwc.chain[i].to_chain
        );

        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);
        chop_newline(err_buf);

        log_msg(LOG_DEBUG, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
            cmd_buf, res, err_buf);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);

    }
    return;
}

static int
create_chain(const fko_srv_options_t * const opts, const int chain_num)
{
    int res = 0;

    zero_cmd_buffers();

    /* Create the custom chain.
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_NEW_CHAIN_ARGS,
        fwc.fw_command,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].to_chain
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "create_chain() CMD: '%s' (res: %d, err: %s)",
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

static int
set_fw_chain_conf(const int type, const char * const conf_str)
{
    int i, j, is_err;
    char tbuf[MAX_LINE_LEN]  = {0};
    const char *ndx          = conf_str;

    char *chain_fields[FW_NUM_CHAIN_FIELDS];

    struct fw_chain *chain = &(fwc.chain[type]);

    if(conf_str == NULL)
    {
        log_msg(LOG_ERR, "[*] NULL conf_str");
        return 0;
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
        if(*ndx != '\0'
                && *ndx != ' '
                && *ndx != ','
                && *ndx != '_'
                && isalnum(*ndx) == 0)
        {
            log_msg(LOG_ERR, "[*] Custom chain config parse error: "
                "invalid character '%c' for chain type %i, "
                "line: %s", *ndx, type, conf_str);
            return 0;
        }
        ndx++;
    }

    /* Sanity check - j should be the number of chain fields
     * (excluding the type).
    */
    if(j != FW_NUM_CHAIN_FIELDS)
    {
        log_msg(LOG_ERR, "[*] Custom chain config parse error: "
            "wrong number of fields for chain type %i, "
            "line: %s", type, conf_str);
        return 0;
    }

    /* Pull and set Target */
    strlcpy(chain->target, chain_fields[0], sizeof(chain->target));

    /* Pull and set Table */
    strlcpy(chain->table, chain_fields[1], sizeof(chain->table));

    /* Pull and set From_chain */
    strlcpy(chain->from_chain, chain_fields[2], sizeof(chain->from_chain));

    /* Pull and set Jump_rule_position */
    chain->jump_rule_pos = strtol_wrapper(chain_fields[3],
            0, RCHK_MAX_FIREWD_RULE_NUM, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] invalid jump rule position in Line: %s",
            conf_str);
        return 0;
    }

    /* Pull and set To_chain */
    strlcpy(chain->to_chain, chain_fields[4], sizeof(chain->to_chain));

    /* Pull and set to_chain rule position */
    chain->rule_pos = strtol_wrapper(chain_fields[5],
            0, RCHK_MAX_FIREWD_RULE_NUM, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] invalid to_chain rule position in Line: %s",
            conf_str);
        return 0;
    }
    return 1;
}

int
fw_config_init(fko_srv_options_t * const opts)
{

    memset(&fwc, 0x0, sizeof(struct fw_config));

    /* Set our firewall exe command path (firewall-cmd or iptables in most cases).
    */
#if FIREWALL_FIREWALLD
    char cmd_passthru[512];
    snprintf(cmd_passthru, sizeof cmd_passthru, "%s %s ",
        opts->config[CONF_FIREWALL_EXE], " --direct --passthrough ipv4 ");
    strlcpy(fwc.fw_command, cmd_passthru, sizeof(fwc.fw_command));
#else
    strlcpy(fwc.fw_command, opts->config[CONF_FIREWALL_EXE], sizeof(fwc.fw_command));
#endif

#if HAVE_LIBFIU
    fiu_return_on("fw_config_init", 0);
#endif

    /* Pull the fwknop chain config info and setup our internal
     * config struct.  The FIREWD_INPUT is the only one that is
     * required. The rest are optional.
    */
    if(set_fw_chain_conf(FIREWD_INPUT_ACCESS, opts->config[CONF_FIREWD_INPUT_ACCESS]) != 1)
        return 0;

    /* The FWKNOP_OUTPUT_ACCESS requires ENABLE_FIREWD_OUTPUT_ACCESS be Y
    */
    if(strncasecmp(opts->config[CONF_ENABLE_FIREWD_OUTPUT], "Y", 1)==0)
        if(set_fw_chain_conf(FIREWD_OUTPUT_ACCESS, opts->config[CONF_FIREWD_OUTPUT_ACCESS]) != 1)
            return 0;

    /* The remaining access chains require ENABLE_FIREWD_FORWARDING = Y
    */
    if(strncasecmp(opts->config[CONF_ENABLE_FIREWD_FORWARDING], "Y", 1)==0)
    {
        if(set_fw_chain_conf(FIREWD_FORWARD_ACCESS, opts->config[CONF_FIREWD_FORWARD_ACCESS]) != 1)
            return 0;

        if(set_fw_chain_conf(FIREWD_DNAT_ACCESS, opts->config[CONF_FIREWD_DNAT_ACCESS]) != 1)
            return 0;

        /* SNAT (whichever mode) requires ENABLE_FIREWD_SNAT = Y
        */
        if(strncasecmp(opts->config[CONF_ENABLE_FIREWD_SNAT], "Y", 1)==0)
        {
            if(opts->config[CONF_SNAT_TRANSLATE_IP] == NULL
                    || ! is_valid_ipv4_addr(opts->config[CONF_SNAT_TRANSLATE_IP]))
            {
                fwc.use_masquerade = 1;
                if(set_fw_chain_conf(FIREWD_MASQUERADE_ACCESS, opts->config[CONF_FIREWD_MASQUERADE_ACCESS]) != 1)
                    return 0;
            }
            else
            {
                if(is_valid_ipv4_addr(opts->config[CONF_SNAT_TRANSLATE_IP]))
                {
                    if(set_fw_chain_conf(FIREWD_SNAT_ACCESS, opts->config[CONF_FIREWD_SNAT_ACCESS]) != 1)
                        return 0;
                }
                else
                {
                    return 0;
                }
            }
        }
    }
    
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
    int res = 1;

    /* Flush the chains (just in case) so we can start fresh.
    */
    if(strncasecmp(opts->config[CONF_FLUSH_FIREWD_AT_INIT], "Y", 1) == 0)
        delete_all_chains(opts);

    /* Now create any configured chains.
    */
    if(create_fw_chains(opts) != 0)
    {
        log_msg(LOG_WARNING,
                "Warning: Errors detected during fwknop custom chain creation");
        res = 0;
    }

    /* Make sure that the 'comment' match is available
    */
    if(strncasecmp(opts->config[CONF_ENABLE_FIREWD_COMMENT_CHECK], "Y", 1) == 0)
    {
        if(comment_match_exists(opts) == 1)
        {
            log_msg(LOG_INFO, "firewalld 'comment' match is available");
        }
        else
        {
            log_msg(LOG_WARNING, "Warning: Could not use the 'comment' match");
            res = 0;
        }
    }

    /* See if firewalld offers the '-C' argument (older versions don't).  If not,
     * then switch to parsing firewalld -L output to find rules.
    */
    if(opts->firewd_disable_check_support)
        have_firewd_chk_support = 0;
    else
        firewd_chk_support(opts);

    return(res);
}

int
fw_cleanup(const fko_srv_options_t * const opts)
{
    if(strncasecmp(opts->config[CONF_FLUSH_FIREWD_AT_EXIT], "N", 1) == 0
            && opts->fw_flush == 0)
        return(0);

    delete_all_chains(opts);
    return(0);
}

static int
create_rule(const fko_srv_options_t * const opts,
        const char * const fw_chain, const char * const fw_rule)
{
    int res = 0;

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s -A %s %s", opts->fw_config->fw_command, fw_chain, fw_rule);

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "create_rule() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    if(EXTCMD_IS_SUCCESS(res))
    {
        log_msg(LOG_DEBUG, "create_rule() Rule: '%s' added to %s", fw_rule, fw_chain);
        res = 1;
    }
    else
        log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);

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
    char             rule_buf[CMD_BUFSIZE] = {0};
    char            *ndx;

    unsigned int     nat_port = 0;

    acc_port_list_t *port_list = NULL;
    acc_port_list_t *ple = NULL;

    unsigned int    fst_proto;
    unsigned int    fst_port;

    struct fw_chain * const in_chain   = &(opts->fw_config->chain[FIREWD_INPUT_ACCESS]);
    struct fw_chain * const out_chain  = &(opts->fw_config->chain[FIREWD_OUTPUT_ACCESS]);
    struct fw_chain * const fwd_chain  = &(opts->fw_config->chain[FIREWD_FORWARD_ACCESS]);
    struct fw_chain * const dnat_chain = &(opts->fw_config->chain[FIREWD_DNAT_ACCESS]);
    struct fw_chain *snat_chain; /* We assign this later (if we need to). */

    int             res = 0, is_err, snat_chain_num = 0;
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
        if(chain_exists(opts, FIREWD_INPUT_ACCESS) == 0)
            create_chain(opts, FIREWD_INPUT_ACCESS);

        if(jump_rule_exists(opts, FIREWD_INPUT_ACCESS) == 0)
            add_jump_rule(opts, FIREWD_INPUT_ACCESS);

        if(strlen(out_chain->to_chain))
        {
            if(chain_exists(opts, FIREWD_OUTPUT_ACCESS) == 0)
                create_chain(opts, FIREWD_OUTPUT_ACCESS);

            if(jump_rule_exists(opts, FIREWD_OUTPUT_ACCESS) == 0)
                add_jump_rule(opts, FIREWD_OUTPUT_ACCESS);
        }

        /* Create an access command for each proto/port for the source ip.
        */
        while(ple != NULL)
        {
            memset(rule_buf, 0, CMD_BUFSIZE);

            snprintf(rule_buf, CMD_BUFSIZE-1, FIREWD_RULE_ARGS,
                in_chain->table,
                ple->proto,
                spadat->use_src_ip,
                (fwc.use_destination ? spadat->pkt_destination_ip : FIREWD_ANY_IP)
                ple->port,
                exp_ts,
                in_chain->target
            );

            if(rule_exists(opts, in_chain, rule_buf,
                        ple->proto, spadat->use_src_ip, spadat->pkt_destination_ip, ple->port, exp_ts) == 0)
            {
                if(create_rule(opts, in_chain->to_chain, rule_buf))
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

                snprintf(rule_buf, CMD_BUFSIZE-1, FIREWD_OUT_RULE_ARGS,
                    out_chain->table,
                    ple->proto,
                    spadat->use_src_ip,
                    (fwc.use_destination ? spadat->pkt_destination_ip : FIREWD_ANY_IP),
                    ple->port,
                    exp_ts,
                    out_chain->target
                );

                if(rule_exists(opts, out_chain, rule_buf,
                        ple->proto, spadat->use_src_ip, spadat->pkt_destination_ip, ple->port, exp_ts) == 0)
                {
                    if(create_rule(opts, out_chain->to_chain, rule_buf))
                    {
                        log_msg(LOG_INFO, "Added Rule in %s for %s, %s expires at %u",
                            out_chain->to_chain, spadat->use_src_ip,
                            spadat->spa_message_remain, exp_ts
                        );

                        out_chain->active_rules++;

                        /* Reset the next expected expire time for this chain if it
                        * is warranted.  */
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
                if (! is_valid_ipv4_addr(nat_ip))
                {
                    log_msg(LOG_INFO, "Invalid NAT IP in SPA message");
                    free_acc_port_list(port_list);
                    return res;
                }

                nat_port = strtol_wrapper(ndx+1, 0, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
                if(is_err != FKO_SUCCESS)
                {
                    log_msg(LOG_INFO, "Invalid NAT port in SPA message");
                    free_acc_port_list(port_list);
                    res = is_err;
                    return res;
                }
            }
        }

        if(spadat->message_type == FKO_LOCAL_NAT_ACCESS_MSG)
        {
            memset(rule_buf, 0, CMD_BUFSIZE);

            snprintf(rule_buf, CMD_BUFSIZE-1, FIREWD_RULE_ARGS,
                in_chain->table,
                fst_proto,
                spadat->use_src_ip,
                (fwc.use_destination ? spadat->pkt_destination_ip : FIREWD_ANY_IP),
                nat_port,
                exp_ts,
                in_chain->target
            );

            /* Check to make sure that the jump rules exist for each
             * required chain
            */
            if(chain_exists(opts, FIREWD_INPUT_ACCESS) == 0)
                create_chain(opts, FIREWD_INPUT_ACCESS);

            if(jump_rule_exists(opts, FIREWD_INPUT_ACCESS) == 0)
                add_jump_rule(opts, FIREWD_INPUT_ACCESS);

            if(rule_exists(opts, in_chain, rule_buf,
                        fst_proto, spadat->use_src_ip, spadat->pkt_destination_ip, nat_port, exp_ts) == 0)
            {
                if(create_rule(opts, in_chain->to_chain, rule_buf))
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
            if(chain_exists(opts, FIREWD_FORWARD_ACCESS) == 0)
                create_chain(opts, FIREWD_FORWARD_ACCESS);

            if (jump_rule_exists(opts, FIREWD_FORWARD_ACCESS) == 0)
                add_jump_rule(opts, FIREWD_FORWARD_ACCESS);

            memset(rule_buf, 0, CMD_BUFSIZE);

            snprintf(rule_buf, CMD_BUFSIZE-1, FIREWD_FWD_RULE_ARGS,
                fwd_chain->table,
                fst_proto,
                spadat->use_src_ip,
                nat_ip,
                nat_port,
                exp_ts,
                fwd_chain->target
            );

            if(rule_exists(opts, fwd_chain, rule_buf, fst_proto,
                    spadat->use_src_ip, nat_ip, nat_port, exp_ts) == 0)
            {
                if(create_rule(opts, fwd_chain->to_chain, rule_buf))
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
            /* Make sure the required chain and jump rule exist
            */
            if(chain_exists(opts, FIREWD_DNAT_ACCESS) == 0)
                create_chain(opts, FIREWD_DNAT_ACCESS);

            if (jump_rule_exists(opts, FIREWD_DNAT_ACCESS) == 0)
                add_jump_rule(opts, FIREWD_DNAT_ACCESS);

            memset(rule_buf, 0, CMD_BUFSIZE);

            snprintf(rule_buf, CMD_BUFSIZE-1, FIREWD_DNAT_RULE_ARGS,
                dnat_chain->table,
                fst_proto,
                spadat->use_src_ip,
                (fwc.use_destination ? spadat->pkt_destination_ip : FIREWD_ANY_IP),
                fst_port,
                exp_ts,
                dnat_chain->target,
                nat_ip,
                nat_port
            );

            if(rule_exists(opts, dnat_chain, rule_buf, fst_proto,
                        spadat->use_src_ip, spadat->pkt_destination_ip, fst_port, exp_ts) == 0)
            {
                if(create_rule(opts, dnat_chain->to_chain, rule_buf))
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
        if(acc->force_snat || strncasecmp(opts->config[CONF_ENABLE_FIREWD_SNAT], "Y", 1) == 0)
        {
            /* Add SNAT or MASQUERADE rules.
            */
            if(acc->force_snat && is_valid_ipv4_addr(acc->force_snat_ip))
            {
                /* Using static SNAT */
                snat_chain = &(opts->fw_config->chain[FIREWD_SNAT_ACCESS]);
                snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                    "--to-source %s:%i", acc->force_snat_ip, fst_port);
                snat_chain_num = FIREWD_SNAT_ACCESS;
            }
            else if(acc->force_snat && acc->force_masquerade)
            {
                /* Using MASQUERADE */
                snat_chain = &(opts->fw_config->chain[FIREWD_MASQUERADE_ACCESS]);
                snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                    "--to-ports %i", fst_port);
                snat_chain_num = FIREWD_MASQUERADE_ACCESS;
            }
            else if((opts->config[CONF_SNAT_TRANSLATE_IP] != NULL)
                && is_valid_ipv4_addr(opts->config[CONF_SNAT_TRANSLATE_IP]))
            {
                /* Using static SNAT */
                snat_chain = &(opts->fw_config->chain[FIREWD_SNAT_ACCESS]);
                snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                    "--to-source %s:%i", opts->config[CONF_SNAT_TRANSLATE_IP],
                    fst_port);
                snat_chain_num = FIREWD_SNAT_ACCESS;
            }
            else
            {
                /* Using MASQUERADE */
                snat_chain = &(opts->fw_config->chain[FIREWD_MASQUERADE_ACCESS]);
                snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                    "--to-ports %i", fst_port);
                snat_chain_num = FIREWD_MASQUERADE_ACCESS;
            }

            if(chain_exists(opts, snat_chain_num) == 0)
                create_chain(opts, snat_chain_num);

            if(jump_rule_exists(opts, snat_chain_num) == 0)
                add_jump_rule(opts, snat_chain_num);

            memset(rule_buf, 0, CMD_BUFSIZE);

            snprintf(rule_buf, CMD_BUFSIZE-1, FIREWD_SNAT_RULE_ARGS,
                snat_chain->table,
                fst_proto,
                nat_ip,
                nat_port,
                exp_ts,
                snat_chain->target,
                snat_target
            );

            if(rule_exists(opts, snat_chain, rule_buf, fst_proto,
                        spadat->use_src_ip, NULL, nat_port, exp_ts) == 0)
            {
                if(create_rule(opts, snat_chain->to_chain, rule_buf))
                {
                    log_msg(LOG_INFO, "Added SNAT Rule to %s for %s, %s expires at %u",
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
    char             exp_str[12]     = {0};
    char             rule_num_str[6] = {0};
    char            *ndx, *rn_start, *rn_end, *tmp_mark;

    int             i, res, rn_offset, rule_num, is_err;
    time_t          now, rule_exp, min_exp = 0;

    struct fw_chain *ch = opts->fw_config->chain;

    time(&now);

    /* Iterate over each chain and look for active rules to delete.
    */
    for(i=0; i < NUM_FWKNOP_ACCESS_TYPES; i++)
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
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_LIST_RULES_ARGS,
            opts->fw_config->fw_command,
            ch[i].table,
            ch[i].to_chain
        );

        res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE,
                WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
        chop_newline(cmd_out);

        log_msg(LOG_DEBUG, "check_firewall_rules() CMD: '%s' (res: %d, cmd_out: %s)",
            cmd_buf, res, cmd_out);

        if(!EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, cmd_out);
            continue;
        }

        log_msg(LOG_DEBUG, "RES=%i, CMD_BUF: %s\nRULES LIST: %s", res, cmd_buf, cmd_out);

        ndx = strstr(cmd_out, EXPIRE_COMMENT_PREFIX);
        if(ndx == NULL)
        {
            /* we did not find an expected rule.
            */
            log_msg(LOG_ERR,
                "Did not find expire comment in rules list %i", i);

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

                rule_num = strtol_wrapper(rule_num_str, rn_offset, RCHK_MAX_FIREWD_RULE_NUM,
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

                snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " FIREWD_DEL_RULE_ARGS,
                    opts->fw_config->fw_command,
                    ch[i].table,
                    ch[i].to_chain,
                    rule_num - rn_offset
                );

                res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
                        WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
                chop_newline(err_buf);

                log_msg(LOG_DEBUG, "check_firewall_rules() CMD: '%s' (res: %d, err: %s)",
                    cmd_buf, res, err_buf);

                if(EXTCMD_IS_SUCCESS(res))
                {
                    log_msg(LOG_INFO, "Removed rule %s from %s with expire time of %u",
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

int
validate_firewd_chain_conf(const char * const chain_str)
{
    int         j, rv  = 1;
    const char   *ndx  = chain_str;

    j = 1;
    while(*ndx != '\0')
    {
        if(*ndx == ',')
            j++;

        if(*ndx != '\0'
                && *ndx != ' '
                && *ndx != ','
                && *ndx != '_'
                && isalnum(*ndx) == 0)
        {
            rv = 0;
            break;
        }
        ndx++;
    }

    /* Sanity check - j should be the number of chain fields
     * (excluding the type).
    */
    if(j != FW_NUM_CHAIN_FIELDS)
        rv = 0;

    return rv;
}

#endif /* FIREWALL_FIREWALLD */

/***EOF***/
