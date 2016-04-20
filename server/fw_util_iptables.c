/**
 * \file server/fw_util_iptables.c
 *
 * \brief Fwknop routines for managing iptables firewall rules.
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

/* assume 'iptables -C' is offered since only older versions
 * don't have this (see ipt_chk_support()).
*/
static int have_ipt_chk_support = 1;

static void
zero_cmd_buffers(void)
{
    memset(cmd_buf, 0x0, CMD_BUFSIZE);
    memset(err_buf, 0x0, CMD_BUFSIZE);
    memset(cmd_out, 0x0, STANDARD_CMD_OUT_BUFSIZE);
}

static int pid_status = 0;

static int
rule_exists_no_chk_support(const fko_srv_options_t * const opts,
        const struct fw_chain * const fwc,
        const unsigned int proto,
        const char * const srcip,
        const char * const dstip,
        const unsigned int port,
        const char * const natip,
        const unsigned int nat_port,
        const unsigned int exp_ts)
{
    int     rule_exists=0;
    char    ipt_line_buf[CMD_BUFSIZE]    = {0};
    char    target_search[CMD_BUFSIZE]   = {0};
    char    proto_search[CMD_BUFSIZE]    = {0};
    char    srcip_search[CMD_BUFSIZE]    = {0};
    char    dstip_search[CMD_BUFSIZE]    = {0};
    char    natip_search[CMD_BUFSIZE]    = {0};
    char    port_search[CMD_BUFSIZE]     = {0};
    char    nat_port_search[CMD_BUFSIZE] = {0};
    char    exp_ts_search[CMD_BUFSIZE]   = {0};
    char    *ndx = NULL;

#if CODE_COVERAGE
    /* If we're maximizing code coverage, then exercise the run_extcmd_write()
     * function which is normally only used for the PF firewall. This is to
     * maximize code coverage in conjunction with the test suite, and is never
     * compiled in for a production release of fwknop.
    */
    if(run_extcmd_write("/bin/grep -v test", "/bin/echo test", &pid_status, opts) == 0)
        log_msg(LOG_WARNING, "[ignore] Code coverage: Executed command");
#endif

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_LIST_RULES_ARGS,
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

    snprintf(port_search, CMD_BUFSIZE-1, "dpt:%u ", port);
    snprintf(nat_port_search, CMD_BUFSIZE-1, ":%u", nat_port);
    snprintf(target_search, CMD_BUFSIZE-1, " %s ", fwc->target);

    if (srcip != NULL)
        snprintf(srcip_search, CMD_BUFSIZE-1, " %s ", srcip);

    if (dstip != NULL)
        snprintf(dstip_search, CMD_BUFSIZE-1, " %s ", dstip);

    if (natip != NULL)
        snprintf(dstip_search, CMD_BUFSIZE-1, " to:%s", natip);

    snprintf(exp_ts_search, CMD_BUFSIZE-1, "%u ", exp_ts);

    /* search for each of the substrings - the rule expiration time is the
     * primary search method
    */
    if(search_extcmd_getline(cmd_buf, ipt_line_buf,
                CMD_BUFSIZE, NO_TIMEOUT, exp_ts_search, &pid_status, opts))
    {
        chop_newline(ipt_line_buf);
        /* we have an iptables policy rule that matches the
         * expiration time, so make sure this rule matches the
         * other fields too. If not, then it is for different
         * access requested by a separate SPA packet.
        */
        if(((proto == ANY_PROTO) ? 1 : (strstr(ipt_line_buf, proto_search) != NULL))
            && ((srcip == NULL) ? 1 : (strstr(ipt_line_buf, srcip_search) != NULL))
            && ((dstip == NULL) ? 1 : (strstr(ipt_line_buf, dstip_search) != NULL))
            && ((natip == NULL) ? 1 : (strstr(ipt_line_buf, natip_search) != NULL))
            && (strstr(ipt_line_buf, target_search) != NULL)
            && ((port == ANY_PORT) ? 1 : (strstr(ipt_line_buf, port_search) != NULL)))
        {
            rule_exists = 1;
        }
    }

    /* If there is a nat port, we have to qualify it as part
     * of the 'to:<ip>:<port>' portion of the rule (at the end)
    */
    if(rule_exists && nat_port != NAT_ANY_PORT)
    {
        ndx = strstr(ipt_line_buf, " to:");
        /* Make sure there isn't a duplicate " to:" string (i.e. if someone
         * was trying to be tricky with the iptables comment match).
        */
        if(ndx != NULL && (strstr((ndx+strlen(" to:")), " to:") == NULL))
        {
            ndx = strstr((ndx+strlen(" to:")), nat_port_search);
            if (ndx == NULL)
            {
                rule_exists = 0;
            }
            else if((*(ndx+strlen(nat_port_search)) != '\0')
                    && (*(ndx+strlen(nat_port_search)) != ' '))
            {
                rule_exists = 0;
            }
        }
        else
        {
            rule_exists = 0;
        }
    }

    if(rule_exists)
        log_msg(LOG_DEBUG,
                "rule_exists_no_chk_support() %s %u -> %s expires: %u rule already exists",
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

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_CHK_RULE_ARGS,
            opts->fw_config->fw_command, chain, rule);

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG,
            "rule_exists_chk_support() CMD: '%s' (res: %d, err: %s)",
            cmd_buf, res, err_buf);

    if(EXTCMD_IS_SUCCESS(res) && strlen(err_buf))
    {
        log_msg(LOG_DEBUG,
                "rule_exists_chk_support() Rule : '%s' in %s does not exist",
                rule, chain);
    }
    else
    {
        rule_exists = 1;
        log_msg(LOG_DEBUG,
                "rule_exists_chk_support() Rule : '%s' in %s already exists",
                rule, chain);
    }

    return(rule_exists);
}

static int
rule_exists(const fko_srv_options_t * const opts,
        const struct fw_chain * const fwc,
        const char * const rule,
        const unsigned int proto,
        const char * const srcip,
        const char * const dstip,
        const unsigned int port,
        const char * const nat_ip,
        const unsigned int nat_port,
        const unsigned int exp_ts)
{
    int rule_exists = 0;

    if(have_ipt_chk_support == 1)
        rule_exists = rule_exists_chk_support(opts, fwc->to_chain, rule);
    else
        rule_exists = rule_exists_no_chk_support(opts, fwc, proto, srcip,
                (opts->fw_config->use_destination ? dstip : NULL), port,
                nat_ip, nat_port, exp_ts);

    if(rule_exists == 1)
        log_msg(LOG_DEBUG, "rule_exists() Rule : '%s' in %s already exists",
                rule, fwc->to_chain);
    else
        log_msg(LOG_DEBUG, "rule_exists() Rule : '%s' in %s does not exist",
                rule, fwc->to_chain);

    return(rule_exists);
}

static void
ipt_chk_support(const fko_srv_options_t * const opts)
{
    int               res = 1;
    struct fw_chain  *in_chain = &(opts->fw_config->chain[IPT_INPUT_ACCESS]);

    zero_cmd_buffers();

    /* Add a harmless rule to the iptables INPUT chain and see if iptables
     * supports '-C' to check for it.  Set "have_ipt_chk_support" accordingly,
     * delete the rule, and return.
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_TMP_CHK_RULE_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->from_chain,
        1,   /* first rule */
        in_chain->target
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "ipt_chk_support() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    zero_cmd_buffers();

    /* Now see if '-C' works - any output indicates failure
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_TMP_VERIFY_CHK_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->from_chain,
        in_chain->target
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "ipt_chk_support() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    if(EXTCMD_IS_SUCCESS(res) && strlen(err_buf))
    {
        log_msg(LOG_DEBUG, "ipt_chk_support() -C not supported");
        have_ipt_chk_support = 0;
    }
    else
    {
        log_msg(LOG_DEBUG, "ipt_chk_support() -C supported");
        have_ipt_chk_support = 1;
    }

    /* Delete the tmp rule
    */
    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_DEL_RULE_ARGS,
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
    struct fw_chain  *in_chain  = &(opts->fw_config->chain[IPT_INPUT_ACCESS]);

    zero_cmd_buffers();

    /* Add a harmless rule to the iptables INPUT chain that uses the comment
     * match and make sure it exists.  If not, return zero.  Otherwise, delete
     * the rule and return true.
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_TMP_COMMENT_ARGS,
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

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_LIST_RULES_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->from_chain
    );

    res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(cmd_out);

    if(!EXTCMD_IS_SUCCESS(res))
        log_msg(LOG_ERR, "comment_match_exists() Error %i from cmd:'%s': %s",
                res, cmd_buf, cmd_out);

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
    int res = 0, rv = 0;

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_ADD_JUMP_RULE_ARGS,
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
    {
        log_msg(LOG_INFO, "Added jump rule from chain: %s to chain: %s",
            fwc.chain[chain_num].from_chain,
            fwc.chain[chain_num].to_chain);
        rv = 1;
    }
    else
        log_msg(LOG_ERR, "add_jump_rule() Error %i from cmd:'%s': %s",
                res, cmd_buf, err_buf);

    return rv;
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
        log_msg(LOG_ERR, "chain_exists() Error %i from cmd:'%s': %s",
                res, cmd_buf, err_buf);

    return res;
}

static int
jump_rule_exists_chk_support(const fko_srv_options_t * const opts, const int chain_num)
{
    int    exists = 0;
    char   rule_buf[CMD_BUFSIZE] = {0};

    snprintf(rule_buf, CMD_BUFSIZE-1, IPT_CHK_JUMP_RULE_ARGS,
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
jump_rule_exists_no_chk_support(const fko_srv_options_t * const opts,
        const int chain_num)
{
    int     exists = 0;
    char    chain_search[CMD_BUFSIZE] = {0};

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_LIST_RULES_ARGS,
        fwc.fw_command,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].from_chain
    );

    /* include spaces on either side as produced by 'iptables -L' output
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

    if(have_ipt_chk_support == 1)
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
    int     i, res, got_err = 0;

    struct fw_chain *ch = opts->fw_config->chain;

    if (opts->fw_list_all == 1)
    {
        fprintf(stdout, "Listing all iptables rules in applicable tables...\n");
        fflush(stdout);

        for(i=0; i < NUM_FWKNOP_ACCESS_TYPES; i++)
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

            res = run_extcmd(cmd_buf, NULL, 0, NO_STDERR,
                        NO_TIMEOUT, &pid_status, opts);

            log_msg(LOG_DEBUG, "fw_dump_rules() CMD: '%s' (res: %d)",
                cmd_buf, res);

            /* Expect full success on this */
            if(! EXTCMD_IS_SUCCESS(res))
            {
                log_msg(LOG_ERR, "fw_dump_rules() Error %i from cmd:'%s': %s",
                        res, cmd_buf, err_buf);
                got_err++;
            }
        }
    }
    else
    {
        fprintf(stdout, "Listing rules in fwknopd iptables chains...\n");
        fflush(stdout);

        for(i=0; i < NUM_FWKNOP_ACCESS_TYPES; i++)
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

            res = run_extcmd(cmd_buf, NULL, 0, NO_STDERR,
                        NO_TIMEOUT, &pid_status, opts);

            log_msg(LOG_DEBUG, "fw_dump_rules() CMD: '%s' (res: %d)",
                cmd_buf, res);

            /* Expect full success on this */
            if(! EXTCMD_IS_SUCCESS(res))
            {
                log_msg(LOG_ERR, "fw_dump_rules() Error %i from cmd:'%s': %s",
                        res, cmd_buf, err_buf);
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

    for(i=0; i < NUM_FWKNOP_ACCESS_TYPES; i++)
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

            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_DEL_JUMP_RULE_ARGS,
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
                log_msg(LOG_ERR, "delete_all_chains() Error %i from cmd:'%s': %s",
                        res, cmd_buf, err_buf);

            cmd_ctr++;
        }

        zero_cmd_buffers();

        /* Now flush and remove the chain.
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_FLUSH_CHAIN_ARGS,
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
            log_msg(LOG_ERR, "delete_all_chains() Error %i from cmd:'%s': %s",
                    res, cmd_buf, err_buf);

        zero_cmd_buffers();

        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_DEL_CHAIN_ARGS,
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
            log_msg(LOG_ERR, "delete_all_chains() Error %i from cmd:'%s': %s",
                    res, cmd_buf, err_buf);
    }

#if USE_LIBNETFILTER_QUEUE
    if(opts->enable_nfq_capture)
    {
        zero_cmd_buffers();

        /* Delete the rule to direct traffic to the NFQ chain.
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_DEL_RULE_ARGS,
            fwc.fw_command,
            opts->config[CONF_NFQ_TABLE],
            "INPUT",
            1
        );
        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);

        if (opts->verbose)
            log_msg(LOG_INFO, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);

        zero_cmd_buffers();

        /* Flush the NFQ chain
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_FLUSH_CHAIN_ARGS,
            fwc.fw_command,
            opts->config[CONF_NFQ_TABLE],
            opts->config[CONF_NFQ_CHAIN]
        );
        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);

        if (opts->verbose)
            log_msg(LOG_INFO, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);

        zero_cmd_buffers();

        /* Delete the NF_QUEUE chains and rules
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_DEL_CHAIN_ARGS,
            fwc.fw_command,
            opts->config[CONF_NFQ_TABLE],
            opts->config[CONF_NFQ_CHAIN]
        );
        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);

        if (opts->verbose)
            log_msg(LOG_INFO, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);
    }
#endif
    return;
}

static int
create_chain(const fko_srv_options_t * const opts, const int chain_num)
{
    int res = 0, rv = 0;

    zero_cmd_buffers();

    /* Create the custom chain.
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_NEW_CHAIN_ARGS,
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
    if(EXTCMD_IS_SUCCESS(res))
        rv = 1;
    else
        log_msg(LOG_ERR, "create_chain() Error %i from cmd:'%s': %s",
                res, cmd_buf, err_buf);

    return rv;
}

static int
mk_chain(const fko_srv_options_t * const opts, const int chain_num)
{
    int err = 0;

    /* Make sure the required chain and jump rule exist
    */
    if(! chain_exists(opts, chain_num))
        if(! create_chain(opts, chain_num))
            err++;

    if (! jump_rule_exists(opts, chain_num))
        if(! add_jump_rule(opts, chain_num))
            err++;

    return err;
}

/* Create the fwknop custom chains (at least those that are configured).
*/
static int
create_fw_chains(const fko_srv_options_t * const opts)
{
    int     i, got_err = 0;
#if USE_LIBNETFILTER_QUEUE
    int     res = 0;
#endif

    for(i=0; i < NUM_FWKNOP_ACCESS_TYPES; i++)
    {
        if(fwc.chain[i].target[0] == '\0')
            continue;

        got_err += mk_chain(opts, i);
    }

#if USE_LIBNETFILTER_QUEUE
    if(opts->enable_nfq_capture)
    {
        zero_cmd_buffers();

        /* Create the NF_QUEUE chains and rules
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_NEW_CHAIN_ARGS,
            fwc.fw_command,
            opts->config[CONF_NFQ_TABLE],
            opts->config[CONF_NFQ_CHAIN]
        );
        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                         NO_TIMEOUT, &pid_status, opts);

        if (opts->verbose)
            log_msg(LOG_INFO, "create_fw_chains() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);
            got_err++;
        }

        zero_cmd_buffers();

        /* Create the rule to direct traffic to the NFQ chain.
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_ADD_JUMP_RULE_ARGS,
            fwc.fw_command,
            opts->config[CONF_NFQ_TABLE],
            "INPUT",
            1,
            opts->config[CONF_NFQ_CHAIN]
        );
        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                         NO_TIMEOUT, &pid_status, opts);

        if (opts->verbose)
            log_msg(LOG_INFO, "create_fw_chains() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);
            got_err++;
        }

        zero_cmd_buffers();

        /* Create the rule to direct SPA packets to the queue.
         * If an interface is specified use the "_WITH_IF" version
         * of the command.
        */
        if(strlen(opts->config[CONF_NFQ_INTERFACE]) > 0)
        {
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_NFQ_ADD_ARGS_WITH_IF,
                fwc.fw_command,
                opts->config[CONF_NFQ_TABLE],
                opts->config[CONF_NFQ_CHAIN],
                opts->config[CONF_NFQ_INTERFACE],
                opts->config[CONF_NFQ_PORT],
                opts->config[CONF_NFQ_QUEUE_NUMBER]
            );
        }
        else
        {
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_NFQ_ADD_ARGS,
                fwc.fw_command,
                opts->config[CONF_NFQ_TABLE],
                opts->config[CONF_NFQ_CHAIN],
                opts->config[CONF_NFQ_PORT],
                opts->config[CONF_NFQ_QUEUE_NUMBER]
            );
        }

        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);

        if (opts->verbose)
            log_msg(LOG_INFO, "create_fw_chains() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);
            got_err++;
        }
    }
#endif
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
            0, RCHK_MAX_IPT_RULE_NUM, NO_EXIT_UPON_ERR, &is_err);
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
            0, RCHK_MAX_IPT_RULE_NUM, NO_EXIT_UPON_ERR, &is_err);
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

    /* Set our firewall exe command path (iptables in most cases).
    */
    strlcpy(fwc.fw_command, opts->config[CONF_FIREWALL_EXE], sizeof(fwc.fw_command));

#if HAVE_LIBFIU
    fiu_return_on("fw_config_init", 0);
#endif

    /* Pull the fwknop chain config info and setup our internal
     * config struct.  The IPT_INPUT is the only one that is
     * required. The rest are optional.
    */
    if(set_fw_chain_conf(IPT_INPUT_ACCESS, opts->config[CONF_IPT_INPUT_ACCESS]) != 1)
        return 0;

    /* The FWKNOP_OUTPUT_ACCESS requires ENABLE_IPT_OUTPUT_ACCESS == Y
    */
    if(strncasecmp(opts->config[CONF_ENABLE_IPT_OUTPUT], "Y", 1)==0)
        if(set_fw_chain_conf(IPT_OUTPUT_ACCESS, opts->config[CONF_IPT_OUTPUT_ACCESS]) != 1)
            return 0;

    /* The remaining access chains require ENABLE_IPT_FORWARDING = Y
    */
    if(strncasecmp(opts->config[CONF_ENABLE_IPT_FORWARDING], "Y", 1)==0
            || strncasecmp(opts->config[CONF_ENABLE_IPT_LOCAL_NAT], "Y", 1)==0)

    {
        if(set_fw_chain_conf(IPT_FORWARD_ACCESS, opts->config[CONF_IPT_FORWARD_ACCESS]) != 1)
            return 0;

        if(set_fw_chain_conf(IPT_DNAT_ACCESS, opts->config[CONF_IPT_DNAT_ACCESS]) != 1)
            return 0;

        /* Requires ENABLE_IPT_SNAT = Y
        */
        if(strncasecmp(opts->config[CONF_ENABLE_IPT_SNAT], "Y", 1)==0)
        {
            /* Support both SNAT and MASQUERADE - this will be controlled
             * via the access.conf configuration for individual rules
            */
            if(set_fw_chain_conf(IPT_MASQUERADE_ACCESS,
                        opts->config[CONF_IPT_MASQUERADE_ACCESS]) != 1)
                return 0;

            if(set_fw_chain_conf(IPT_SNAT_ACCESS,
                        opts->config[CONF_IPT_SNAT_ACCESS]) != 1)
                return 0;
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

    /* See if iptables offers the '-C' argument (older versions don't).  If not,
     * then switch to parsing iptables -L output to find rules.
    */
    if(opts->ipt_disable_check_support)
        have_ipt_chk_support = 0;
    else
        ipt_chk_support(opts);

    /* Flush the chains (just in case) so we can start fresh.
    */
    if(strncasecmp(opts->config[CONF_FLUSH_IPT_AT_INIT], "Y", 1) == 0)
        delete_all_chains(opts);

    /* Now create any configured chains.
    */
    if(create_fw_chains(opts) != 0)
    {
        log_msg(LOG_WARNING,
                "fw_initialize() Warning: Errors detected during fwknop custom chain creation");
        res = 0;
    }

    /* Make sure that the 'comment' match is available
    */
    if(strncasecmp(opts->config[CONF_ENABLE_IPT_COMMENT_CHECK], "Y", 1) == 0)
    {
        if(comment_match_exists(opts) == 1)
        {
            log_msg(LOG_INFO, "iptables 'comment' match is available");
        }
        else
        {
            log_msg(LOG_WARNING, "Warning: Could not use the 'comment' match");
            res = 0;
        }
    }

    return(res);
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
create_rule(const fko_srv_options_t * const opts,
        const char * const fw_chain, const char * const fw_rule)
{
    int res = 0;

    zero_cmd_buffers();

    if (strncasecmp(opts->config[CONF_ENABLE_PREPEND], "Y", 1) == 0) {
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s -I %s %s",
                opts->fw_config->fw_command, fw_chain, fw_rule);
    } else {
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s -A %s %s",
                opts->fw_config->fw_command, fw_chain, fw_rule);
    }
    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "create_rule() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    if(EXTCMD_IS_SUCCESS(res))
    {
        log_msg(LOG_DEBUG, "create_rule() Rule: '%s' added to %s",
                fw_rule, fw_chain);
        res = 1;
    }
    else
        log_msg(LOG_ERR, "create_rule() Error %i from cmd:'%s': %s",
                res, cmd_buf, err_buf);

    return res;
}

static void
ipt_rule(const fko_srv_options_t * const opts,
        const char * const complete_rule_buf,
        const char * const fw_rule_macro,
        const char * const srcip,
        const char * const dstip,
        const unsigned int proto,
        const unsigned int port,
        const char * const nat_ip,
        const unsigned int nat_port,
        struct fw_chain * const chain,
        const unsigned int exp_ts,
        const time_t now,
        const char * const msg,
        const char * const access_msg)
{
    char rule_buf[CMD_BUFSIZE] = {0};

    if(complete_rule_buf != NULL && complete_rule_buf[0] != 0x0)
    {
        strlcpy(rule_buf, complete_rule_buf, CMD_BUFSIZE-1);
    }
    else
    {
        memset(rule_buf, 0, CMD_BUFSIZE);

        snprintf(rule_buf, CMD_BUFSIZE-1, fw_rule_macro,
            chain->table,
            proto,
            srcip,
            dstip,
            port,
            exp_ts,
            chain->target
        );
    }

    /* Check to make sure that the chain and jump rule exist
    */
    mk_chain(opts, chain->type);

    if(rule_exists(opts, chain, rule_buf, proto, srcip,
                dstip, port, nat_ip, nat_port, exp_ts) == 0)
    {
        if(create_rule(opts, chain->to_chain, rule_buf))
        {
            log_msg(LOG_INFO, "Added %s rule to %s for %s -> %s %s, expires at %u",
                msg, chain->to_chain, srcip, (dstip == NULL) ? IPT_ANY_IP : dstip,
                access_msg, exp_ts
            );

            chain->active_rules++;

            /* Reset the next expected expire time for this chain if it
            * is warranted.
            */
            if(chain->next_expire < now || exp_ts < chain->next_expire)
                chain->next_expire = exp_ts;
        }
    }

    return;
}

static void forward_access_rule(const fko_srv_options_t * const opts,
        const acc_stanza_t * const acc,
        struct fw_chain * const fwd_chain,
        const char * const nat_ip,
        const unsigned int nat_port,
        const unsigned int fst_proto,
        const unsigned int fst_port,
        spa_data_t * const spadat,
        const unsigned int exp_ts,
        const time_t now)
{
    char   rule_buf[CMD_BUFSIZE] = {0};

    log_msg(LOG_DEBUG,
            "forward_access_rule() forward_all: %d, nat_ip: %s, nat_port: %d",
            acc->forward_all, nat_ip, nat_port);

    if(acc->forward_all)
    {
        memset(rule_buf, 0, CMD_BUFSIZE);

        snprintf(rule_buf, CMD_BUFSIZE-1, IPT_FWD_ALL_RULE_ARGS,
            fwd_chain->table,
            spadat->use_src_ip,
            exp_ts,
            fwd_chain->target
        );

        /* Make a global ACCEPT rule for all ports/protocols
        */
        ipt_rule(opts, rule_buf, NULL, spadat->use_src_ip,
            NULL, ANY_PROTO, ANY_PORT, NULL, NAT_ANY_PORT,
            fwd_chain, exp_ts, now, "FORWARD ALL", "*/*");
    }
    else
    {
        /* Make the FORWARD access rule
        */
        ipt_rule(opts, NULL, IPT_FWD_RULE_ARGS, spadat->use_src_ip,
            nat_ip, fst_proto, nat_port, NULL, NAT_ANY_PORT,
            fwd_chain, exp_ts, now, "FORWARD", spadat->spa_message_remain);
    }
    return;
}

static void dnat_rule(const fko_srv_options_t * const opts,
        const acc_stanza_t * const acc,
        struct fw_chain * const dnat_chain,
        const char * const nat_ip,
        const unsigned int nat_port,
        const unsigned int fst_proto,
        const unsigned int fst_port,
        spa_data_t * const spadat,
        const unsigned int exp_ts,
        const time_t now)
{
    char   rule_buf[CMD_BUFSIZE] = {0};

    log_msg(LOG_DEBUG, "dnat_rule() forward_all: %d, nat_ip: %s, nat_port: %d",
            acc->forward_all, nat_ip, nat_port);

    if(acc->forward_all)
    {
        memset(rule_buf, 0, CMD_BUFSIZE);

        snprintf(rule_buf, CMD_BUFSIZE-1, IPT_DNAT_ALL_RULE_ARGS,
            dnat_chain->table,
            spadat->use_src_ip,
            (fwc.use_destination ? spadat->pkt_destination_ip : IPT_ANY_IP),
            exp_ts,
            dnat_chain->target,
            nat_ip
        );

        /* Make a global DNAT rule for all ports/protocols
        */
        ipt_rule(opts, rule_buf, NULL, spadat->use_src_ip,
            NULL, ANY_PROTO, ANY_PORT, NULL, NAT_ANY_PORT,
            dnat_chain, exp_ts, now, "DNAT ALL", "*/*");
    }
    else
    {
        memset(rule_buf, 0, CMD_BUFSIZE);

        snprintf(rule_buf, CMD_BUFSIZE-1, IPT_DNAT_RULE_ARGS,
            dnat_chain->table,
            fst_proto,
            spadat->use_src_ip,
            (fwc.use_destination ? spadat->pkt_destination_ip : IPT_ANY_IP),
            fst_port,
            exp_ts,
            dnat_chain->target,
            nat_ip,
            nat_port
        );

        ipt_rule(opts, rule_buf, NULL, spadat->use_src_ip,
            (fwc.use_destination ? spadat->pkt_destination_ip : IPT_ANY_IP),
            fst_proto, fst_port, nat_ip, nat_port, dnat_chain, exp_ts, now,
            "DNAT", spadat->spa_message_remain);
    }
    return;
}

static void snat_rule(const fko_srv_options_t * const opts,
        const acc_stanza_t * const acc,
        const char * const nat_ip,
        const unsigned int nat_port,
        const unsigned int fst_proto,
        const unsigned int fst_port,
        spa_data_t * const spadat,
        const unsigned int exp_ts,
        const time_t now)
{
    char     rule_buf[CMD_BUFSIZE] = {0};
    char     snat_target[SNAT_TARGET_BUFSIZE] = {0};
    struct   fw_chain *snat_chain = NULL;

    log_msg(LOG_DEBUG,
            "snat_rule() forward_all: %d, nat_ip: %s, nat_port: %d, force_snat: %d, force_snat_ip: %s, force_masq: %d",
            acc->forward_all, nat_ip, nat_port, acc->force_snat,
            (acc->force_snat_ip == NULL) ? "(NONE)" : acc->force_snat_ip,
            acc->force_masquerade);

    if(acc->forward_all)
    {
        /* Default to MASQUERADE */
        snat_chain = &(opts->fw_config->chain[IPT_MASQUERADE_ACCESS]);
        snprintf(snat_target, SNAT_TARGET_BUFSIZE-1, " ");

        /* Add SNAT or MASQUERADE rules.
        */
        if(acc->force_snat && is_valid_ipv4_addr(acc->force_snat_ip))
        {
            /* Using static SNAT */
            snat_chain = &(opts->fw_config->chain[IPT_SNAT_ACCESS]);
            snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                "--to-source %s", acc->force_snat_ip);
        }
        else if((opts->config[CONF_SNAT_TRANSLATE_IP] != NULL)
            && is_valid_ipv4_addr(opts->config[CONF_SNAT_TRANSLATE_IP]))
        {
            /* Using static SNAT */
            snat_chain = &(opts->fw_config->chain[IPT_SNAT_ACCESS]);
            snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                "--to-source %s", opts->config[CONF_SNAT_TRANSLATE_IP]);
        }

        memset(rule_buf, 0, CMD_BUFSIZE);

        snprintf(rule_buf, CMD_BUFSIZE-1, IPT_SNAT_ALL_RULE_ARGS,
            snat_chain->table,
            spadat->use_src_ip,
            exp_ts,
            snat_chain->target,
            snat_target
        );

        ipt_rule(opts, rule_buf, NULL, spadat->use_src_ip,
            NULL, ANY_PROTO, ANY_PORT, NULL, NAT_ANY_PORT,
            snat_chain, exp_ts, now, "SNAT ALL", "*/*");
    }
    else
    {
        /* Add SNAT or MASQUERADE rules.
        */
        if(acc->force_snat && is_valid_ipv4_addr(acc->force_snat_ip))
        {
            /* Using static SNAT */
            snat_chain = &(opts->fw_config->chain[IPT_SNAT_ACCESS]);
            snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                "--to-source %s:%i", acc->force_snat_ip, fst_port);
        }
        else if(acc->force_snat && acc->force_masquerade)
        {
            /* Using MASQUERADE */
            snat_chain = &(opts->fw_config->chain[IPT_MASQUERADE_ACCESS]);
            snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                "--to-ports %i", fst_port);
        }
        else if((opts->config[CONF_SNAT_TRANSLATE_IP] != NULL)
            && is_valid_ipv4_addr(opts->config[CONF_SNAT_TRANSLATE_IP]))
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

        ipt_rule(opts, rule_buf, NULL, spadat->use_src_ip,
                NULL, fst_proto, nat_port, nat_ip, nat_port,
                snat_chain, exp_ts, now, "SNAT",
                spadat->spa_message_remain);
    }
    return;
}

/****************************************************************************/

/* Rule Processing - Create an access request...
*/
int
process_spa_request(const fko_srv_options_t * const opts,
        const acc_stanza_t * const acc, spa_data_t * const spadat)
{
    char            nat_ip[MAX_IPV4_STR_LEN] = {0};
    char            nat_dst[MAX_HOSTNAME_LEN] = {0};

    unsigned int    nat_port = 0;
    unsigned int    fst_proto;
    unsigned int    fst_port;

    struct fw_chain * const in_chain   = &(opts->fw_config->chain[IPT_INPUT_ACCESS]);
    struct fw_chain * const out_chain  = &(opts->fw_config->chain[IPT_OUTPUT_ACCESS]);
    struct fw_chain * const fwd_chain  = &(opts->fw_config->chain[IPT_FORWARD_ACCESS]);
    struct fw_chain * const dnat_chain = &(opts->fw_config->chain[IPT_DNAT_ACCESS]);

    acc_port_list_t *port_list = NULL;
    acc_port_list_t *ple = NULL;

    char            *ndx = NULL;
    int             res = 0, is_err;
    int             str_len;
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

    /* deal with SPA packets that themselves request a NAT operation
    */
    if(spadat->message_type == FKO_LOCAL_NAT_ACCESS_MSG
      || spadat->message_type == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG
      || spadat->message_type == FKO_NAT_ACCESS_MSG
      || spadat->message_type == FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG
      || acc->force_nat)
    {
        if(acc->force_nat)
        {
            strlcpy(nat_ip, acc->force_nat_ip, sizeof(nat_ip));
            nat_port = acc->force_nat_port;
        }
        else
        {
            ndx = strchr(spadat->nat_access, ',');
            str_len = strcspn(spadat->nat_access, ",");
            if((ndx != NULL) && (str_len <= MAX_HOSTNAME_LEN))
            {
                strlcpy(nat_dst, spadat->nat_access, str_len+1);
                if (! is_valid_ipv4_addr(nat_dst))
                {
                    if(strncasecmp(opts->config[CONF_ENABLE_NAT_DNS], "Y", 1) == 0)
                    {
                        if (!is_valid_hostname(nat_dst))
                        {
                            log_msg(LOG_INFO, "Invalid Hostname in NAT SPA message");
                            return res;
                        }
                        if (ipv4_resolve(nat_dst, nat_ip) == 0)
                        {
                            log_msg(LOG_INFO, "Resolved NAT IP in SPA message");
                        }
                        else
                        {
                            log_msg(LOG_INFO, "Unable to resolve Hostname in NAT SPA message");
                            free_acc_port_list(port_list);
                            return res;
                        }
                    }
                    else
                    {
                        log_msg(LOG_INFO, "Received Hostname in NAT SPA message, but hostname is disabled.");
                        free_acc_port_list(port_list);
                        return res;

                    }
                }
                else
                {
                    strlcpy(nat_ip, nat_dst, MAX_IPV4_STR_LEN);
                }

                nat_port = strtol_wrapper(ndx+1, 0, MAX_PORT,
                        NO_EXIT_UPON_ERR, &is_err);
                if(is_err != FKO_SUCCESS)
                {
                    log_msg(LOG_INFO, "Invalid NAT port in SPA message");
                    free_acc_port_list(port_list);
                    res = is_err;
                    return res;
                }
            }
            else
            {
                log_msg(LOG_INFO, "Invalid NAT IP in SPA message");
                free_acc_port_list(port_list);
                return res;
            }
        }

        if(spadat->message_type == FKO_LOCAL_NAT_ACCESS_MSG
                || spadat->message_type == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
        {
            ipt_rule(opts, NULL, IPT_RULE_ARGS, spadat->use_src_ip,
                (fwc.use_destination ? spadat->pkt_destination_ip : IPT_ANY_IP),
                fst_proto, nat_port, nat_ip, nat_port, in_chain, exp_ts,
                now, "local NAT", spadat->spa_message_remain);
        }
        else if(strlen(fwd_chain->to_chain))
        {
            /* FORWARD access rule
            */
            forward_access_rule(opts, acc, fwd_chain, nat_ip,
                    nat_port, fst_proto, fst_port, spadat, exp_ts, now);
        }

        /* DNAT rule
        */
        if(strlen(dnat_chain->to_chain) && !acc->disable_dnat)
            dnat_rule(opts, acc, dnat_chain, nat_ip,
                    nat_port, fst_proto, fst_port, spadat, exp_ts, now);

        /* SNAT rule
        */
        if(acc->force_snat || strncasecmp(opts->config[CONF_ENABLE_IPT_SNAT], "Y", 1) == 0)
            snat_rule(opts, acc, nat_ip, nat_port,
                    fst_proto, fst_port, spadat, exp_ts, now);
    }
    else /* Non-NAT request - this is the typical case. */
    {
        /* Create an access command for each proto/port for the source ip.
        */
        while(ple != NULL)
        {
            ipt_rule(opts, NULL, IPT_RULE_ARGS, spadat->use_src_ip,
                (fwc.use_destination ? spadat->pkt_destination_ip : IPT_ANY_IP),
                ple->proto, ple->port, NULL, NAT_ANY_PORT,
                in_chain, exp_ts, now, "access", spadat->spa_message_remain);

            /* We need to make a corresponding OUTPUT rule if out_chain target
             * is not NULL.
            */
            if(strlen(out_chain->to_chain))
            {
                ipt_rule(opts, NULL, IPT_OUT_RULE_ARGS, spadat->use_src_ip,
                    (fwc.use_destination ? spadat->pkt_destination_ip : IPT_ANY_IP),
                    ple->proto, ple->port, NULL, NAT_ANY_PORT,
                    out_chain, exp_ts, now, "OUTPUT", spadat->spa_message_remain);
            }
            ple = ple->next;
        }
    }

    /* Done with the port list for access rules.
    */
    free_acc_port_list(port_list);

    return(res);
}

static void
rm_expired_rules(const fko_srv_options_t * const opts,
        const char * const ipt_output_buf,
        char *ndx, struct fw_chain *ch, int cpos, time_t now)
{
    char        exp_str[12]     = {0};
    char        rule_num_str[6] = {0};
    char        *rn_start, *rn_end, *tmp_mark;

    int         res, is_err, rn_offset=0, rule_num;
    time_t      rule_exp, min_exp = 0;

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
        chop_spaces(exp_str);
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
            /* Backtrack and get the rule number and delete it.
            */
            rn_start = ndx;
            while(--rn_start > ipt_output_buf)
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
                    "Rule parse error while finding rule line start in chain %i",
                    cpos);

                if (ch[cpos].active_rules > 0)
                    ch[cpos].active_rules--;

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
                    "Rule parse error while finding rule number in chain %i",
                    cpos);

                if (ch[cpos].active_rules > 0)
                    ch[cpos].active_rules--;

                break;
            }

            strlcpy(rule_num_str, rn_start, (rn_end - rn_start)+1);

            rule_num = strtol_wrapper(rule_num_str, rn_offset, RCHK_MAX_IPT_RULE_NUM,
                    NO_EXIT_UPON_ERR, &is_err);
            if(is_err != FKO_SUCCESS)
            {
                log_msg(LOG_ERR,
                    "Rule parse error while finding rule number in chain %i",
                    cpos);

                if (ch[cpos].active_rules > 0)
                    ch[cpos].active_rules--;

                break;
            }

            zero_cmd_buffers();

            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_DEL_RULE_ARGS,
                opts->fw_config->fw_command,
                ch[cpos].table,
                ch[cpos].to_chain,
                rule_num - rn_offset /* account for position of previously
                                        deleted rule with rn_offset */
            );

            res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
                    WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
            chop_newline(err_buf);

            log_msg(LOG_DEBUG, "rm_expired_rules() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

            if(EXTCMD_IS_SUCCESS(res))
            {
                log_msg(LOG_INFO, "Removed rule %s from %s with expire time of %u",
                    rule_num_str, ch[cpos].to_chain, rule_exp
                );

                rn_offset++;

                if (ch[cpos].active_rules > 0)
                    ch[cpos].active_rules--;
            }
            else
                log_msg(LOG_ERR, "rm_expired_rules() Error %i from cmd:'%s': %s",
                        res, cmd_buf, err_buf);

        }
        else
        {
            /* Track the minimum future rule expire time.
            */
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
    if(ch[cpos].active_rules < 1)
        ch[cpos].next_expire = 0;
    else if(min_exp)
        ch[cpos].next_expire = min_exp;

    return;
}

/* Iterate over the configure firewall access chains and purge expired
 * firewall rules.
*/
void
check_firewall_rules(const fko_srv_options_t * const opts,
        const int chk_rm_all)
{
    char            *ndx;
    char            ipt_output_buf[STANDARD_CMD_OUT_BUFSIZE] = {0};

    int             i, res;
    time_t          now;

    struct fw_chain *ch = opts->fw_config->chain;

    time(&now);

    /* Iterate over each chain and look for active rules to delete.
    */
    for(i=0; i < NUM_FWKNOP_ACCESS_TYPES; i++)
    {
        /* If there are no active rules or we have not yet
         * reached our expected next expire time, continue.
        */
        if(!chk_rm_all && (ch[i].active_rules == 0 || ch[i].next_expire > now))
            continue;

        if(ch[i].table[0] == '\0' || ch[i].to_chain[i] == '\0')
            continue;

        zero_cmd_buffers();
        memset(ipt_output_buf, 0x0, STANDARD_CMD_OUT_BUFSIZE);

        /* Get the current list of rules for this chain and delete
         * any that have expired. Note that chk_rm_all puts us in
         * garbage collection mode, and allows any rules that have
         * been manually added (potentially by a program separate
         * from fwknopd) to take advantage of fwknopd's timeout
         * mechanism.
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_LIST_RULES_ARGS,
            opts->fw_config->fw_command,
            ch[i].table,
            ch[i].to_chain
        );

        res = run_extcmd(cmd_buf, ipt_output_buf, STANDARD_CMD_OUT_BUFSIZE,
                WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
        chop_newline(ipt_output_buf);

        log_msg(LOG_DEBUG,
            "check_firewall_rules() CMD: '%s' (res: %d, ipt_output_buf: %s)",
            cmd_buf, res, ipt_output_buf);

        if(!EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR,
                    "check_firewall_rules() Error %i from cmd:'%s': %s",
                    res, cmd_buf, ipt_output_buf);
            continue;
        }

        log_msg(LOG_DEBUG, "RES=%i, CMD_BUF: %s\nRULES LIST: %s",
                res, cmd_buf, ipt_output_buf);

        ndx = strstr(ipt_output_buf, EXPIRE_COMMENT_PREFIX);
        if(ndx == NULL)
        {
            /* we did not find a candidate rule to expire
            */
            log_msg(LOG_DEBUG,
                "Did not find expire comment in rules list %i", i);

            if (ch[i].active_rules > 0)
                ch[i].active_rules--;

            continue;
        }

        rm_expired_rules(opts, ipt_output_buf, ndx, ch, i, now);
    }

    return;
}

int
validate_ipt_chain_conf(const char * const chain_str)
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

#endif /* FIREWALL_IPTABLES */

/***EOF***/
