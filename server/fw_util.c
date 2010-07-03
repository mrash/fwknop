/* $Id$
 *****************************************************************************
 *
 * File:    fw_util.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Fwknop routines for managing the firewall rules.
 *
 * Copyright (C) 2010 Damien Stuart (dstuart@dstuart.org)
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
#include "fw_util.h"
#include "log_msg.h"
#include "config_init.h"  /* for the IS_EMPTY_LINE macro */
#include "extcmd.h"
#include "access.h"

static struct fw_config fwc;

static void
parse_extcmd_error(int retval, int status, char *se_buf)
{
    char errmsg[CMD_BUFSIZE];
    char *emptr = errmsg;

    if(retval < 0)
    {
        log_msg(LOG_ERR, "Extcmd fork error: %s", strerror(errno));
        return;
    }

    sprintf(emptr, "Extcmd return: %i, command exit status: %i", retval, status);
    emptr += strlen(emptr);

    if(EXTCMD_EXECUTION_ERROR(retval))
    {
        sprintf(errmsg, "Extcmd stderr=%s", se_buf);
        emptr += strlen(emptr);
    }

    if(EXTCMD_IS_SUCCESS_PARTIAL_STDOUT(retval))
    {
        sprintf(errmsg, "\n - Got partial stdout");
        emptr += strlen(emptr);
    }

    if(EXTCMD_IS_SUCCESS_PARTIAL_STDERR(retval))
    {
        sprintf(errmsg, "\n - Got partial stderr");
        emptr += strlen(emptr);
    }

    if(EXTCMD_STDOUT_READ_ERROR(retval))
    {
        sprintf(errmsg, "\n - Got read error on stdout");
        emptr += strlen(emptr);
    }

    if(EXTCMD_STDERR_READ_ERROR(retval))
    {
        sprintf(errmsg, "\n - Got read error on stderr");
        emptr += strlen(emptr);
    }

    log_msg(LOG_WARNING, errmsg);
}

static int
jump_rule_exists(int chain_num)
{
    int     num, x, pos = 0;
    char    cmd_buf[CMD_BUFSIZE] = {0};
    char    target[CMD_BUFSIZE] = {0};
    char    line_buf[CMD_BUFSIZE] = {0};
    FILE   *ipt;
    
    sprintf(cmd_buf, "%s " IPT_LIST_RULES_ARGS,
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
         * first character.
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

    return(pos);
}

/* Quietly flush and delete all fwknop custom chains.
*/
static void
delete_all_chains(void)
{
    int     i, pos, res, status;
    int     jump_rule_num;
    char    cmd_buf[CMD_BUFSIZE] = {0};
    char    err[CMD_BUFSIZE] = {0};

    for(i=0; i<(NUM_FWKNOP_ACCESS_TYPES); i++)
    {
        if(fwc.chain[i].target[0] == '\0')
            continue;

        /* First look for a jump rule to this chain and remove it if it
         * is there.
        */
        if((jump_rule_num = jump_rule_exists(i)) > 0)
        {
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_DEL_RULE_ARGS,
                fwc.fw_command,
                fwc.chain[i].table,
                fwc.chain[i].from_chain,
                jump_rule_num
            );

            //printf("CMD: '%s'\n", cmd_buf);
            res = run_extcmd(cmd_buf, err, CMD_BUFSIZE, 0);
            /* Expect full success on this */
            if(! EXTCMD_IS_SUCCESS(res))
                log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err); 
        }

        memset(cmd_buf, 0x0, CMD_BUFSIZE);

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

        //printf("CMD: '%s'\n", cmd_buf);
        res = run_extcmd(cmd_buf, err, CMD_BUFSIZE, 0);
        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err); 
    }
}

/* Create the fwknop custom chains (at least those that are configured).
*/
static int
create_fw_chains(void)
{
    int     i;
    int     res, status, got_err = 0;
    char    cmd_buf[CMD_BUFSIZE] = {0};
    char    err[CMD_BUFSIZE] = {0};

    for(i=0; i<(NUM_FWKNOP_ACCESS_TYPES); i++)
    {
        if(fwc.chain[i].target[0] == '\0')
            continue;

        /* Create the custom chain.
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_NEW_CHAIN_ARGS,
            fwc.fw_command,
            fwc.chain[i].table,
            fwc.chain[i].to_chain
        );

        //printf("(%i) CMD: '%s'\n", i, cmd_buf);
        res = run_extcmd(cmd_buf, err, CMD_BUFSIZE, 0);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err); 
            got_err++;
        }

        memset(cmd_buf, 0x0, CMD_BUFSIZE);

        /* Then create the jump rule to that chain.
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_ADD_JUMP_RULE_ARGS,
            fwc.fw_command,
            fwc.chain[i].table,
            fwc.chain[i].from_chain,
            fwc.chain[i].jump_rule_pos,
            fwc.chain[i].to_chain
        );

        //printf("(%i) CMD: '%s'\n", i, cmd_buf);
        res = run_extcmd(cmd_buf, err, CMD_BUFSIZE, 0);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err); 
            got_err++;
        }
    }

    return(got_err);
}


static void
set_fw_chain_conf(int type, char *conf_str)
{
    int i, j;
    char *mark;
    char tbuf[1024]     = {0};
    char *ndx           = conf_str;

    char *chain_fields[FW_NUM_CHAIN_FIELDS];

    struct fw_chain *chain = &(fwc.chain[type]);

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
    strlcpy(chain->target, chain_fields[0], MAX_TARGET_NAME_LEN);

    /* Pull and set Direction */
    if(strcmp(chain_fields[1], FW_CHAIN_DIR_SRC_STR) == 0)
        chain->direction = FW_CHAIN_DIR_SRC;
    else if(strcmp(chain_fields[1], FW_CHAIN_DIR_DST_STR) == 0)
        chain->direction = FW_CHAIN_DIR_DST;
    else if(strcmp(chain_fields[1], FW_CHAIN_DIR_BOTH_STR) == 0)
        chain->direction = FW_CHAIN_DIR_BOTH;
    else
        chain->direction = FW_CHAIN_DIR_UNKNOWN;

    /* Pull and set Table */
    strlcpy(chain->table, chain_fields[2], MAX_TABLE_NAME_LEN);

    /* Pull and set From_chain */
    strlcpy(chain->from_chain, chain_fields[3], MAX_CHAIN_NAME_LEN);

    /* Pull and set Jump_rule_position */
    chain->jump_rule_pos = atoi(chain_fields[4]);

    /* Pull and set To_chain */
    strlcpy(chain->to_chain, chain_fields[5], MAX_CHAIN_NAME_LEN);

    /* Pull and set Jump_rule_position */
    chain->rule_pos = atoi(chain_fields[6]);

}

void
fw_initialize(fko_srv_options_t *opts)
{
    int res;

    memset(&fwc, 0x0, sizeof(struct fw_config));

    /* Set our firewall exe command path (iptables in most cases).
    */
    strlcpy(fwc.fw_command, opts->config[CONF_EXE_IPTABLES], MAX_PATH_LEN);

    /* Pull the fwknop chain config info and setup our internal
     * config struct.  The IPT_INPUT is the only one that is
     * required. The rest are optional.
    */
    if(opts->config[CONF_IPT_INPUT_ACCESS] != NULL)
        set_fw_chain_conf(IPT_INPUT_ACCESS, opts->config[CONF_IPT_INPUT_ACCESS]);
    else
    {
        fprintf(stderr, "The IPT_INPUT_ACCESS chain must be defined in the config file.\n");
        exit(EXIT_FAILURE);
    }

    /* The FWKNOP_OUTPUT_ACCESS requires ENABLE_IPT_OUTPUT_ACCESS be Y
    */
    if(opts->config[CONF_ENABLE_IPT_OUTPUT] != NULL
      && (strncasecmp(opts->config[CONF_ENABLE_IPT_OUTPUT], "Y", 1)==0)
      && opts->config[CONF_IPT_OUTPUT_ACCESS] != NULL)
        set_fw_chain_conf(IPT_OUTPUT_ACCESS, opts->config[CONF_IPT_OUTPUT_ACCESS]);

    /* The remaining access chains require ENABLE_IPT_FORWARDING = Y
    */
    if(opts->config[CONF_ENABLE_IPT_FORWARDING] != NULL
      && (strncasecmp(opts->config[CONF_ENABLE_IPT_FORWARDING], "Y", 1)==0))
    {

        if(opts->config[CONF_IPT_FORWARD_ACCESS] != NULL)
            set_fw_chain_conf(IPT_FORWARD_ACCESS, opts->config[CONF_IPT_FORWARD_ACCESS]);

        if(opts->config[CONF_IPT_DNAT_ACCESS] != NULL)
            set_fw_chain_conf(IPT_DNAT_ACCESS, opts->config[CONF_IPT_DNAT_ACCESS]);

        /* SNAT (whichever mode) requires ENABLE_IPT_SNAT = Y
        */
        if(opts->config[CONF_ENABLE_IPT_SNAT] != NULL
          && (strncasecmp(opts->config[CONF_ENABLE_IPT_SNAT], "Y", 1)==0))
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
            {
                if(opts->config[CONF_IPT_SNAT_ACCESS] != NULL)
                    set_fw_chain_conf(IPT_SNAT_ACCESS, opts->config[CONF_IPT_SNAT_ACCESS]);
            }
            else
            {
                if(opts->config[CONF_IPT_MASQUERADE_ACCESS] != NULL)
                    set_fw_chain_conf(IPT_MASQUERADE_ACCESS, opts->config[CONF_IPT_MASQUERADE_ACCESS]);
            }
        }
    }

    /* Let us find it via our opts struct as well.
    */
    opts->fw_config = &fwc;

    /* Flush the chains (just in case) so we can start fresh.
    */
    delete_all_chains();

    /* Now create any configured chains.
    */
    res = create_fw_chains();

    if(res != 0)
    {
        fprintf(stderr, "Warning: Errors detected during fwknop custom chain creation.\n");
        exit(EXIT_FAILURE);
    }
}

void
fw_cleanup(void)
{
    delete_all_chains();
}

/****************************************************************************/

/* Rule Processing - Create an access request...
*/
int
process_spa_request(fko_srv_options_t *opts, spa_data_t *spadat)
{
    char             cmd_buf[CMD_BUFSIZE] = {0};
    char             err[CMD_BUFSIZE] = {0};
    char             nat_ip[16] = {0};
    char             snat_target[SNAT_TARGET_BUFSIZE] = {0};
    char            *ndx;

    unsigned int     nat_port = 0;;

    acc_port_list_t *port_list = NULL;
    acc_port_list_t *ple;

    unsigned int    fst_proto;
    unsigned int    fst_port;

    struct fw_chain *in_chain   = &(opts->fw_config->chain[IPT_INPUT_ACCESS]);
    struct fw_chain *out_chain  = &(opts->fw_config->chain[IPT_OUTPUT_ACCESS]);
    struct fw_chain *fwd_chain  = &(opts->fw_config->chain[IPT_FORWARD_ACCESS]);
    struct fw_chain *dnat_chain = &(opts->fw_config->chain[IPT_DNAT_ACCESS]);
    struct fw_chain *snat_chain; /* We assign this later (if we need to). */

    int             status, res;
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
        /* Create an access command for each proto/port for the source ip.
        */
        while(ple != NULL)
        {
            memset(cmd_buf, 0x0, CMD_BUFSIZE);

            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_ADD_RULE_ARGS,
                opts->fw_config->fw_command,
                in_chain->table,
                in_chain->to_chain,
                ple->proto,
                spadat->use_src_ip,
                ple->port,
                exp_ts,
                in_chain->target
            );

//--DSS tmp
//fprintf(stderr, "ADD CMD: %s\n", cmd_buf);
            res = run_extcmd(cmd_buf, err, CMD_BUFSIZE, 0);
            if(EXTCMD_IS_SUCCESS(res))
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
            else
                log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err); 

            /* If we have to make an corresponding OUTPUT rule if out_chain target
            * is not NULL.
            */
            if(out_chain->to_chain != NULL && strlen(out_chain->to_chain))
            {
                memset(cmd_buf, 0x0, CMD_BUFSIZE);

                snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_ADD_OUT_RULE_ARGS,
                    opts->fw_config->fw_command,
                    out_chain->table,
                    out_chain->to_chain,
                    ple->proto,
                    spadat->use_src_ip,
                    ple->port,
                    exp_ts,
                    out_chain->target
                );

//--DSS tmp
//fprintf(stderr, "ADD OUTPUT CMD: %s\n", cmd_buf);
                res = run_extcmd(cmd_buf, err, CMD_BUFSIZE, 0);
                if(EXTCMD_IS_SUCCESS(res))
                {
                    log_msg(LOG_INFO, "Added OUTPUT Rule to %s for %s, %s expires at %u",
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
                else
                    log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err); 

            }

            ple = ple->next;
        }

        /* Done with the port list for access rules.
        */
        free_acc_port_list(port_list);

    }
    /* NAT requests... */
    else if(  spadat->message_type == FKO_LOCAL_NAT_ACCESS_MSG
      || spadat->message_type == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG
      || spadat->message_type == FKO_NAT_ACCESS_MSG
      || spadat->message_type == FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG  )
    {
        /* Parse out the NAT IP and Port components.
        */
        ndx = strchr(spadat->nat_access, ',');
        if(ndx != NULL)
        {
            strlcpy(nat_ip, spadat->nat_access, (ndx-spadat->nat_access)+1);
            nat_port = atoi(ndx+1);
        }

// --DSS temp
//fprintf(stderr, "NAT IP: '%s', NAT PORT: '%i'\n", nat_ip, nat_port);

        /* Make our FORWARD and NAT rules
        */
        if(fwd_chain->to_chain != NULL && strlen(fwd_chain->to_chain))
        {
            memset(cmd_buf, 0x0, CMD_BUFSIZE);

            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_ADD_FWD_RULE_ARGS,
                opts->fw_config->fw_command,
                fwd_chain->table,
                fwd_chain->to_chain,
                fst_proto,
                spadat->use_src_ip,
                nat_ip,
                nat_port,
                exp_ts,
                fwd_chain->target
            );

//--DSS tmp
//fprintf(stderr, "ADD OUTPUT CMD: %s\n", cmd_buf);
            res = run_extcmd(cmd_buf, err, CMD_BUFSIZE, 0);
            if(EXTCMD_IS_SUCCESS(res))
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
            else
                log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err); 
        }

        if(dnat_chain->to_chain != NULL && strlen(dnat_chain->to_chain))
        {
            memset(cmd_buf, 0x0, CMD_BUFSIZE);

            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_ADD_DNAT_RULE_ARGS,
                opts->fw_config->fw_command,
                dnat_chain->table,
                dnat_chain->to_chain,
                fst_proto,
                spadat->use_src_ip,
                fst_port,
                exp_ts,
                dnat_chain->target,
                nat_ip,
                nat_port
            );

//--DSS tmp
//fprintf(stderr, "ADD DNAT CMD: %s\n", cmd_buf);
            res = run_extcmd(cmd_buf, err, CMD_BUFSIZE, 0);
            if(EXTCMD_IS_SUCCESS(res))
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
            else
                log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err); 
        }

        /* If SNAT (or MASQUERADE) is wanted, then we add those rules here as well.
        */
        if(opts->config[CONF_ENABLE_IPT_SNAT] != NULL
          && strncasecmp(opts->config[CONF_ENABLE_IPT_SNAT], "Y", 1) == 0)
        {
            memset(cmd_buf, 0x0, CMD_BUFSIZE);

            /* Setup some parameter depending on whether we are using SNAT
             * or MASQUERADE.
            */
            if(opts->config[CONF_SNAT_TRANSLATE_IP] != NULL
              && strncasecmp(opts->config[CONF_SNAT_TRANSLATE_IP], "__CHANGEME__", 10)!=0)
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

            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_ADD_SNAT_RULE_ARGS,
                opts->fw_config->fw_command,
                snat_chain->table,
                snat_chain->to_chain,
                fst_proto,
                //spadat->use_src_ip,
                nat_ip,
                //fst_port,
                nat_port,
                exp_ts,
                snat_chain->target,
                snat_target
            );

            res = run_extcmd(cmd_buf, err, CMD_BUFSIZE, 0);
            if(EXTCMD_IS_SUCCESS(res))
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
            else
                log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err); 
        }
    }

    return(res);
}

/* Iterate over the configure firewall access chains and purge expired
 * firewall rules.
*/
void
check_firewall_rules(fko_srv_options_t *opts)
{
    char             cmd_buf[CMD_BUFSIZE] = {0};
    char             err[CMD_BUFSIZE] = {0};
    char             cmd_out[STANDARD_CMD_OUT_BUFSIZE];
    char             exp_str[12];
    char             rule_num_str[6];
    char            *ndx, *rn_start, *rn_end, *tmp_mark;

    int             i, res, status, rn_offset;
    time_t          now, rule_exp, min_exp;

    struct fw_chain *ch = opts->fw_config->chain;

    time(&now);

    /* Iterate over each chain and look for active rules to delete.
    */
    for(i = 0; i < NUM_FWKNOP_ACCESS_TYPES; i++)
    {
        /* Just in case we somehow lose track and fall out-of-whack,
         * we be the hero and reset it to zero.
         *  (poet but don't know it :-o )
        */
        if(ch[i].active_rules < 0)
            ch[i].active_rules = 0;

        /* If there are no active rules or we have not yet
         * reached our expected next expire time, continue.
        */
        if(ch[i].active_rules == 0 || ch[i].next_expire > now)
            continue;

        rn_offset = 0;

        /* There should be a rule to delete.  Get the current list of
         * rules for this chain and delete the ones that are expired.
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_LIST_RULES_ARGS,
            opts->fw_config->fw_command,
            ch[i].table,
            ch[i].to_chain
        );

        memset(cmd_out, 0x0, STANDARD_CMD_OUT_BUFSIZE);

        res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE, 0);

        if(!EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, cmd_out); 
            continue;
        }

        if(opts->verbose > 2)
            log_msg(LOG_INFO, "RES=%i, CMD_BUF: %s\nRULES LIST: %s", res, cmd_buf, cmd_out);

        ndx = strstr(cmd_out, "_exp_");
        if(ndx == NULL)
        {
            /* we did not find an expected rule.
            */
            log_msg(LOG_ERR,
                "Did not find expire comment in rules list %i.\n", i);

            ch[i].active_rules--;
            continue;
        }

        /* walk the list and process rules as needed.
        */
        while (ndx != NULL) {
            /* Jump forward and extract the timestamp
            */
            ndx +=5;

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
                
                if(*rn_start != '\n')
                {
                    /* This should not happen. But if it does, complain,
                     * decrement the active rule value, and go on.
                    */
                    log_msg(LOG_ERR,
                        "Rule parse error while finding rule line start in chain %i", i);

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

                    ch[i].active_rules--;
                    break;
                }
                 
                strlcpy(rule_num_str, rn_start, (rn_end - rn_start)+1);

                memset(cmd_buf, 0x0, CMD_BUFSIZE);

                snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_DEL_RULE_ARGS,
                    opts->fw_config->fw_command,
                    ch[i].table,
                    ch[i].to_chain,
                    atoi(rule_num_str) - rn_offset
                );
 

//fprintf(stderr, "DELETE RULE CMD: %s\n", cmd_buf);
                res = run_extcmd(cmd_buf, err, CMD_BUFSIZE, 0);
                if(EXTCMD_IS_SUCCESS(res))
                {
                    log_msg(LOG_INFO, "Removed rule %s from %s with expire time of %u.",
                        rule_num_str, ch[i].to_chain, rule_exp
                    );

                    rn_offset++;
                    ch[i].active_rules--;
                }
                else
                    log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err); 

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
            ndx = strstr(tmp_mark, "_exp_");
        }

        /* Set the next pending expire time accordingly. 0 if there are no
         * more rules, or whatever the next expected (min_exp) time will be.
        */
        if(ch[i].active_rules < 1)
            ch[i].next_expire = 0;
        else
            ch[i].next_expire = min_exp;
    }
}

/***EOF***/
