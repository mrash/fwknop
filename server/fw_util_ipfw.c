/* $Id$
 *****************************************************************************
 *
 * File:    fw_util_ipfw.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Fwknop routines for managing ipfw firewall rules.
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

#if FIREWALL_IPFW

#include "fw_util.h"
#include "utils.h"
#include "log_msg.h"
#include "config_init.h"  /* for the IS_EMPTY_LINE macro */
#include "extcmd.h"
#include "access.h"

static struct fw_config fwc;
static char   cmd_buf[CMD_BUFSIZE];
static char   err_buf[CMD_BUFSIZE];
static char   cmd_out[STANDARD_CMD_OUT_BUFSIZE];

unsigned short
get_next_rule_num(void)
{
    unsigned short i, next_rule;

    for(i=0; i < fwc.max_rules; i++)
    {
        if(fwc.rule_map[i] == 0)
            return(fwc.start_rule_num + i);
    }

    return(0);
}

void
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

    /* Let us find it via our opts struct as well.
    */
    opts->fw_config = &fwc;

    return;
}

void
fw_initialize(fko_srv_options_t *opts)
{
    int res = 0;

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

            (fwc.rule_map)[0] = 1;
        }
        else
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf); 
    }
}

int
fw_cleanup(void)
{
    int     res, got_err = 0;

    zero_cmd_buffers();

    if(fwc.active_set_num > 0)
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

    if(fwc.expire_set_num > 0)
    {
        /* Create the set delete command for active rules
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

    /* Free the rule map.
    */
    free(fwc.rule_map);

    return(got_err);
}

/****************************************************************************/

/* Rule Processing - Create an access request...
*/
int
process_spa_request(fko_srv_options_t *opts, spa_data_t *spadat)
{
    /* TODO: Implement me */

    char             nat_ip[16] = {0};
    char            *ndx;

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
        rule_num = get_next_rule_num();

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

                (fwc.rule_map)[fwc.start_rule_num + rule_num] = 1;

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
        /* No other modes supported yet.
        */
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
    char             exp_str[12];
    char             rule_num_str[6];
    char            *ndx, *rn_start, *rn_end, *tmp_mark;

    int             i, res, rn_offset;
    time_t          now, rule_exp, min_exp = 0;

    time(&now);

    zero_cmd_buffers();

}

#endif /* FIREWALL_IPFW */

/***EOF***/
