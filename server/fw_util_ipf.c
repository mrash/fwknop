/*
 *****************************************************************************
 *
 * File:    fw_util_ipf.c
 *
 * Purpose: Fwknop routines for managing ipf firewall rules.
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
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

#if FIREWALL_IPF

#include "fw_util.h"
#include "utils.h"
#include "log_msg.h"
#include "extcmd.h"
#include "access.h"

static struct fw_config fwc;
static char   cmd_buf[CMD_BUFSIZE];
static char   err_buf[CMD_BUFSIZE];
static char   cmd_out[STANDARD_CMD_OUT_BUFSIZE];

/* Print all firewall rules currently instantiated by the running fwknopd
 * daemon to stdout.
*/
int
fw_dump_rules(const fko_srv_options_t *opts)
{
    int     i;
    int     res, got_err = 0;

    fprintf(stdout, "Listing fwknopd ipf rules...\n");
    fflush(stdout);

    zero_cmd_buffers();

    /* TODO: Implement or get rid of me */

    return(got_err);
}

void
fw_config_init(fko_srv_options_t *opts)
{
    /* TODO: Implement me */

    memset(&fwc, 0x0, sizeof(struct fw_config));

    /* Set our firewall exe command path (iptables in most cases).
    */
    strlcpy(fwc.fw_command, opts->config[CONF_FIREWALL_EXE], sizeof(fwc.fw_command));
    
    if(strncasecmp(opts->config[CONF_ENABLE_DESTINATION_RULE], "Y", 1)==0)
    {
        fwc.use_destination = 1;
    }

    /* Let us find it via our opts struct as well.
    */
    opts->fw_config = &fwc;

    return 1;
}

void
fw_initialize(const fko_srv_options_t *opts)
{
    int res = 0;

    /* TODO: Implement me */

    if(res != 0)
    {
        log_msg(LOG_WARNING,
                "Warning: Errors detected during fw_initialize().");
        return 0;
    }
    return 1;
}

int
fw_cleanup(void)
{

    /* TODO: Implement or get rid of me */

    return(0);
}

/****************************************************************************/

/* Rule Processing - Create an access request...
*/
int
process_spa_request(const fko_srv_options_t *opts, const acc_stanza_t *acc, spa_data_t *spadat)
{
    /* TODO: Implement me */

    char             nat_ip[MAX_IPV4_STR_LEN] = {0};
    char            *ndx;

    unsigned int     nat_port = 0;;

    acc_port_list_t *port_list = NULL;
    acc_port_list_t *ple;

    int             res = 0;
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

    /* TODO: Implement me */

    return(res);
}

/* Iterate over the configure firewall access chains and purge expired
 * firewall rules.
*/
void
check_firewall_rules(const fko_srv_options_t *opts,
        const int chk_rm_all)
{

    /* TODO: Implement me */

    char             exp_str[12]     = {0};
    char             rule_num_str[6] = {0};
    char            *ndx, *rn_start, *rn_end, *tmp_mark;

    int             i, res, rn_offset;
    time_t          now, rule_exp, min_exp = 0;

    time(&now);

    zero_cmd_buffers();
}

#endif /* FIREWALL_IPF */

/***EOF***/
