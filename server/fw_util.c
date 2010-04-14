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

static struct fw_config fwc;

static void
parse_extcmd_error(int retval, int status, char *se_buf)
{
    char errmsg[256];
    char *emptr = errmsg;

    if(retval < 0)
    {
        log_msg(LOG_ERR|LOG_STDERR, "Extcmd fork error: %s", strerror(errno));
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

    log_msg(LOG_WARNING|LOG_STDERR, errmsg);
}

static int
jump_rule_exists(int chain_num)
{
    int     num, x, pos = 0;
    char    cmd_buf[256];
    char    target[256];
    char    line_buf[256] = {0};
    FILE   *ipt;
    
    sprintf(cmd_buf, "%s " IPT_LIST_RULES_ARGS,
        fwc.fw_command,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].from_chain
    );

    ipt = popen(cmd_buf, "r");

    if(ipt == NULL)
    {
        log_msg(LOG_ERR|LOG_STDERR,
            "Got error %i trying to get rules list.\n", errno);
        return(-1);
    }

    while((fgets(line_buf, 255, ipt)) != NULL)
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
    char    cmd_buf[256];
    char    err[256];

    for(i=0; i<(NUM_FWKNOP_CHAIN_TYPES-1); i++)
    {
        if(fwc.chain[i].target[0] == '\0')
            continue;

        /* First look for a jump rule to this chain and remove it if it
         * is there.
        */
        if((jump_rule_num = jump_rule_exists(i)) > 0)
        {
            sprintf(cmd_buf, "%s " IPT_DEL_RULE_ARGS,
                fwc.fw_command,
                fwc.chain[i].table,
                fwc.chain[i].from_chain,
                jump_rule_num
            );

            //printf("CMD: '%s'\n", cmd_buf);
            res = run_extcmd(cmd_buf, NULL, err, 0, 256, &status);
            /* Expect full success on this */
            if(! EXTCMD_IS_SUCCESS(res))
                parse_extcmd_error(res, status, err); 
        }

        /* Now flush and remove the chain.
        */
        sprintf(cmd_buf,
            "(%s " IPT_FLUSH_CHAIN_ARGS "; %s " IPT_DEL_CHAIN_ARGS ")", // > /dev/null 2>&1",
            fwc.fw_command,
            fwc.chain[i].table,
            fwc.chain[i].to_chain,
            fwc.fw_command,
            fwc.chain[i].table,
            fwc.chain[i].to_chain
        );

        //printf("CMD: '%s'\n", cmd_buf);
        res = run_extcmd(cmd_buf, NULL, err, 0, 256, &status);
        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
            parse_extcmd_error(res, status, err); 
    }
}

/* Create the fwknop custom chains (at least those that are configured).
*/
static int
create_fw_chains(void)
{
    int     i;
    int     res, status, got_err = 0;
    char    cmd_buf[256];
    char    err[256];

    for(i=0; i<(NUM_FWKNOP_CHAIN_TYPES-1); i++)
    {
        if(fwc.chain[i].target[0] == '\0')
            continue;

        /* Create the custom chain.
        */
        sprintf(cmd_buf, "%s " IPT_NEW_CHAIN_ARGS,
            fwc.fw_command,
            fwc.chain[i].table,
            fwc.chain[i].to_chain
        );

        //printf("CMD: '%s'\n", cmd_buf);
        res = run_extcmd(cmd_buf, NULL, err, 0, 256, &status);
        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
        {
            parse_extcmd_error(res, status, err); 
            got_err++;
        }

        /* Then create the jump rule to that chain.
        */
        sprintf(cmd_buf, "%s " IPT_ADD_JUMP_RULE_ARGS,
            fwc.fw_command,
            fwc.chain[i].table,
            fwc.chain[i].from_chain,
            fwc.chain[i].jump_rule_pos,
            fwc.chain[i].to_chain
        );

        //printf("CMD: '%s'\n", cmd_buf);
        res = run_extcmd(cmd_buf, NULL, err, 0, 256, &status);
        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
        {
            parse_extcmd_error(res, status, err); 
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

    if(opts->config[CONF_IPT_OUTPUT_ACCESS] != NULL)
        set_fw_chain_conf(IPT_OUTPUT_ACCESS, opts->config[CONF_IPT_OUTPUT_ACCESS]);

    if(opts->config[CONF_IPT_FORWARD_ACCESS] != NULL)
        set_fw_chain_conf(IPT_FORWARD_ACCESS, opts->config[CONF_IPT_FORWARD_ACCESS]);

    if(opts->config[CONF_IPT_DNAT_ACCESS] != NULL)
        set_fw_chain_conf(IPT_DNAT_ACCESS, opts->config[CONF_IPT_DNAT_ACCESS]);

    if(opts->config[CONF_IPT_SNAT_ACCESS] != NULL)
        set_fw_chain_conf(IPT_SNAT_ACCESS, opts->config[CONF_IPT_SNAT_ACCESS]);

    if(opts->config[CONF_IPT_MASQUERADE_ACCESS] != NULL)
        set_fw_chain_conf(IPT_MASQUERADE_ACCESS, opts->config[CONF_IPT_MASQUERADE_ACCESS]);

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

/***EOF***/
