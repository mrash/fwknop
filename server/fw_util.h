/* $Id$
 *****************************************************************************
 *
 * File:    fw_util.h
 *
 * Author:  Damien Stuart (dstuart@dstuart.org)
 *
 * Purpose: Header file for fw_util.c.
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
#ifndef FW_UTIL_H
#define FW_UTIL_H

#define CMD_BUFSIZE                 256
#define MAX_FW_COMMAND_ARGS_LEN     256

#define STANDARD_CMD_OUT_BUFSIZE    4096

#define SNAT_TARGET_BUFSIZE         64

/* iptables command args            
*/
#define IPT_ADD_RULE_ARGS "-t %s -A %s -p %i -s %s --dport %i -m comment --comment _exp_%u -j %s 2>&1"
#define IPT_ADD_OUT_RULE_ARGS "-t %s -A %s -p %i -d %s --sport %i -m comment --comment _exp_%u -j %s 2>&1"
#define IPT_ADD_FWD_RULE_ARGS "-t %s -A %s -p %i -s %s -d %s --dport %i -m comment --comment _exp_%u -j %s 2>&1"
#define IPT_ADD_DNAT_RULE_ARGS "-t %s -A %s -p %i -s %s --dport %i -m comment --comment _exp_%u -j %s --to-destination %s:%i 2>&1"
#define IPT_ADD_SNAT_RULE_ARGS "-t %s -A %s -p %i -d %s --dport %i -m comment --comment _exp_%u -j %s %s 2>&1"
#define IPT_DEL_RULE_ARGS "-t %s -D %s %i 2>&1"
#define IPT_NEW_CHAIN_ARGS "-t %s -N %s 2>&1"
#define IPT_FLUSH_CHAIN_ARGS "-t %s -F %s 2>&1"
#define IPT_DEL_CHAIN_ARGS "-t %s -X %s 2>&1"
#define IPT_ADD_JUMP_RULE_ARGS "-t %s -I %s %i -j %s 2>&1"
#define IPT_LIST_RULES_ARGS "-t %s -L %s --line-numbers -n 2>&1"

/* Function prototypes
*/
void fw_initialize(fko_srv_options_t *opts);
void fw_cleanup(void);
int process_spa_request(fko_srv_options_t *opts, spa_data_t *spdat);
void check_firewall_rules(fko_srv_options_t *opts);

#endif /* FW_UTIL_H */

/***EOF***/
