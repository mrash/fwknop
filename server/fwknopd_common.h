/*
 ******************************************************************************
 *
 * File:    fwknopd_common.h
 *
 * Author:  Damien Stuart
 *
 * Purpose: Header file for fwknopd source files.
 *
 * Copyright (C) 2009 Damien Stuart (dstuart@dstuart.org)
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
 ******************************************************************************
*/
#ifndef FWKNOPD_COMMON_H
#define FWKNOPD_COMMON_H

#include "common.h"

#if HAVE_LIBPCAP
  #include <pcap.h>
#endif

/* My Name and Version
*/
#define MY_NAME     "fwknopd"
#define MY_DESC     "Single Packet Authorization server"

/* Get our program version from VERSION (defined in config.h).
*/
#define MY_VERSION VERSION

/* Some program defaults.
*/
#ifndef DEF_CONF_DIR
  #define DEF_CONF_DIR      SYSCONFDIR"/fwknop"
#endif
#define DEF_CONFIG_FILE     DEF_CONF_DIR"/"MY_NAME".conf"
#define DEF_INTERFACE       "eth0"

/* fwknopd-specific limits
*/
#define MAX_PCAP_FILTER_LEN 1024
#define MAX_IFNAME_LEN      128

/* Data collection modes
*/
enum {
    SPA_CAP_MODE_PCAP,
    SPA_CAP_MODE_UDP,
    SPA_CAP_MODE_TCP
};

/* Configuration file parameter tags.
 * This will correspond to entries in the configuration parameters
 * array.
*/
enum {
    CONF_CONFIG_FILE = 0,
    CONF_FIREWALL_LOG,
    CONF_GPG_KEY,
    CONF_OVERRIDE_CONFIG,
    CONF_EMAIL_ADDRESSES,
    CONF_HOSTNAME,
    CONF_FIREWALL_TYPE,
    CONF_AUTH_MODE,
    CONF_PCAP_INTF,
    CONF_ENABLE_PCAP_PROMISC,
    CONF_PCAP_FILTER,
    CONF_ENABLE_SPA_PACKET_AGING,
    CONF_MAX_SPA_PACKET_AGE,
    CONF_ENABLE_DIGEST_PERSISTENCE,
    CONF_DIGEST_TYPE,
    CONF_ENABLE_DIGEST_INCLUDE_SRC,
    CONF_ENABLE_IPT_FORWARDING,
    CONF_ENABLE_IPT_LOCAL_NAT,
    CONF_ENABLE_IPT_SNAT,
    CONF_SNAT_TRANSLATE_IP,
    CONF_ENABLE_PROC_IP_FORWARD,
    CONF_ENABLE_IPT_OUTPUT,
    CONF_REQUIRE_SOURCE_ADDRESS,
    CONF_ENABLE_COOKED_INTF,
    CONF_ENABLE_VOLUNTARY_EXITS,
    CONF_EXIT_INTERVAL,
    CONF_MAX_SNIFF_BYTES,
    CONF_FLUSH_IPT_AT_INIT,
    CONF_IPFW_RULE_NUM,
    CONF_IPFW_SET_NUM,
    CONF_IPFW_DYNAMIC_INTERVAL,
    CONF_PCAP_CMD_TIMEOUT,
    CONF_GPG_HOME_DIR,
    CONF_PCAP_PKT_FILE,
    CONF_BLACKLIST,
    CONF_MAX_HOPS,
    CONF_ENABLE_SPA_OVER_HTTP,
    CONF_ENABLE_TCP_SERVER,
    CONF_TCPSERV_PORT,
    CONF_LOCALE,
    CONF_SYSLOG_DAEMON,
    CONF_SYSLOG_IDENTITY,
    CONF_SYSLOG_FACILITY,
    CONF_SYSLOG_PRIORITY,
    CONF_ALERTING_METHODS,
    CONF_IPT_CMD_ALARM,
    CONF_IPT_EXEC_STYLE,
    CONF_IPT_EXEC_SLEEP,
    CONF_IPT_EXEC_TRIES,
    CONF_ENABLE_EXTERNAL_CMDS,
    CONF_EXTERNAL_CMD_OPEN,
    CONF_EXTERNAL_CMD_CLOSE,
    CONF_EXTERNAL_CMD_ALARM,
    CONF_ENABLE_EXT_CMD_PREFIX,
    CONF_EXT_CMD_PREFIX,
    CONF_IPT_INPUT_ACCESS,
    CONF_IPT_OUTPUT_ACCESS,
    CONF_IPT_FORWARD_ACCESS,
    CONF_IPT_DNAT_ACCESS,
    CONF_IPT_SNAT_ACCESS,
    CONF_IPT_MASQUERADE_ACCESS,
    CONF_FWKNOP_DIR,
    CONF_FWKNOP_RUN_DIR,
    CONF_FWKNOP_MOD_DIR,
    CONF_FWKNOP_CONF_DIR,
    CONF_FWKNOP_ERR_DIR,
    CONF_ACCESS_CONF,
    CONF_DIGEST_FILE,
    CONF_FWKNOP_PID_FILE,
    CONF_FWKNOP_CMDLINE_FILE,
    CONF_TCPSERV_PID_FILE,
    CONF_PROC_IP_FORWARD_FILE,
    CONF_IPT_OUTPUT_FILE,
    CONF_IPT_ERROR_FILE,
    NUMBER_OF_CONFIG_ENTRIES  /* Marks the end and number of entries */
};

/* Now that we have the config entry indexes defined, we will create a
 * config entry name map as well (too lazy to make a hash table).
 *
 * Note: It is very important this list matches the one above (with the
 *       exception of the last entry above).
*/
static char *config_map[NUMBER_OF_CONFIG_ENTRIES] = {
    "CONFIG_FILE",
    "FIREWALL_LOG",
    "GPG_KEY",
    "OVERRIDE_CONFIG",
    "EMAIL_ADDRESSES",
    "HOSTNAME",
    "FIREWALL_TYPE",
    "AUTH_MODE",
    "PCAP_INTF",
    "ENABLE_PCAP_PROMISC",
    "PCAP_FILTER",
    "ENABLE_SPA_PACKET_AGING",
    "MAX_SPA_PACKET_AGE",
    "ENABLE_DIGEST_PERSISTENCE",
    "DIGEST_TYPE",
    "ENABLE_DIGEST_INCLUDE_SRC",
    "ENABLE_IPT_FORWARDING",
    "ENABLE_IPT_LOCAL_NAT",
    "ENABLE_IPT_SNAT",
    "SNAT_TRANSLATE_IP",
    "ENABLE_PROC_IP_FORWARD",
    "ENABLE_IPT_OUTPUT",
    "REQUIRE_SOURCE_ADDRESS",
    "ENABLE_COOKED_INTF",
    "ENABLE_VOLUNTARY_EXITS",
    "EXIT_INTERVAL",
    "MAX_SNIFF_BYTES",
    "FLUSH_IPT_AT_INIT",
    "IPFW_RULE_NUM",
    "IPFW_SET_NUM",
    "IPFW_DYNAMIC_INTERVAL",
    "PCAP_CMD_TIMEOUT",
    "GPG_HOME_DIR",
    "PCAP_PKT_FILE",
    "BLACKLIST",
    "MAX_HOPS",
    "ENABLE_SPA_OVER_HTTP",
    "ENABLE_TCP_SERVER",
    "TCPSERV_PORT",
    "LOCALE",
    "SYSLOG_DAEMON",
    "SYSLOG_IDENTITY",
    "SYSLOG_FACILITY",
    "SYSLOG_PRIORITY",
    "ALERTING_METHODS",
    "IPT_CMD_ALARM",
    "IPT_EXEC_STYLE",
    "IPT_EXEC_SLEEP",
    "IPT_EXEC_TRIES",
    "ENABLE_EXTERNAL_CMDS",
    "EXTERNAL_CMD_OPEN",
    "EXTERNAL_CMD_CLOSE",
    "EXTERNAL_CMD_ALARM",
    "ENABLE_EXT_CMD_PREFIX",
    "EXT_CMD_PREFIX",
    "IPT_INPUT_ACCESS",
    "IPT_OUTPUT_ACCESS",
    "IPT_FORWARD_ACCESS",
    "IPT_DNAT_ACCESS",
    "IPT_SNAT_ACCESS",
    "IPT_MASQUERADE_ACCESS",
    "FWKNOP_DIR",
    "FWKNOP_RUN_DIR",
    "FWKNOP_MOD_DIR",
    "FWKNOP_CONF_DIR",
    "FWKNOP_ERR_DIR",
    "ACCESS_CONF",
    "DIGEST_FILE",
    "FWKNOP_PID_FILE",
    "FWKNOP_CMDLINE_FILE",
    "TCPSERV_PID_FILE",
    "PROC_IP_FORWARD_FILE",
    "IPT_OUTPUT_FILE",
    "IPT_ERROR_FILE"
};  

/* fwknopd server configuration parameters and values
*/
typedef struct fko_srv_options
{
    /* The command-line options or flags that invoke an immediate response
     * then exit.
    */
    unsigned char   dump_config;        /* Dump current configuration flag */
    unsigned char   foreground;         /* Run in foreground flag */
    unsigned char   restart;            /* Restart fwknopd flag*/
    unsigned char   verbose;            /* Verbose mode flag */
    unsigned char   test;               /* Test mode flag */

    /* This array holds all of the config file entry values as strings
     * indexed by their tag name.
    */
    char           *config[NUMBER_OF_CONFIG_ENTRIES];

} fko_srv_options_t;

extern fko_srv_options_t options;

#endif /* FWKNOPD_COMMON_H */

/***EOF***/
