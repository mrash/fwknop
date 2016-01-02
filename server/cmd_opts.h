/*
 ******************************************************************************
 *
 * File:    cmd_opts.h
 *
 * Purpose: Header file for fwknopd command line options.
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
 ******************************************************************************
*/
#ifndef CMD_OPTS_H
#define CMD_OPTS_H

/* The config entry indexes are defined in the fwknopd_common.h, and now we
 * create a config entry name map as well (too lazy to make a hash table).
 *
 * Note: It is very important this list matches the enum in fwknopd_common.h
 *
*/
static char *config_map[NUMBER_OF_CONFIG_ENTRIES] = {
    "CONFIG_FILE",
    "OVERRIDE_CONFIG",
    //"FIREWALL_TYPE",
    "PCAP_INTF",
    "PCAP_FILE",
    "ENABLE_PCAP_PROMISC",
    "PCAP_FILTER",
    "PCAP_DISPATCH_COUNT",
    "PCAP_LOOP_SLEEP",
    "ENABLE_PCAP_ANY_DIRECTION",
    "EXIT_AT_INTF_DOWN",
    "MAX_SNIFF_BYTES",
    "ENABLE_SPA_PACKET_AGING",
    "MAX_SPA_PACKET_AGE",
    "ENABLE_DIGEST_PERSISTENCE",
    "RULES_CHECK_THRESHOLD",
    "CMD_EXEC_TIMEOUT",
    //"BLACKLIST",
    "ENABLE_SPA_OVER_HTTP",
    "ENABLE_TCP_SERVER",
    "TCPSERV_PORT",
    "ENABLE_UDP_SERVER",
    "UDPSERV_PORT",
    "UDPSERV_SELECT_TIMEOUT",
    "LOCALE",
    "SYSLOG_IDENTITY",
    "SYSLOG_FACILITY",
    //"ENABLE_EXTERNAL_CMDS",
    //"EXTERNAL_CMD_OPEN",
    //"EXTERNAL_CMD_CLOSE",
    //"EXTERNAL_CMD_ALARM",
    //"ENABLE_EXT_CMD_PREFIX",
    //"EXT_CMD_PREFIX",
    "ENABLE_DESTINATION_RULE",
    "ENABLE_NAT_DNS",
#if FIREWALL_FIREWALLD
    "ENABLE_FIREWD_FORWARDING",
    "ENABLE_FIREWD_LOCAL_NAT",
    "ENABLE_FIREWD_SNAT",
    "SNAT_TRANSLATE_IP",
    "ENABLE_FIREWD_OUTPUT",
    "FLUSH_FIREWD_AT_INIT",
    "FLUSH_FIREWD_AT_EXIT",
    "FIREWD_INPUT_ACCESS",
    "FIREWD_OUTPUT_ACCESS",
    "FIREWD_FORWARD_ACCESS",
    "FIREWD_DNAT_ACCESS",
    "FIREWD_SNAT_ACCESS",
    "FIREWD_MASQUERADE_ACCESS",
    "ENABLE_FIREWD_COMMENT_CHECK",
#elif FIREWALL_IPTABLES
    "ENABLE_IPT_FORWARDING",
    "ENABLE_IPT_LOCAL_NAT",
    "ENABLE_IPT_SNAT",
    "SNAT_TRANSLATE_IP",
    "ENABLE_IPT_OUTPUT",
    "FLUSH_IPT_AT_INIT",
    "FLUSH_IPT_AT_EXIT",
    "IPT_INPUT_ACCESS",
    "IPT_OUTPUT_ACCESS",
    "IPT_FORWARD_ACCESS",
    "IPT_DNAT_ACCESS",
    "IPT_SNAT_ACCESS",
    "IPT_MASQUERADE_ACCESS",
    "ENABLE_IPT_COMMENT_CHECK",
#elif FIREWALL_IPFW
    "FLUSH_IPFW_AT_INIT",
    "FLUSH_IPFW_AT_EXIT",
    "IPFW_START_RULE_NUM",
    "IPFW_MAX_RULES",
    "IPFW_ACTIVE_SET_NUM",
    "IPFW_EXPIRE_SET_NUM",
    "IPFW_EXPIRE_PURGE_INTERVAL",
    "IPFW_ADD_CHECK_STATE",
#elif FIREWALL_PF
    "PF_ANCHOR_NAME",
    "PF_EXPIRE_INTERVAL",
#elif FIREWALL_IPF
    /* --DSS Place-holder */
#endif /* FIREWALL type */
    "FWKNOP_RUN_DIR",
    "FWKNOP_CONF_DIR",
    "ACCESS_FILE",
    "ACCESS_FOLDER",
    "FWKNOP_PID_FILE",
#if USE_FILE_CACHE
    "DIGEST_FILE",
#else
    "DIGEST_DB_FILE",
#endif
    "GPG_HOME_DIR",
    "GPG_EXE",
    "SUDO_EXE",
    "FIREWALL_EXE",
    "VERBOSE",
#if AFL_FUZZING
    "AFL_PKT_FILE",
#endif
    "FAULT_INJECTION_TAG"
};


/* Long options values (for those that may not have a short option).
*/
enum {
    FW_LIST         = 0x200,
    FW_LIST_ALL,
    FW_FLUSH,
    KEY_GEN_FILE,
    KEY_LEN,
    HMAC_KEY_LEN,
    HMAC_DIGEST_TYPE,
    AFL_PKT_FILE,
    GPG_HOME_DIR,
    GPG_EXE_PATH,
    SUDO_EXE_PATH,
    FIREWD_DISABLE_CHECK_SUPPORT,
    IPT_DISABLE_CHECK_SUPPORT,
    PCAP_FILE,
    ENABLE_PCAP_ANY_DIRECTION,
    ROTATE_DIGEST_CACHE,
    SYSLOG_ENABLE,
    DUMP_SERVER_ERR_CODES,
    EXIT_AFTER_PARSE_CONFIG,
    EXIT_VALIDATE_DIGEST_CACHE,
    FAULT_INJECTION_TAG,
    ACCESS_FOLDER,
    NOOP /* Just to be a marker for the end */
};

/* Our getopt_long options string.
*/
#define GETOPTS_OPTION_STRING "Aa:c:C:d:Dfhi:Kl:O:p:P:Rr:StUvV"

/* Our program command-line options...
*/
static struct option cmd_opts[] =
{
    {"access-file",             1, NULL, 'a'},
    {"access-folder",           1, NULL, ACCESS_FOLDER},
    {"afl-fuzzing",             0, NULL, 'A'},
    {"afl-pkt-file",            1, NULL, AFL_PKT_FILE },
    {"config-file",             1, NULL, 'c'},
    {"packet-limit",            1, NULL, 'C'},
    {"digest-file",             1, NULL, 'd'},
    {"dump-config",             0, NULL, 'D'},
    {"dump-serv-err-codes",     0, NULL, DUMP_SERVER_ERR_CODES },
    {"exit-parse-config",       0, NULL, EXIT_AFTER_PARSE_CONFIG },
    {"exit-parse-digest-cache", 0, NULL, EXIT_VALIDATE_DIGEST_CACHE },
    {"syslog-enable",           0, NULL, SYSLOG_ENABLE },
    {"foreground",              0, NULL, 'f'},
    {"fault-injection-tag",     1, NULL, FAULT_INJECTION_TAG},
    {"help",                    0, NULL, 'h'},
    {"interface",               1, NULL, 'i'},
    {"key-gen",                 0, NULL, 'k'},
    {"key-gen-file",            1, NULL, KEY_GEN_FILE },
    {"key-len",                 1, NULL, KEY_LEN },
    {"hmac-key-len",            1, NULL, HMAC_KEY_LEN },
    {"hmac-digest-type",        1, NULL, HMAC_DIGEST_TYPE },
    {"kill",                    0, NULL, 'K' },
    {"fw-flush",                0, NULL, FW_FLUSH },
    {"fw-list",                 0, NULL, FW_LIST },
    {"fw-list-all",             0, NULL, FW_LIST_ALL },
    {"gpg-home-dir",            1, NULL, GPG_HOME_DIR },
    {"gpg-exe",                 1, NULL, GPG_EXE_PATH },
    {"no-firewd-check-support", 0, NULL, FIREWD_DISABLE_CHECK_SUPPORT },
    {"no-ipt-check-support",    0, NULL, IPT_DISABLE_CHECK_SUPPORT },
    {"locale",                  1, NULL, 'l' },
    {"rotate-digest-cache",     0, NULL, ROTATE_DIGEST_CACHE },
    {"override-config",         1, NULL, 'O' },
    {"pcap-file",               1, NULL, PCAP_FILE },
    {"pcap-filter",             1, NULL, 'P'},
    {"pcap-any-direction",      0, NULL, ENABLE_PCAP_ANY_DIRECTION },
    {"pid-file",                1, NULL, 'p'},
    {"run-dir",                 1, NULL, 'r'},
    {"restart",                 0, NULL, 'R'},
    {"status",                  0, NULL, 'S'},
    {"sudo-exe",                1, NULL, SUDO_EXE_PATH },
    {"test",                    0, NULL, 't'},
    {"udp-server",              0, NULL, 'U'},
    {"verbose",                 0, NULL, 'v'},
    {"version",                 0, NULL, 'V'},
    {0, 0, 0, 0}
};

#endif /* CMD_OPTS_H */

/***EOF***/
