/*
 ******************************************************************************
 *
 * File:    cmd_opts.h
 *
 * Author:  Damien Stuart
 *
 * Purpose: Header file for fwknopd command line options.
 *
 * Copyright 2010-2013 Damien Stuart (dstuart@dstuart.org)
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
    "MAX_SNIFF_BYTES",
    "ENABLE_SPA_PACKET_AGING",
    "MAX_SPA_PACKET_AGE",
    "ENABLE_DIGEST_PERSISTENCE",
    "CMD_EXEC_TIMEOUT",
    //"BLACKLIST",
    "ENABLE_SPA_OVER_HTTP",
    "ENABLE_TCP_SERVER",
    "TCPSERV_PORT",
    "LOCALE",
    "SYSLOG_IDENTITY",
    "SYSLOG_FACILITY",
    //"ENABLE_EXTERNAL_CMDS",
    //"EXTERNAL_CMD_OPEN",
    //"EXTERNAL_CMD_CLOSE",
    //"EXTERNAL_CMD_ALARM",
    //"ENABLE_EXT_CMD_PREFIX",
    //"EXT_CMD_PREFIX",
#if FIREWALL_IPTABLES
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
    "FWKNOP_PID_FILE",
#if USE_FILE_CACHE
    "DIGEST_FILE",
#else
    "DIGEST_DB_FILE",
#endif
    "GPG_HOME_DIR",
    "FIREWALL_EXE",
    "VERBOSE"
};


/* Long options values (for those that may not have a short option).
*/
enum {
    FW_LIST         = 0x200,
    FW_LIST_ALL,
    FW_FLUSH,
    GPG_HOME_DIR,
    PCAP_FILE,
    ENABLE_PCAP_ANY_DIRECTION,
    ROTATE_DIGEST_CACHE,
    NOOP /* Just to be a marker for the end */
};

/* Our getopt_long options string.
*/
#define GETOPTS_OPTION_STRING "a:c:C:d:Dfhi:Kl:O:p:P:RSvV"

/* Our program command-line options...
*/
static struct option cmd_opts[] =
{
    {"access-file",         1, NULL, 'a'},
    {"config-file",         1, NULL, 'c'},
    {"packet-limit",        1, NULL, 'C'},
    {"digest-file",         1, NULL, 'd'},
    {"dump-config",         0, NULL, 'D'},
    {"foreground",          0, NULL, 'f'},
    {"help",                0, NULL, 'h'},
    {"interface",           1, NULL, 'i'},
    {"kill",                0, NULL, 'K'},
    {"fw-flush",            0, NULL, FW_FLUSH },
    {"fw-list",             0, NULL, FW_LIST },
    {"fw-list-all",         0, NULL, FW_LIST_ALL },
    {"gpg-home-dir",        1, NULL, GPG_HOME_DIR },
    {"locale",              1, NULL, 'l' },
    {"rotate-digest-cache", 0, NULL, ROTATE_DIGEST_CACHE },
    {"override-config",     1, NULL, 'O' },
    {"pcap-file",           1, NULL, PCAP_FILE },
    {"pcap-filter",         1, NULL, 'P'},
    {"pcap-any-direction",  0, NULL, ENABLE_PCAP_ANY_DIRECTION },
    {"pid-file",            1, NULL, 'p'},
    {"restart",             0, NULL, 'R'},
    {"status",              0, NULL, 'S'},
    {"verbose",             0, NULL, 'v'},
    {"version",             0, NULL, 'V'},
    {0, 0, 0, 0}
};

#endif /* CMD_OPTS_H */

/***EOF***/
