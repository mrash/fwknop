/*
 ******************************************************************************
 *
 * File:    config_init.h
 *
 * Author:  Damien Stuart
 *
 * Purpose: Header file for fwknopd config_init.
 *
 * Copyright 2010 Damien Stuart (dstuart@dstuart.org)
 *
 *  License (GNU Public License):
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
#ifndef CONFIG_INIT_H
#define CONFIG_INIT_H

#include <getopt.h>
#include <sys/stat.h>

/* For integer variable range checking
*/
#define RCHK_MAX_PCAP_LOOP_SLEEP            100000  /* microseconds */
#define RCHK_MAX_SPA_PACKET_AGE             100000  /* seconds, can disable */
#define RCHK_MAX_SNIFF_BYTES                1514
#define RCHK_MAX_TCPSERV_PORT               65535

#if FIREWALL_IPFW
  #define RCHK_MAX_IPFW_START_RULE_NUM      65535
  #define RCHK_MAX_IPFW_MAX_RULES           10000
  #define RCHK_MAX_IPFW_SET_NUM             31
  #define RCHK_MAX_IPFW_PURGE_INTERVAL      65535
#elif FIREWALL_PF
  #define RCHK_MAX_PF_EXPIRE_INTERVAL       65535
#endif

/* Function Prototypes
*/
void config_init(fko_srv_options_t *opts, int argc, char **argv);
void dump_config(const fko_srv_options_t *opts);
void clear_configs(fko_srv_options_t *opts);
void free_configs(fko_srv_options_t *opts);
void usage(void);

#endif /* CONFIG_INIT_H */

/***EOF***/
