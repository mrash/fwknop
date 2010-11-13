/* $Id$
 ******************************************************************************
 *
 * File:    fwknop_common.h
 *
 * Author:  Damien Stuart
 *
 * Purpose: Header file for fwknop config_init.
 *
 * Copyright 2009-2010 Damien Stuart (dstuart@dstuart.org)
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
#ifndef FWKNOP_COMMON_H
#define FWKNOP_COMMON_H

#include "common.h"

/* My Name and Version
*/
#define MY_NAME     "fwknop"
#define MY_DESC     "Single Packet Authorization client"

/* Get our program version from VERSION (defined in config.h).
*/
#define MY_VERSION VERSION

/* Default config path, can override with -c
*/
#define DEF_CONFIG_FILE MY_NAME".conf"

/* For time offset handling
*/
#define MAX_TIME_STR_LEN        9
#define TIME_OFFSET_SECONDS     1
#define TIME_OFFSET_MINUTES     60
#define TIME_OFFSET_HOURS       3600
#define TIME_OFFSET_DAYS        86400

/* For resolving the allow IP via HTTP and sending SPA packets over
 * HTTP -  http://www.whatismyip.com/automation/n09230945.asp 
    #define HTTP_RESOLVE_HOST          "www.whatismyip.com"
    #define HTTP_RESOLVE_URL           "/automation/n09230945.asp"
  * --DSS Note: The whatismyip.com site has some usage restrictions.
  *             so we will make the default run on cipherdyne website
  *             for now.
*/
#define HTTP_RESOLVE_HOST          "www.cipherdyne.org"
#define HTTP_RESOLVE_URL           "/cgi-bin/myip"
#define HTTP_MAX_REQUEST_LEN       2000
#define HTTP_MAX_RESPONSE_LEN      2000
#define HTTP_MAX_USER_AGENT_LEN    50
#define MAX_HOSTNAME_LEN           70

/* fwknop client configuration parameters and values
*/
typedef struct fko_cli_options
{
    char config_file[MAX_PATH_LEN];
    char access_str[MAX_PATH_LEN];
    char server_command[MAX_LINE_LEN];
    char get_key_file[MAX_PATH_LEN];
    char save_packet_file[MAX_PATH_LEN];
    int  save_packet_file_append;
    int  show_last_command;
    int  run_last_command;
    int  no_save_args;
    char spa_server_str[MAX_SERVER_STR_LEN];  /* may be a hostname */
    char allow_ip_str[MAX_IP_STR_LEN];
    char spoof_ip_src_str[MAX_IP_STR_LEN];
    char spoof_user[MAX_USERNAME_LEN];
    int  rand_port;
    char gpg_recipient_key[MAX_GPG_KEY_ID];
    char gpg_signer_key[MAX_GPG_KEY_ID];
    char gpg_home_dir[MAX_PATH_LEN];

    /* NAT access
    */
    char nat_access_str[MAX_PATH_LEN];
    int  nat_local;
    int  nat_port;
    int  nat_rand_port;

    /* External IP resolution via HTTP
    */
    int  resolve_ip_http;
    char http_user_agent[HTTP_MAX_USER_AGENT_LEN];

    /* HTTP proxy support
    */
    char http_proxy[HTTP_MAX_REQUEST_LEN];

    /* SPA packet transmission port and protocol
    */
    int spa_proto;
    unsigned int spa_dst_port;
    unsigned int spa_src_port; /* only used with --source-port */

    unsigned int digest_type;

    /* Various command-line flags */
    unsigned char   verbose; /* --verbose mode */
    unsigned char   version; /* --version */
    unsigned char   test;
    unsigned char   use_gpg;
    unsigned char   use_gpg_agent;
    int             time_offset_plus;
    int             time_offset_minus;
    int             fw_timeout;

    char            use_rc_stanza[MAX_LINE_LEN];
    unsigned char   got_named_stanza;

    //char            config_file[MAX_PATH_LEN];

} fko_cli_options_t;

extern fko_cli_options_t options;

#endif /* FWKNOP_COMMON_H */

/***EOF***/
