/*
 ******************************************************************************
 *
 * File:    fwknop_common.h
 *
 * Author:  Damien Stuart
 *
 * Purpose: Header file for fwknop config_init.
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
#ifndef FWKNOP_COMMON_H
#define FWKNOP_COMMON_H

/* Common includes for our other fwknop client source files.
*/
#if HAVE_CONFIG_H
  #include "config.h"
#endif

#include <stdio.h>
#include <sys/types.h>

#include <errno.h>

#if STDC_HEADERS
  #include <stdlib.h>
  #include <string.h>
#elif HAVE_STRINGS_H
  #include <strings.h>
#endif /* STDC_HEADERS*/

#if HAVE_UNISTD_H
  #include <unistd.h>
#endif

#if HAVE_NETINET_IN_H
  #include <netinet/in.h>
#endif

#ifdef WIN32
  #define strncasecmp	_strnicmp
  #define snprintf		_snprintf
  #define unlink		_unlink
#else
  #include <signal.h>
#endif

#include "fko.h"

/* My Name and Version
*/
#define MY_NAME     "fwknop"
#define MY_DESC     "Single Packet Authorization client"

#define FKO_PROTO_VERSION  "1.9.12"

/* Get our program version from VERSION (defined in config.h).
*/
#define MY_VERSION VERSION

/* Default config path, can override with -c
*/
#define DEF_CONFIG_FILE MY_NAME".conf"

/* Protocol assignment values
*/
enum {
    FKO_PROTO_UDP,
    FKO_PROTO_TCP,
    FKO_PROTO_TCP_RAW,
    FKO_PROTO_ICMP,
    FKO_PROTO_HTTP,
};

/* Other common defines
*/
#define FKO_DEFAULT_PROTO FKO_PROTO_UDP
#define FKO_DEFAULT_PORT 62201
#define FKO_DEFAULT_PORT_STR "62201"
#define MAX_PORT_STR_LEN 6
#define MAX_IP_STR_LEN 16
#define MAX_SERVER_STR_LEN 50

#define MAX_LINE_LEN        1024
#define MAX_PATH_LEN        1024
#define MAX_GPG_KEY_ID      128
#define MAX_USERNAME_LEN    30

/* fwkop client configuration parameters and values
*/
typedef struct fko_cli_options
{
    char config_file[MAX_PATH_LEN];
    char access_str[MAX_PATH_LEN];
    char get_key_file[MAX_LINE_LEN];
    char save_packet_file[MAX_LINE_LEN];
    int  save_packet_file_append;
    char spa_server_str[MAX_SERVER_STR_LEN];  /* may be a hostname */
    char allow_ip_str[MAX_IP_STR_LEN];
    char spoof_ip_src_str[MAX_IP_STR_LEN];
    char spoof_user[MAX_USERNAME_LEN];
    char gpg_recipient_key[MAX_GPG_KEY_ID];
    char gpg_signer_key[MAX_GPG_KEY_ID];
    char gpg_home_dir[MAX_PATH_LEN];

    int spa_proto;
    unsigned int spa_dst_port;
    char spa_dst_port_str[MAX_PORT_STR_LEN];
    unsigned int spa_src_port; /* only used with --source-port */
    char spa_src_port_str[MAX_PORT_STR_LEN];  /* --source-port */

    unsigned int digest_type;

    /* Various command-line flags */
    unsigned char   quiet;   /* --quiet mode */
    unsigned char   verbose; /* --verbose mode */
    unsigned char   version; /* --version */
    unsigned char   no_save;
    unsigned char   test;
    unsigned char   use_gpg;
    unsigned char   use_gpg_agent;

    //char            config_file[MAX_PATH_LEN];

} fko_cli_options_t;

extern fko_cli_options_t options;

#endif /* FWKNOP_COMMON_H */

/***EOF***/
