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
  #define DEF_CONF_DIR      "/etc/fwknop"
#endif
#define DEF_CONFIG_FILE     DEF_CONF_DIR"/"MY_NAME".conf"
#define DEF_INTERFACE       "eth0"

/* fwknopd-specific limits
*/
#define MAX_PCAP_FILTER_LEN 1024
#define MAX_IFNAME_LEN      128

/* fwknopd server configuration parameters and values
*/
typedef struct fko_srv_options
{
    /* Various command-line options and flags
    */
    char config_file[MAX_PATH_LEN];     /* The main fwknopd config file */
    char firewall_log[MAX_PATH_LEN];    /* The firewall log file */
    char gpg_home_dir[MAX_PATH_LEN];    /* GPG Home directory */
    char gpg_key[MAX_GPG_KEY_ID];       /* The gpg key id for decrypting */
    char net_interface[MAX_IFNAME_LEN]; /* Network interface to sniff */
    char override_config[MAX_PATH_LEN]; /* One of more overried config files */

    unsigned char   dump_config;        /* Dump current configuration flag */
    unsigned char   restart;            /* Restart fwknopd flag*/
    unsigned char   verbose;            /* Verbose mode flag */
    unsigned char   test;               /* Test mode flag */

    /* Options from the config file only.
    */


} fko_srv_options_t;

extern fko_srv_options_t options;

#endif /* FWKNOPD_COMMON_H */

/***EOF***/
