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

/* My Name and Version
*/
#define MY_NAME     "fwknopd"
#define MY_DESC     "Single Packet Authorization server"

/* Get our program version from VERSION (defined in config.h).
*/
#define MY_VERSION VERSION

/* Default config path, can override with -c
*/
#define DEF_CONFIG_FILE MY_NAME".conf"

/* fwknopd server configuration parameters and values
*/
typedef struct fko_srv_options
{
    char config_file[MAX_PATH_LEN];
    char gpg_home_dir[MAX_PATH_LEN];

    /* Various command-line flags */
    unsigned char   verbose; /* --verbose mode */
    unsigned char   version; /* --version */
    unsigned char   test;
    int             fw_timeout;

    //char            config_file[MAX_PATH_LEN];

} fko_srv_options_t;

extern fko_srv_options_t options;

#endif /* FWKNOPD_COMMON_H */

/***EOF***/
