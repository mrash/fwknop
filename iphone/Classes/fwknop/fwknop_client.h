/*
 *****************************************************************************
 *
 * File:    fwknop_client.h
 *
 * Purpose: Header file for fwknop_client.c fwknop client for Android.
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009–2014 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
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
#ifndef FWKNOP_CLIENT_H
#define FWKNOP_CLIENT_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>

#include "config.h"

#define FKO_DEFAULT_PORT    62201
#define MAX_PORT_STR_LEN    6
#define MAX_SERVER_STR_LEN  50
#define MSG_BUFSIZE         255


typedef u_int8_t uint8_t;
typedef u_int16_t uint16_t;
typedef u_int32_t uint32_t;

typedef struct fwknop_options
{
    char           *spa_server_str;
    unsigned int    spa_dst_port;
    char           *spa_data;
} fwknop_options_t;

/* Function Prototypes
*/
int send_spa_packet(fwknop_options_t *options);

#endif  /* FWKNOP_CLIENT_H */
