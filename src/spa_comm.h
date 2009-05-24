/*
 *****************************************************************************
 *
 * File:    spa_comm.h
 *
 * Author:  Damien Stuart (dstuart@dstuart.org)
 *
 * Purpose: Header file for fwknop client test program.
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
 *****************************************************************************
*/
#ifndef SPA_COMM_H
#define SPA_COMM_H

#include "fwknop_common.h"

#ifdef WIN32
  #include <winsock2.h>

  #define unlink _unlink
#else
  #if HAVE_SYS_SOCKET_H
    #include <sys/socket.h>
  #endif
#endif

/* Prototypes
*/
int send_spa_packet(fko_ctx_t ctx, fko_cli_options_t *options);
int write_spa_packet_data(fko_ctx_t ctx, fko_cli_options_t *options);

#endif  /* SPA_COMM_H */
