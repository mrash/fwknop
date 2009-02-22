/* $Id$
 *****************************************************************************
 *
 * File:    spa_comm.c
 *
 * Author:  Damien S. Stuart (dstuart@dstuart.org)
 *          Michael Rash (mbr@cipherdyne.org)
 *
 * Purpose: Network-related functions for the fwknop client
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
#include "spa_comm.h"
#if HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
#endif

/* Send the SPA data via UDP packet.
*/
int
send_spa_packet_udp(fko_ctx_t ctx, struct sockaddr_in *saddr,
    struct sockaddr_in *daddr, fko_cli_options_t *options)
{
    int rv = 0;
    int sock = 0;

    /* create the socket
    */
    sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        fprintf(stderr, "[*] Could not create UDP socket.\n");
        exit(1);
    }

    sendto(sock, fko_get_spa_data(ctx), strlen(fko_get_spa_data(ctx)),
            0, (struct sockaddr *)daddr, sizeof(*daddr));

    return rv;
}

/* Send the SPA data via TCP packet.
*/
int
send_spa_packet_tcp(fko_ctx_t ctx, struct sockaddr_in *saddr,
    struct sockaddr_in *daddr, fko_cli_options_t *options)
{
    int rv;
    return rv;
}

/* Send the SPA data via ICMP packet.
*/
int
send_spa_packet_icmp(fko_ctx_t ctx, fko_cli_options_t *options)
{
    int rv;
    return rv;
}

/* Function used to send the SPA data.
*/
int
send_spa_packet(fko_ctx_t ctx, fko_cli_options_t *options)
{
    int rv = 0;
    struct sockaddr_in saddr, daddr;

    /* initialize to zeros
    */
    memset(&saddr, 0, sizeof(saddr));
    memset(&daddr, 0, sizeof(daddr));

    saddr.sin_family = AF_INET;
    daddr.sin_family = AF_INET;

    /* set source address and port
    */
    if (options->src_port)
        saddr.sin_port = htons(options->src_port);
    else
        saddr.sin_port = INADDR_ANY;  /* default */

    if (options->spoof_ip_src_str[0] != 0x00)
        saddr.sin_addr.s_addr = inet_addr(options->spoof_ip_src_str);
    else
        saddr.sin_addr.s_addr = INADDR_ANY;  /* default */

    /* set destination address and port */
    daddr.sin_port = htons(options->port);
    daddr.sin_addr.s_addr = inet_addr(options->spa_server_ip_str);

    if (options->proto == IPPROTO_UDP)
        rv = send_spa_packet_udp(ctx, &saddr, &daddr, options);
    else if (options->proto == IPPROTO_TCP)
        rv = send_spa_packet_tcp(ctx, &saddr, &daddr, options);
    else if (options->proto == IPPROTO_ICMP)
        rv = send_spa_packet_icmp(ctx, options);

    return rv;
}


/***EOF***/
