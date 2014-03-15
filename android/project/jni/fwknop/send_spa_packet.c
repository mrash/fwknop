/*
 *****************************************************************************
 *
 * File:    send_spa_packet.c
 *
 * Purpose: Function to send a SPA data packet out onto the network.
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2014 fwknop developers and contributors. For a full
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
#include "fwknop_client.h"

#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* Send the SPA data via UDP packet.
*/
int
send_spa_packet(fwknop_options_t *options)
{
    int     sock, res=0, sd_len, error;
    struct  addrinfo *result, *rp, hints;
    char    port_str[MAX_PORT_STR_LEN];

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_family   = AF_UNSPEC; /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    sprintf(port_str, "%d", options->spa_dst_port);

    error = getaddrinfo(options->spa_server_str, port_str, &hints, &result);

    if (error != 0)
    {
        LOGV("Error in getaddrinfo: %s\n", gai_strerror(error));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype,
                rp->ai_protocol);
        if (sock < 0)
            continue;

        if ((error = (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1)))
            break;  /* made it */

        close(sock);
    }

    if (rp == NULL)
    {
        LOGV("Error: Unable to create socket.");
        return -1;
    }

    freeaddrinfo(result);

    sd_len = strlen(options->spa_data);

    res = send(sock, options->spa_data, sd_len, 0);

    if(res < 0)
        LOGV("send_spa_packet: write error: ");
    else if(res != sd_len)
        LOGV("Warning: bytes sent (%i) not spa data length (%i).\n",
            res, sd_len
        );

    close(sock);

    return(res);
}

/***EOF***/
