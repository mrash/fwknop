/*
 *****************************************************************************
 *
 * File:    http_resolve_host.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Routine for using an http request to obtain a client's IP
 *          address as seen from the outside world.
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
#include "fwknop_common.h"
#include "utils.h"

#ifdef WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #if HAVE_SYS_SOCKET_H
    #include <sys/socket.h>
  #endif
  #include <netdb.h>
#endif

int
resolve_ip_http(fko_cli_options_t *options)
{
    int     sock, res, error, http_buf_len, i;
    struct  addrinfo *result, *rp, hints;
    char    http_buf[HTTP_MAX_REQUEST_LEN];
    char    http_response[HTTP_MAX_RESPONSE_LEN];

    /* Build our HTTP request to resolve the external IP (this is similar to
     * to contacting whatismyip.org, but using a different URL).
    */
    snprintf(http_buf, HTTP_MAX_REQUEST_LEN,
        "GET %s HTTP/1.0\r\nUser-Agent: %s\r\nAccept: */*\r\n"
        "Host: %s\r\nConnection: Keep-Alive\r\n\r\n",
        HTTP_RESOLVE_URL, options->http_user_agent, HTTP_RESOLVE_HOST
    );

    http_buf_len = strlen(http_buf);

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_family   = AF_UNSPEC; /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    error = getaddrinfo(HTTP_RESOLVE_HOST, "80", &hints, &result);
    if (error != 0)
    {
        fprintf(stderr, "[*] error in getaddrinfo: %s\n", gai_strerror(error));
        return(-1);
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype,
                rp->ai_protocol);
        if (sock < 0)
            continue;

        if (error = connect(sock, rp->ai_addr, rp->ai_addrlen) != -1)
            break;  /* made it */

#ifdef WIN32
        closesocket(sock);
#else
        close(sock);
#endif
    }

    if (rp == NULL) {
        perror("[*] resolve_ip_http: Could not create socket: ");
        return(-1);
    }

    freeaddrinfo(result);

    res = send(sock, http_buf, http_buf_len, 0);

    if(res < 0)
    {
        perror("[*] resolve_ip_http: write error: ");
    }
    else if(res != http_buf_len)
    {
        fprintf(stderr,
            "[#] Warning: bytes sent (%i) not spa data length (%i).\n",
            res, http_buf_len
        );
    }

    res = recv(sock, http_response, HTTP_MAX_RESPONSE_LEN, 0);
    http_response[HTTP_MAX_RESPONSE_LEN-1] = '\0';

#ifdef WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    /* Now parse the response for the IP address (which should be at
     * the end of the string
    */
    for (i=res-3; i >= 0; i--)
    {
        if(http_response[i] == '\n')
            break;
        if(http_response[i] != '.' && ! isdigit(http_response[i]))
        {
            fprintf(stderr, "[*] Invalid IP in HTTP response.\n");
            return(-1);
        }
    }

    if (i < MIN_IP_STR_LEN)
    {
        fprintf(stderr, "[*] Invalid IP in HTTP response.\n");
        return(-1);
    }

    http_response[res-1] = '\0';

    strlcpy(options->allow_ip_str,
        (http_response + i+1), (res - (i+2)));

    if(options->verbose)
        printf("[+] Resolved external IP (via http://%s%s) as: %s\n",
            HTTP_RESOLVE_HOST, HTTP_RESOLVE_URL, options->allow_ip_str);

    return(0);
}

/***EOF***/
