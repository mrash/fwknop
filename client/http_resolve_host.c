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
 *****************************************************************************
*/
#include "fwknop_common.h"
#include "utils.h"

#include <errno.h>

#ifdef WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #if HAVE_SYS_SOCKET_H
    #include <sys/socket.h>
  #endif
  #include <netdb.h>
#endif

struct url
{
    char    port[MAX_PORT_STR_LEN];
    char    host[MAX_URL_HOST_LEN+1];
    char    path[MAX_URL_PATH_LEN+1];
};

static int
try_url(struct url *url, fko_cli_options_t *options)
{
    int     sock, res, error, http_buf_len, i;
    int     bytes_read = 0, position = 0;
    int     o1, o2, o3, o4;
    struct  addrinfo *result, *rp, hints;
    char    http_buf[HTTP_MAX_REQUEST_LEN];
    char    http_response[HTTP_MAX_RESPONSE_LEN] = {0};
    char   *ndx;

#ifdef WIN32
    WSADATA wsa_data;

    /* Winsock needs to be initialized...
    */
    res = WSAStartup( MAKEWORD(1,1), &wsa_data );
    if( res != 0 )
    {
        fprintf(stderr, "Winsock initialization error %d\n", res );
        return(-1);
    }
#endif

    /* Build our HTTP request to resolve the external IP (this is similar to
     * to contacting whatismyip.org, but using a different URL).
    */
    snprintf(http_buf, HTTP_MAX_REQUEST_LEN,
        "GET %s HTTP/1.0\r\nUser-Agent: %s\r\nAccept: */*\r\n"
        "Host: %s\r\nConnection: close\r\n\r\n",
        url->path,
        options->http_user_agent,
        url->host
    );

    http_buf_len = strlen(http_buf);

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_family   = AF_UNSPEC; /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    error = getaddrinfo(url->host, url->port, &hints, &result);
    if (error != 0)
    {
        fprintf(stderr, "error in getaddrinfo: %s\n", gai_strerror(error));
        return(-1);
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype,
                rp->ai_protocol);
        if (sock < 0)
            continue;

        if ((error = (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1)))
            break;  /* made it */

#ifdef WIN32
        closesocket(sock);
#else
        close(sock);
#endif
    }

    if (rp == NULL) {
        perror("resolve_ip_http: Could not create socket: ");
        return(-1);
    }

    freeaddrinfo(result);

    if(options->verbose > 1)
        printf("\nHTTP request: %s\n", http_buf);

    res = send(sock, http_buf, http_buf_len, 0);

    if(res < 0)
    {
        perror("resolve_ip_http: write error: ");
    }
    else if(res != http_buf_len)
    {
        fprintf(stderr,
            "[#] Warning: bytes sent (%i) not spa data length (%i).\n",
            res, http_buf_len
        );
    }

    do
    {
        memset(http_buf, 0x0, sizeof(http_buf));
        bytes_read = recv(sock, http_buf, sizeof(http_buf), 0);
        if ( bytes_read > 0 ) {
            if(position + bytes_read >= HTTP_MAX_RESPONSE_LEN)
                break;
            memcpy(&http_response[position], http_buf, bytes_read);
            position += bytes_read;
        }
    }
    while ( bytes_read > 0 );

    http_response[HTTP_MAX_RESPONSE_LEN-1] = '\0';

#ifdef WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    if(options->verbose > 1)
        printf("\nHTTP response: %s\n", http_response);

    /* Move to the end of the HTTP header and to the start of the content.
    */
    ndx = strstr(http_response, "\r\n\r\n");
    if(ndx == NULL)
    {
        fprintf(stderr, "Did not find the end of HTTP header.\n");
        return(-1);
    }
    ndx += 4;

    /* Walk along the content to try to find the end of the IP address.
     * Note: We are expecting the content to be just an IP address
     *       (possibly followed by whitespace or other not-digit value).
     */
    for(i=0; i<MAX_IPV4_STR_LEN; i++) {
        if(! isdigit(*(ndx+i)) && *(ndx+i) != '.')
            break;
    }

    /* Terminate at the first non-digit and non-dot.
    */
    *(ndx+i) = '\0';

    /* Now that we have what we think is an IP address string.  We make
     * sure the format and values are sane.
     */
    if((sscanf(ndx, "%u.%u.%u.%u", &o1, &o2, &o3, &o4)) == 4
            && o1 >= 0 && o1 <= 255
            && o2 >= 0 && o2 <= 255
            && o3 >= 0 && o3 <= 255
            && o4 >= 0 && o4 <= 255)
    {
        strlcpy(options->allow_ip_str, ndx, MAX_IPV4_STR_LEN);

        if(options->verbose)
            printf("\n[+] Resolved external IP (via http://%s%s) as: %s\n",
                    url->host,
                    url->path,
                    options->allow_ip_str);

        return(1);
    }
    else
    {
        fprintf(stderr, "Invalid IP (%s) in HTTP response:\n\n%s\n",
            ndx, http_response);
        return(-1);
    }
}

static int
parse_url(char *res_url, struct url* url)
{
    char *s_ndx, *e_ndx;
    int  tlen, tlen_offset, port, is_err;

    /* https is not supported.
    */
    if(strncasecmp(res_url, "https", 5) == 0)
    {
        fprintf(stderr, "[*] https is not yet supported for http-resolve-ip.\n");
        return(-1);
    }

    /* Strip off http:// portion if necessary
    */
    if(strncasecmp(res_url, "http://", 7) == 0)
        s_ndx = res_url + 7;
    else
        s_ndx = res_url;

    /* Look for a colon in case an alternate port was specified.
    */
    e_ndx = strchr(s_ndx, ':');
    if(e_ndx != NULL)
    {
        port = strtol_wrapper(e_ndx+1, 1, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
        if(is_err != FKO_SUCCESS)
        {
            fprintf(stderr,
                "[*] resolve-url port value is invalid, must be in [%d-%d]\n",
                1, MAX_PORT);
            return(-1);
        }

        sprintf(url->port, "%u", port);

        /* Get the offset we need to skip the port portion when we
         * extract the hostname part.
        */
        tlen_offset = strlen(url->port)+1;
    }
    else
    {
        strlcpy(url->port, "80", 3);
        tlen_offset = 0;
    }

    /* Get rid of any trailing slash
    */
    if(res_url[strlen(res_url)-1] == '/')
        res_url[strlen(res_url)-1] = '\0';

    e_ndx = strchr(s_ndx, '/');
    if(e_ndx == NULL)
        tlen = strlen(s_ndx)+1;
    else
        tlen = (e_ndx-s_ndx)+1;

    tlen -= tlen_offset;

    if(tlen > MAX_URL_HOST_LEN)
    {
        fprintf(stderr, "resolve-url hostname portion is too large.\n");
        return(-1);
    }
    strlcpy(url->host, s_ndx, tlen);

    if(e_ndx != NULL)
    {
        if(strlen(e_ndx) > MAX_URL_PATH_LEN)
        {
            fprintf(stderr, "resolve-url path portion is too large.\n");
            return(-1);
        }

        strlcpy(url->path, e_ndx, MAX_URL_PATH_LEN);
    }
    else
    {
        /* default to "GET /" if there isn't a more specific URL
        */
        strlcpy(url->path, "/", MAX_URL_PATH_LEN);
    }

    return(0);
}

int
resolve_ip_http(fko_cli_options_t *options)
{
    int     res;
    struct  url url;

    if(options->resolve_url != NULL)
    {
        if(parse_url(options->resolve_url, &url) < 0)
        {
            fprintf(stderr, "Error parsing resolve-url\n");
            return(-1);
        }

        res = try_url(&url, options);

    } else {
        strlcpy(url.port, "80", 3);
        strlcpy(url.host, HTTP_RESOLVE_HOST, MAX_URL_HOST_LEN);
        strlcpy(url.path, HTTP_RESOLVE_URL, MAX_URL_PATH_LEN);

        res = try_url(&url, options);
        if(res != 1)
        {
            /* try the backup url (just switches the host to cipherdyne.com)
            */
            strlcpy(url.host, HTTP_BACKUP_RESOLVE_HOST, MAX_URL_HOST_LEN);

#ifndef WIN32
            sleep(2);
#endif
            res = try_url(&url, options);
        }
    }
    return(res);
}

/***EOF***/
