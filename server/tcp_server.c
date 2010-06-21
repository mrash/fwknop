/* $Id$
 *****************************************************************************
 *
 * File:    tcp_server.c
 *
 * Author:  Damien Stuart (dstuart@dstuart.org)
 *
 * Purpose: Spawns off a dummy tcp server for fwknopd.  Its purpose is
 *          to accept a tcp connection, then drop it after the first packet.
 *
 * Copyright (C) 2010 Damien Stuart (dstuart@dstuart.org)
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
#include "fwknopd_common.h"
#include "tcp_server.h"
#include "log_msg.h"
#include <errno.h>

#if HAVE_SYS_SOCKET_H
    #include <sys/socket.h>
#endif
#include <netdb.h>
#include <signal.h>

static int c_sock;

/* Fork off and run a "dummy" TCP server. The return value is the PID of
 * the child process or -1 if there is a fork error.
*/
int
run_tcp_server(fko_srv_options_t *opts)
{
    pid_t               pid;
    int                 s_sock, clen;
    struct sockaddr_in  saddr, caddr;
    char                sipbuf[MAX_IP_STR_LEN];

    unsigned short      port = atoi(opts->config[CONF_TCPSERV_PORT]);

    log_msg(LOG_INFO, "Kicking off TCP server for port %i)", port);

    /* Fork off a child process to run the command and provide its outputs.
    */
    pid = fork();

    /* Non-zero pid means we are the parent or there was a fork error.
     * in either case we simply return that value to the caller.
    */
    if (pid != 0)
    {
        opts->tcp_server_pid = pid;
        return(pid);
    }

    /* We are the child, so let's make a TCP server */

    if ((s_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
        log_msg(LOG_ERR|LOG_STDERR, "run_tcp_server: socket() failed: %s",
            strerror(errno));
        exit(EXIT_FAILURE);
    }
      
    /* Construct local address structure */
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family      = AF_INET;           /* Internet address family */
    saddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
    saddr.sin_port        = htons(port);       /* Local port */

    /* Bind to the local address */
    if (bind(s_sock, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
    {
        log_msg(LOG_ERR|LOG_STDERR, "run_tcp_server: bind() failed: %s",
            strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Mark the socket so it will listen for incoming connections
     * (but only one at a time)
    */
    if (listen(s_sock, 1) < 0)
    {
        log_msg(LOG_ERR|LOG_STDERR, "run_tcp_server: listen() failed: %s",
            strerror(errno));
        exit(EXIT_FAILURE);
    }

    clen = sizeof(caddr);

    /* Now loop and accept and drop connections after the first packet or a
     * short timeout.
    */
    while(1)
    {
        /* Wait for a client to connect
        */
        if((c_sock = accept(s_sock, (struct sockaddr *) &caddr, &clen)) < 0)
        {
            log_msg(LOG_ERR|LOG_STDERR, "run_tcp_server: accept() failed: %s",
                strerror(errno));
            exit(EXIT_FAILURE); /* Should this be fatal? */
        }

        if(opts->verbose)
        {
            memset(sipbuf, 0x0, MAX_IP_STR_LEN);
            inet_ntop(AF_INET, &(caddr.sin_addr.s_addr), sipbuf, MAX_IP_STR_LEN);
            log_msg(LOG_INFO, "tcp_server: Got TCP connection from %s.", sipbuf);
        }

        /* Though hacky and clunky, we just sleep for a second then
         * close the socket.  No need to read or write anything.  This
         * just gives the client a sufficient window to send their
         * request on this socket. In any case the socket is closed
         * after that time.
        */
        usleep(1000000);

        close(c_sock);
    }
}

/***EOF***/
