/*
 *****************************************************************************
 *
 * File:    tcp_server.c
 *
 * Purpose: Spawns off a dummy tcp server for fwknopd.  Its purpose is
 *          to accept a tcp connection, then drop it after the first packet.
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2014 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
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
#include "fwknopd_common.h"
#include "tcp_server.h"
#include "log_msg.h"
#include "utils.h"
#include <errno.h>

#if HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
#endif
#if HAVE_ARPA_INET_H
  #include <arpa/inet.h>
#endif
#if HAVE_NETDB
  #include <netdb.h>
#endif

#include <fcntl.h>
#include <sys/select.h>

/* Fork off and run a "dummy" TCP server. The return value is the PID of
 * the child process or -1 if there is a fork error.
*/
int
run_tcp_server(fko_srv_options_t *opts)
{
#if !FUZZING_INTERFACES
    pid_t               pid, ppid;
#endif
    int                 s_sock, c_sock, sfd_flags, clen, selval;
    int                 reuse_addr = 1, is_err;
    fd_set              sfd_set;
    struct sockaddr_in  saddr, caddr;
    struct timeval      tv;
    char                sipbuf[MAX_IPV4_STR_LEN] = {0};

    unsigned short      port;

    port = strtol_wrapper(opts->config[CONF_TCPSERV_PORT],
            1, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] Invalid max TCPSERV_PORT value.");
        return -1;
    }
    log_msg(LOG_INFO, "Kicking off TCP server to listen on port %i.", port);

#if !FUZZING_INTERFACES
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

    /* Get our parent PID so we can periodically check for it. We want to
     * know when it goes away so we can too.
    */
    ppid = getppid();

    /* We are the child.  The first thing to do is close our copy of the
     * parent PID file so we don't end up holding the lock if the parent
     * suffers a sudden death that doesn't take us out too.
    */
    close(opts->lock_fd);
#endif

    /* Now, let's make a TCP server
    */
    if ((s_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
        log_msg(LOG_ERR, "run_tcp_server: socket() failed: %s",
            strerror(errno));
        return -1;
    }

    /* So that we can re-bind to it without TIME_WAIT problems
    */
    if(setsockopt(s_sock, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr)) == -1)
    {
        log_msg(LOG_ERR, "run_tcp_server: setsockopt error: %s",
            strerror(errno));
        close(s_sock);
        return -1;
    }

    /* Make our main socket non-blocking so we don't have to be stuck on
     * listening for incoming connections.
    */
    if((sfd_flags = fcntl(s_sock, F_GETFL, 0)) < 0)
    {
        log_msg(LOG_ERR, "run_tcp_server: fcntl F_GETFL error: %s",
            strerror(errno));
        close(s_sock);
        return -1;
    }

#if !FUZZING_INTERFACES
    sfd_flags |= O_NONBLOCK;

    if(fcntl(s_sock, F_SETFL, sfd_flags) < 0)
    {
        log_msg(LOG_ERR, "run_tcp_server: fcntl F_SETFL error setting O_NONBLOCK: %s",
            strerror(errno));
        close(s_sock);
        return -1;
    }
#endif

    /* Construct local address structure */
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family      = AF_INET;           /* Internet address family */
    saddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
    saddr.sin_port        = htons(port);       /* Local port */

    /* Bind to the local address */
    if (bind(s_sock, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
    {
        log_msg(LOG_ERR, "run_tcp_server: bind() failed: %s",
            strerror(errno));
        close(s_sock);
        return -1;
    }

    /* Mark the socket so it will listen for incoming connections
     * (but only one at a time)
    */
    if (listen(s_sock, 1) < 0)
    {
        log_msg(LOG_ERR, "run_tcp_server: listen() failed: %s",
            strerror(errno));
        close(s_sock);
        return -1;
    }

    clen = sizeof(caddr);

    /* Now loop and accept and drop connections after the first packet or a
     * short timeout.
    */
    while(1)
    {
        /* Initialize and setup the socket for select.
        */
        FD_ZERO(&sfd_set);
        FD_SET(s_sock, &sfd_set);

        /* Set our select timeout to 200 ms.
        */
        tv.tv_sec = 0;
        tv.tv_usec = 200000;

        selval = select(s_sock+1, &sfd_set, NULL, NULL, &tv);

        if(selval == -1)
        {
            /* Select error - so kill the child and bail.
            */
            log_msg(LOG_ERR, "run_tcp_server: select error socket: %s",
                strerror(errno));
            close(s_sock);
            return -1;
        }

#if !FUZZING_INTERFACES
        if(selval == 0)
        {
            /* Timeout - So we check to make sure our parent is still there by simply
             *           using kill(ppid, 0) and checking the return value.
            */
            if(kill(ppid, 0) != 0 && errno == ESRCH)
            {
                close(s_sock);
                return -1;
            }

            continue;
        }
#endif

        /* Wait for a client to connect
        */
        if((c_sock = accept(s_sock, (struct sockaddr *) &caddr, (socklen_t *)&clen)) < 0)
        {
            log_msg(LOG_ERR, "run_tcp_server: accept() failed: %s",
                strerror(errno));
            close(s_sock);
            return -1;
        }

        if(opts->verbose)
        {
            memset(sipbuf, 0x0, MAX_IPV4_STR_LEN);
            inet_ntop(AF_INET, &(caddr.sin_addr.s_addr), sipbuf, MAX_IPV4_STR_LEN);
            log_msg(LOG_INFO, "tcp_server: Got TCP connection from %s.", sipbuf);
        }

        /* Though hacky and clunky, we just sleep for a second then
         * close the socket.  No need to read or write anything.  This
         * just gives the client a sufficient window to send their
         * request on this socket. In any case the socket is closed
         * after that time.
        */
        usleep(1000000);
        shutdown(c_sock, SHUT_RDWR);
        close(c_sock);

#if FUZZING_INTERFACES
        close(s_sock);
        return 1;
#endif
    } /* infinite while loop */
    return 1;
}

/***EOF***/
