/*
 *****************************************************************************
 *
 * File:    udp_server.c
 *
 * Purpose: Collect SPA packets via a UDP server.
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
#include "incoming_spa.h"
#include "log_msg.h"
#include "fw_util.h"
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

int
run_udp_server(fko_srv_options_t *opts)
{
    int                 s_sock, sfd_flags, selval, pkt_len;
    int                 is_err;
    fd_set              sfd_set;
    struct sockaddr_in  saddr, caddr;
    struct timeval      tv;
    char                sipbuf[MAX_IPV4_STR_LEN] = {0};
    char msg[5000];
    socklen_t clen;

    unsigned short      port;

    port = strtol_wrapper(opts->config[CONF_UDPSERV_PORT],
            1, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] Invalid max UDPSERV_PORT value.");
        return -1;
    }
    log_msg(LOG_INFO, "Kicking off UDP server to listen on port %i.", port);

    /* Now, let's make a UDP server
    */
    if ((s_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        log_msg(LOG_ERR, "run_udp_server: socket() failed: %s",
            strerror(errno));
        return -1;
    }

    /* Make our main socket non-blocking so we don't have to be stuck on
     * listening for incoming datagrams.
    */
    if((sfd_flags = fcntl(s_sock, F_GETFL, 0)) < 0)
    {
        log_msg(LOG_ERR, "run_udp_server: fcntl F_GETFL error: %s",
            strerror(errno));
        close(s_sock);
        return -1;
    }

    sfd_flags |= O_NONBLOCK;

    if(fcntl(s_sock, F_SETFL, sfd_flags) < 0)
    {
        log_msg(LOG_ERR, "run_udp_server: fcntl F_SETFL error setting O_NONBLOCK: %s",
            strerror(errno));
        close(s_sock);
        return -1;
    }

    /* Construct local address structure */
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family      = AF_INET;           /* Internet address family */
    saddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
    saddr.sin_port        = htons(port);       /* Local port */

    /* Bind to the local address */
    if (bind(s_sock, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
    {
        log_msg(LOG_ERR, "run_udp_server: bind() failed: %s",
            strerror(errno));
        close(s_sock);
        return -1;
    }

    /* Now loop and receive SPA packets
    */
    while(1)
    {

        /* Check for any expired firewall rules and deal with them.
        */
        if(!opts->test)
            check_firewall_rules(opts);

        clen = sizeof(caddr);

        /* Initialize and setup the socket for select.
        */
        FD_ZERO(&sfd_set);
        FD_SET(s_sock, &sfd_set);

        /* Set our select timeout to 500 ms.
        */
        tv.tv_sec = 0;
        tv.tv_usec = 500000;

        selval = select(s_sock+1, &sfd_set, NULL, NULL, &tv);

        if(selval == -1)
        {
            /* Select error so bail
            */
            log_msg(LOG_ERR, "run_udp_server: select error socket: %s",
                strerror(errno));
            close(s_sock);
            return -1;
        }

        if(selval == 0)
            continue;

        pkt_len = recvfrom(s_sock, msg, 5000, 0, (struct sockaddr *)&caddr, &clen);

        printf("-------------------------------------------------------\n");
        msg[pkt_len] = 0;
        printf("Received %d bytes:\n", pkt_len);
        printf("%s",msg);
        printf("\n-------------------------------------------------------\n");

        if(opts->verbose)
        {
            memset(sipbuf, 0x0, MAX_IPV4_STR_LEN);
            inet_ntop(AF_INET, &(caddr.sin_addr.s_addr), sipbuf, MAX_IPV4_STR_LEN);
            log_msg(LOG_INFO, "udp_server: Got UDP connection from %s.", sipbuf);
        }

        /* Expect the data to not be too large
        */
        if(pkt_len > MAX_SPA_PACKET_LEN)
            continue;

        /* Copy the packet for SPA processing
        */
        strlcpy((char *)opts->spa_pkt.packet_data, msg, pkt_len+1);
        opts->spa_pkt.packet_data_len = pkt_len;
        opts->spa_pkt.packet_proto    = IPPROTO_UDP;
        opts->spa_pkt.packet_src_ip   = caddr.sin_addr.s_addr;
        opts->spa_pkt.packet_dst_ip   = saddr.sin_addr.s_addr;
        opts->spa_pkt.packet_src_port = ntohs(caddr.sin_port);
        opts->spa_pkt.packet_dst_port = ntohs(saddr.sin_port);

        incoming_spa(opts);

    } /* infinite while loop */

    return 1;
}

/***EOF***/
