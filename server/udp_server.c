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
#include "sig_handler.h"
#include "incoming_spa.h"
#include "log_msg.h"
#include "fw_util.h"
#include "cmd_cycle.h"
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
    int                 rv=1, chk_rm_all=0;
    fd_set              sfd_set;
    struct sockaddr_in  saddr, caddr;
    struct timeval      tv;
    char                sipbuf[MAX_IPV4_STR_LEN] = {0};
    char                dgram_msg[MAX_SPA_PACKET_LEN+1] = {0};
    socklen_t           clen;

    log_msg(LOG_INFO, "Kicking off UDP server to listen on port %i.",
            opts->udpserv_port);

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
    memset(&saddr, 0x0, sizeof(saddr));
    saddr.sin_family      = AF_INET;           /* Internet address family */
    saddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
    saddr.sin_port        = htons(opts->udpserv_port); /* Local port */

    /* Bind to the local address */
    if (bind(s_sock, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
    {
        log_msg(LOG_ERR, "run_udp_server: bind() failed: %s",
            strerror(errno));
        close(s_sock);
        return -1;
    }

    /* Initialize our signal handlers. You can check the return value for
     * the number of signals that were *not* set.  Those that were not set
     * will be listed in the log/stderr output.
    */
    if(set_sig_handlers() > 0)
        log_msg(LOG_ERR, "Errors encountered when setting signal handlers.");

    FD_ZERO(&sfd_set);

    /* Now loop and receive SPA packets
    */
    while(1)
    {
        if(sig_do_stop())
        {
            if(opts->verbose)
                log_msg(LOG_INFO,
                        "udp_server: terminating signal received, will stop.");
            break;
        }

        if(!opts->test)
        {
            /* Check for any expired firewall rules and deal with them.
            */
            if(opts->enable_fw)
            {
                if(opts->rules_chk_threshold > 0)
                {
                    opts->check_rules_ctr++;
                    if ((opts->check_rules_ctr % opts->rules_chk_threshold) == 0)
                    {
                        chk_rm_all = 1;
                        opts->check_rules_ctr = 0;
                    }
                }
                check_firewall_rules(opts, chk_rm_all);
                chk_rm_all = 0;
            }

            /* See if any CMD_CYCLE_CLOSE commands need to be executed.
            */
            cmd_cycle_close(opts);
        }

        /* Initialize and setup the socket for select.
        */
        FD_SET(s_sock, &sfd_set);

        /* Set our select timeout to (500ms by default).
        */
        tv.tv_sec = 0;
        tv.tv_usec = opts->udpserv_select_timeout;

        selval = select(s_sock+1, &sfd_set, NULL, NULL, &tv);

        if(selval == -1)
        {
            if(errno == EINTR)
            {
                /* restart loop but only after we check for a terminating
                 * signal above in sig_do_stop()
                */
                continue;
            }
            else
            {
                log_msg(LOG_ERR, "run_udp_server: select error socket: %s",
                    strerror(errno));
                rv = -1;
                break;
            }
        }

        if(selval == 0)
            continue;

        if(! FD_ISSET(s_sock, &sfd_set))
            continue;

        /* If we make it here then there is a datagram to process
        */
        clen = sizeof(caddr);

        pkt_len = recvfrom(s_sock, dgram_msg, MAX_SPA_PACKET_LEN,
                0, (struct sockaddr *)&caddr, &clen);

        dgram_msg[pkt_len] = 0x0;

        if(opts->verbose)
        {
            memset(sipbuf, 0x0, MAX_IPV4_STR_LEN);
            inet_ntop(AF_INET, &(caddr.sin_addr.s_addr), sipbuf, MAX_IPV4_STR_LEN);
            log_msg(LOG_INFO, "udp_server: Got UDP datagram (%d bytes) from: %s",
                    pkt_len, sipbuf);
        }

        /* Expect the data to not be too large
        */
        if(pkt_len <= MAX_SPA_PACKET_LEN)
        {
            /* Copy the packet for SPA processing
            */
            strlcpy((char *)opts->spa_pkt.packet_data, dgram_msg, pkt_len+1);
            opts->spa_pkt.packet_data_len = pkt_len;
            opts->spa_pkt.packet_proto    = IPPROTO_UDP;
            opts->spa_pkt.packet_src_ip   = caddr.sin_addr.s_addr;
            opts->spa_pkt.packet_dst_ip   = saddr.sin_addr.s_addr;
            opts->spa_pkt.packet_src_port = ntohs(caddr.sin_port);
            opts->spa_pkt.packet_dst_port = ntohs(saddr.sin_port);

            incoming_spa(opts);
        }

        memset(dgram_msg, 0x0, sizeof(dgram_msg));

        opts->packet_ctr += 1;
        if(opts->foreground == 1 && opts->verbose > 2)
            log_msg(LOG_DEBUG, "run_udp_server() processed: %d packets",
                    opts->packet_ctr);

        if (opts->packet_ctr_limit && opts->packet_ctr >= opts->packet_ctr_limit)
        {
            log_msg(LOG_WARNING,
                "* Incoming packet count limit of %i reached",
                opts->packet_ctr_limit
            );
            break;
        }

    } /* infinite while loop */

    close(s_sock);
    return rv;
}

/***EOF***/
