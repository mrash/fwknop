/**
 * \file server/nfq_capture.c
 *
 * \brief Capture routine for fwknopd that uses libnetfilter_queue.
 */

/*
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
#include <errno.h>

#include "fwknopd_common.h"
#include "nfq_capture.h"
#include "process_packet.h"
#include "sig_handler.h"
#include "fw_util.h"
#include "log_msg.h"
#include "fwknopd_errors.h"
#include "sig_handler.h"
#include "tcp_server.h"
#include <fcntl.h>
#if HAVE_SYS_WAIT_H
  #include <sys/wait.h>
#endif

#include <limits.h>
#include <linux/netfilter_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

static int process_nfq_packet(struct nfq_q_handle *qh,
        struct nfgenmsg *nfmsg,
        struct nfq_data *nfa,
        void *data)
{
    struct nfqnl_msg_packet_hdr *ph;
    int pkt_len = 0;
    int verdict;
    unsigned char *full_packet;
    fko_srv_options_t   *opts = (fko_srv_options_t *)data;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {

        /* --DSS for ref
          id = ntohl(ph->packet_id);
          hook = ph->hook;
          hw_proto = ph->protocol;
        */

        /* Retrieve packet payload
        */
        pkt_len = nfq_get_payload(nfa, &full_packet);

        process_packet(opts, pkt_len, full_packet);

        /* Verdict on what to do with the packet.  If it is coming from
         * the INPUT chain (NF_IP_LOCAL_IN), then it is assumed to be
         * a spa packet and can be dropped. Otherwise, let it through.
        */
        verdict = (ph->hook == NF_IP_LOCAL_IN) ? NF_DROP : NF_ACCEPT;
        nfq_set_verdict(qh, ph->packet_id, verdict, 0, NULL);
    }
    return 0;
}


/* The nfq capture routine.
*/
int
nfq_capture(fko_srv_options_t *opts)
{
    int                 res, child_pid, fd_flags;
    int                 nfq_errcnt = 0;
    int                 pending_break = 0;
    int                 status;
    char                nfq_buf[1500];
    int                 chk_rm_all = 0;

    /* Netfilter-related handles
    */
    int                  nfq_fd;
    struct nfq_handle   *nfq_h;
    struct nfq_q_handle *nfq_qh;
    struct nfnl_handle  *nfq_nh;

    nfq_h = nfq_open();
    if (!nfq_h) {
        log_msg(LOG_ERR, "[*] nfq_open error\n");
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }

    /* Unbind existing nf_queue handler for AF_INET (if any)
    */
    res = nfq_unbind_pf(nfq_h, AF_INET);
    if (res < 0)  {
        log_msg(LOG_WARNING, "[*] Error during nfq_unbind_pf() error: %d\n", res);
    }

    /* Bind the given queue connection handle to process packets.
    */
    res =  nfq_bind_pf(nfq_h, AF_INET);
    if ( res < 0) {
        log_msg(LOG_ERR, "Error during nfq_bind_pf(), error: %d\n", res);
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }

    /* Create queue
    */
    nfq_qh = nfq_create_queue(nfq_h,  atoi(opts->config[CONF_NFQ_QUEUE_NUMBER]), &process_nfq_packet, opts);
    if (!nfq_qh) {
        log_msg(LOG_ERR, "Error during nfq_create_queue()\n");
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }

    /* Set the amount of data to be copied to userspace for each packet
     * queued to the given queue.
    */
    if (nfq_set_mode(nfq_qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        log_msg(LOG_ERR, "Can't set packet_copy mode\n");
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }

    /* Get the netlink handle associated with the given queue connection
     * handle. Then use it to get the file descriptor we will use for
     * receiving the queued packets
    */
    nfq_nh = nfq_nfnlh(nfq_h);
    nfq_fd = nfnl_fd(nfq_nh);

    /* Set our nfq handle nonblocking mode.
     *
    */
    if((fd_flags = fcntl(nfq_fd, F_GETFL, 0)) < 0)
    {
        log_msg(LOG_ERR, "nfq_capture: fcntl F_GETFL error: %s",
            strerror(errno));
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }

    fd_flags |= O_NONBLOCK;

    if(fcntl(nfq_fd, F_SETFL, fd_flags) < 0)
    {
        log_msg(LOG_ERR, "nfq_capture: fcntl F_SETFL error setting O_NONBLOCK: %s",
            strerror(errno));
        exit(EXIT_FAILURE);
    }

    log_msg(LOG_INFO, "Starting fwknopd main event loop.");

    /* Jump into our home-grown packet cature loop.
    */
    while(1)
    {
        /* If we got a SIGCHLD and it was the tcp server, then handle it here.
        ** XXX: --DSS Do we need this here?  I'm guessing we would not be using
        **            the TCP server in NF_QUEUE capture mode.
        */
        if(got_sigchld)
        {
            if(opts->tcp_server_pid > 0)
            {
                child_pid = waitpid(0, &status, WNOHANG);

                if(child_pid == opts->tcp_server_pid)
                {
                    if(WIFSIGNALED(status))
                        log_msg(LOG_WARNING, "TCP server got signal: %i",  WTERMSIG(status));

                    log_msg(LOG_WARNING,
                        "TCP server exited with status of %i. Attempting restart.",
                        WEXITSTATUS(status)
                    );

                    opts->tcp_server_pid = 0;

                    /* Attempt to restart tcp server ? */
                    usleep(1000000);
                    run_tcp_server(opts);
                }
            }

            got_sigchld = 0;
        }

        /* Any signal except USR1, USR2, and SIGCHLD mean break the loop.
        */
        if(got_signal != 0)
        {
            if(got_sigint || got_sigterm || got_sighup)
            {
                pending_break = 1;
            }
            else if(got_sigusr1 || got_sigusr2)
            {
                /* Not doing anything with these yet.
                */
                got_sigusr1 = got_sigusr2 = 0;
                got_signal = 0;
            }
            else
                got_signal = 0;
        }

        res = recv(nfq_fd, nfq_buf, sizeof(nfq_buf), 0);

        /* Count processed packets
        */
        if(res > 0)
        {
            nfq_handle_packet(nfq_h, nfq_buf, res);

            /* Count the set of processed packets (nfq_dispatch() return
             * value) - we use this as a comparison for --packet-limit regardless
             * of SPA packet validity at this point.
            */
            opts->packet_ctr += res;
            if (opts->packet_ctr_limit && opts->packet_ctr >= opts->packet_ctr_limit)
            {
                log_msg(LOG_WARNING,
                    "* Incoming packet count limit of %i reached",
                    opts->packet_ctr_limit
                );

                pending_break = 1;
            }
        }
        /* If there was an error, complain and go on (to an extent before
         * giving up).
        */
        else if(res < 0 && errno != EAGAIN)
        {

            log_msg(LOG_ERR, "[*] Error reading from  nfq descriptor: %s", strerror);

            if(nfq_errcnt++ > MAX_NFQ_ERRORS_BEFORE_BAIL)
            {
                log_msg(LOG_ERR, "[*] %i consecutive nfq errors.  Giving up",
                    nfq_errcnt
                );
                clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
            }

        }
        else if(pending_break == 1 || res == -2)
        {
            log_msg(LOG_INFO, "Gracefully leaving the fwknopd event loop.");
            break;
        }
        else
            nfq_errcnt = 0;

        /* Check for any expired firewall rules and deal with them.
        */
        check_firewall_rules(opts, chk_rm_all);

        usleep(atoi(opts->config[CONF_NFQ_LOOP_SLEEP]));
    }

    nfq_destroy_queue(nfq_qh);
    nfq_close(nfq_h);

    return(0);
}
/***EOF***/
