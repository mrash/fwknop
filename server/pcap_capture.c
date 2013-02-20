/*
 *****************************************************************************
 *
 * File:    pcap_capture.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: The pcap capture routines for fwknopd.
 *
 * Copyright 2010 Damien Stuart (dstuart@dstuart.org)
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
#include <pcap.h>

#include "fwknopd_common.h"
#include "pcap_capture.h"
#include "process_packet.h"
#include "sig_handler.h"
#include "fw_util.h"
#include "log_msg.h"
#include "fwknopd_errors.h"
#include "sig_handler.h"
#include "tcp_server.h"

#if HAVE_SYS_WAIT_H
  #include <sys/wait.h>
#endif

/* The pcap capture routine.
*/
int
pcap_capture(fko_srv_options_t *opts)
{
    pcap_t              *pcap;
    char                errstr[PCAP_ERRBUF_SIZE] = {0};
    struct bpf_program  fp;
    int                 res;
    int                 pcap_errcnt = 0;
    int                 pending_break = 0;
    int                 promisc = 0;
    int                 set_direction = 1;
    int                 pcap_file_mode = 0;
    int                 status;
    int                 useconds;
    int                 pcap_dispatch_count;
    int                 max_sniff_bytes;
    int                 is_err;
    pid_t               child_pid;

#if FIREWALL_IPFW
    time_t              now;
#endif

    useconds = strtol_wrapper(opts->config[CONF_PCAP_LOOP_SLEEP],
            0, RCHK_MAX_PCAP_LOOP_SLEEP, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] invalid PCAP_LOOP_SLEEP_value\n");
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }

    max_sniff_bytes = strtol_wrapper(opts->config[CONF_MAX_SNIFF_BYTES],
            0, RCHK_MAX_SNIFF_BYTES, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] invalid MAX_SNIFF_BYTES\n");
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }

    /* Set promiscuous mode if ENABLE_PCAP_PROMISC is set to 'Y'.
    */
    if(opts->config[CONF_ENABLE_PCAP_PROMISC][0] == 'Y')
        promisc = 1;

    if(opts->config[CONF_PCAP_FILE] != NULL
            && opts->config[CONF_PCAP_FILE][0] != '\0')
        pcap_file_mode = 1;

    if(pcap_file_mode == 1) {
        log_msg(LOG_INFO, "Reading pcap file: %s",
            opts->config[CONF_PCAP_FILE]);

        pcap = pcap_open_offline(opts->config[CONF_PCAP_FILE], errstr);

        if(pcap == NULL)
        {
            log_msg(LOG_ERR, "[*] pcap_open_offline() error: %s\n",
                    errstr);
            clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
        }
    }
    else
    {
        log_msg(LOG_INFO, "Sniffing interface: %s",
            opts->config[CONF_PCAP_INTF]);

        pcap = pcap_open_live(opts->config[CONF_PCAP_INTF],
            max_sniff_bytes, promisc, 100, errstr
        );

        if(pcap == NULL)
        {
            log_msg(LOG_ERR, "[*] pcap_open_live() error: %s\n", errstr);
            clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
        }
    }

    /* Set pcap filters, if any.
    */
    if (opts->config[CONF_PCAP_FILTER][0] != '\0')
    {
        if(pcap_compile(pcap, &fp, opts->config[CONF_PCAP_FILTER], 1, 0) == -1)
        {
            log_msg(LOG_ERR, "[*] Error compiling pcap filter: %s",
                pcap_geterr(pcap)
            );
            clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
        }

        if(pcap_setfilter(pcap, &fp) == -1)
        {
            log_msg(LOG_ERR, "[*] Error setting pcap filter: %s",
                pcap_geterr(pcap)
            );
            clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
        }

        log_msg(LOG_INFO, "PCAP filter is: '%s'", opts->config[CONF_PCAP_FILTER]);

        pcap_freecode(&fp);
    }

    /* Determine and set the data link encapsulation offset.
    */
    switch(pcap_datalink(pcap)) {
        case DLT_EN10MB:
            opts->data_link_offset = 14;
            break;
#if defined(__linux__)
        case DLT_LINUX_SLL:
            opts->data_link_offset = 16;
            break;
#elif defined(__OpenBSD__)
        case DLT_LOOP:
            set_direction = 0;
            opts->data_link_offset = 4;
            break;
#endif
        case DLT_NULL:
            opts->data_link_offset = 4;
            break;
        default:
            opts->data_link_offset = 0;
            break;
    }

    /* We are only interested on seeing packets coming into the interface.
    */
    if (set_direction && (pcap_file_mode == 0)
            && (pcap_setdirection(pcap, PCAP_D_IN) < 0))
        if(opts->verbose)
            log_msg(LOG_WARNING, "[*] Warning: pcap error on setdirection: %s.",
                pcap_geterr(pcap));

    /* Set our pcap handle nonblocking mode.
     *
     * NOTE: This is simply set to 0 for now until we find a need
     *       to actually use this mode (which when set on a FreeBSD
     *       system, it silently breaks the packet capture).
    */
    if((pcap_file_mode == 0)
            && (pcap_setnonblock(pcap, DEF_PCAP_NONBLOCK, errstr)) == -1)
    {
        log_msg(LOG_ERR, "[*] Error setting pcap nonblocking to %i: %s",
            0, errstr
        );
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }

    pcap_dispatch_count = strtol_wrapper(opts->config[CONF_PCAP_DISPATCH_COUNT],
            0, RCHK_MAX_PCAP_DISPATCH_COUNT, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] invalid PCAP_DISPATCH_COUNT\n");
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }

    /* Initialize our signal handlers. You can check the return value for
     * the number of signals that were *not* set.  Those that were not set
     * will be listed in the log/stderr output.
    */
    if(set_sig_handlers() > 0)
        log_msg(LOG_ERR, "Errors encountered when setting signal handlers.");

    log_msg(LOG_INFO, "Starting fwknopd main event loop.");

    /* Jump into our home-grown packet cature loop.
    */
    while(1)
    {
        /* If we got a SIGCHLD and it was the tcp server, then handle it here.
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
                pcap_breakloop(pcap);
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

        res = pcap_dispatch(pcap, pcap_dispatch_count,
            (pcap_handler)&process_packet, (unsigned char *)opts);

        /* Count processed packets
        */
        if(res > 0)
        {
            if(opts->foreground == 1 && opts->verbose > 2)
                log_msg(LOG_INFO, "pcap_dispatch() processed: %d packets", res);

            /* Count the set of processed packets (pcap_dispatch() return
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

                pcap_breakloop(pcap);
                pending_break = 1;
            }
        }
        /* If there was an error, complain and go on (to an extent before
         * giving up).
        */
        else if(res == -1)
        {
            log_msg(LOG_ERR, "[*] Error from pcap_dispatch: %s",
                pcap_geterr(pcap)
            );

            if(pcap_errcnt++ > MAX_PCAP_ERRORS_BEFORE_BAIL)
            {
                log_msg(LOG_ERR, "[*] %i consecutive pcap errors.  Giving up",
                    pcap_errcnt
                );
                clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
            }
        }
        else if(pending_break == 1 || res == -2)
        {
            /* pcap_breakloop was called, so we bail. */
            log_msg(LOG_INFO, "Gracefully leaving the fwknopd event loop.");
            break;
        }
        else
            pcap_errcnt = 0;

        /* Check for any expired firewall rules and deal with them.
        */
        check_firewall_rules(opts);

#if FIREWALL_IPFW
        /* Purge expired rules that no longer have any corresponding
         * dynamic rules.
        */
        if(opts->fw_config->total_rules > 0)
        {
            time(&now);
            if(opts->fw_config->last_purge < (now - opts->fw_config->purge_interval))
            {
                ipfw_purge_expired_rules(opts);
                opts->fw_config->last_purge = now;
            }
        }
#endif

        usleep(useconds);
    }

    pcap_close(pcap);

    return(0);
}

/***EOF***/
