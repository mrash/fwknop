/* $Id$
 *****************************************************************************
 *
 * File:    pcap_capture.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: The pcap capture routines for fwknopd.
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
#include <pcap.h>

#include "fwknopd_common.h"
#include "pcap_capture.h"
#include "process_packet.h"
#include "incoming_spa.h"
#include "config_init.h"
#include "sig_handler.h"

/* The pcap capture routine.
*/
int
pcap_capture(fko_srv_options_t *opts)
{
#if HAVE_LIBPCAP
    pcap_t              *pcap;
    char                errstr[PCAP_ERRBUF_SIZE] = {0};
    struct bpf_program  fp;
    int                 res;
    int                 pcap_errcnt = 0;
    int                 pending_break = 0;
    int                 promisc = 1;

    /* Set non-promiscuous mode only of the ENABLE_PCAP_PROMISC is
     * explicitly set to 'N'.
    */
    if(opts->config[CONF_ENABLE_PCAP_PROMISC] != NULL
      && opts->config[CONF_ENABLE_PCAP_PROMISC][0] == 'N')
        promisc = 0;

    pcap = pcap_open_live(
        opts->config[CONF_PCAP_INTF],
        atoi(opts->config[CONF_MAX_SNIFF_BYTES]),
        promisc, 500, errstr
    );

    if(pcap == NULL)
    {
        fprintf(stderr, "* pcap_open_live error: %s\n", errstr);
        exit(EXIT_FAILURE);
    }

    /* We are only interested on seeing packets coming into the interface.
    */
    if (pcap_setdirection(pcap, PCAP_D_IN) < 0)
        fprintf(stderr, "* Warning: pcap error on setdirection\n");

    if (pcap == NULL)
    {
        fprintf(stderr, "[*] pcap error: %s\n", errstr);
        exit(EXIT_FAILURE);
    }

    /* Set pcap filters, if any. 
    */
    if (opts->config[CONF_PCAP_FILTER] != NULL
      && opts->config[CONF_PCAP_FILTER][0] != '\0')
    {
        if(pcap_compile(pcap, &fp, opts->config[CONF_PCAP_FILTER], 1, 0) == -1)
        {
            fprintf(stderr, "[*] Error compiling pcap filter: %s\n",
                pcap_geterr(pcap)
            );
            exit(EXIT_FAILURE);
        }

        if(pcap_setfilter(pcap, &fp) == -1)
        {
            fprintf(stderr, "[*] Error setting pcap filter: %s\n",
                pcap_geterr(pcap)
            );
            exit(EXIT_FAILURE);
        }

        pcap_freecode(&fp);
    }

    /* Determine and set the data link encapsulation offset.
    */
    switch(pcap_datalink(pcap)) {
        case DLT_EN10MB:
            opts->data_link_offset = 14;
            break;
        case DLT_LINUX_SLL:
            opts->data_link_offset = 16;
            break;
        case DLT_NULL:
            opts->data_link_offset = 4;
            break;
        default:
            opts->data_link_offset = 0;
            break;
    }

    /* Set our pcap handle to nonblocking mode.
    */
    if((pcap_setnonblock(pcap, 1, errstr)) == -1)
    {
        fprintf(stderr, "[*] Error setting pcap to non-blocking: %s\n",
            errstr
        );
        exit(EXIT_FAILURE);
    }

    /* Initialize our signal handlers. You can check the return value for
     * the number of signals that were *not* set.  Those that we not set
     * will be listed in the log/stderr output.
    */
    set_sig_handlers();

    /* Jump into our home-grown packet cature loop.
    */
    while(1)
    {
        /* Any signal except USR1 and USR2 mean break the loop.
        */
        if((got_signal != 0) && ((got_sigusr1 + got_sigusr2) == 0))
        {
            pcap_breakloop(pcap);
            pending_break = 1;
        }

        res = pcap_dispatch(pcap, 1, (pcap_handler)&process_packet, (unsigned char *)opts);

        /* If there was a packet and it was processed without error, then
         * keep going.
        */
        if(res > 0 && opts->spa_pkt.packet_data_len > 0)
        {
            incoming_spa(opts);

            pcap_errcnt = 0;
            continue;
        }

        /* If there was an error, complain and go on (to an extent
         * before giving up).
        */
        else if(res == -1)
        {
            fprintf(stderr, "[*] Error from pcap_dispatch: %s\n",
                pcap_geterr(pcap)
            );

            if(pcap_errcnt++ > MAX_PCAP_ERRORS_BEFORE_BAIL)
            {
                fprintf(stderr, "[*] %i consecutive pcap errors.  Giving up\n",
                    pcap_errcnt
                );
                exit(EXIT_FAILURE);
            }
        }
        else if(pending_break == 1 || res == -2)
        {
            /* pcap_breakloop was called, so we bail. */
            break;
        }
        else
            pcap_errcnt = 0;

        /* Check for any expired firewall rules and deal with them.
        */
        //--DSS TODO: still need to write this part...
        //check_firewall_rules(opts);

        usleep(10000);
    }
#endif /* HAVE_LIBPCAP */

    pcap_close(pcap);

    return(0);
}

/***EOF***/
