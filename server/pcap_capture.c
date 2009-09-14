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

/* The pcap capture routine.
*/
int
pcap_capture(fko_srv_options_t *opts)
{
#if HAVE_LIBPCAP
    pcap_t              *pcap;

    char                errstr[PCAP_ERRBUF_SIZE] = {0};
    struct bpf_program  fp;

    int                 res, pcap_errcnt = 0;;

    pcap = pcap_open_live(
        opts->config[CONF_PCAP_INTF],
        atoi(opts->config[CONF_MAX_SNIFF_BYTES]),
        1, 500, errstr
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
    if (opts->config[CONF_PCAP_FILTER][0] != '\0')
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

    /* Jump into our home-grown packet cature loop.
    */
    while(1)
    {
        res = pcap_dispatch(pcap, 1, (pcap_handler)&process_packet, (unsigned char *)opts);

        /* If there was a packet and it was processed without error, then
         * keep going.
        */
        if(res > 0 && opts->packet_data_len > 0)
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

            if(pcap_errcnt++ > 100) /* --DSS XXX: Shoudl do this better */
            {
                fprintf(stderr, "[*] %i consecutive pcap errors.  Giving up\n",
                    pcap_errcnt
                );
                exit(EXIT_FAILURE);
            }
        }
        else if(res == -2)
        {
            /* pcap_break_loop was called, so we bail. */
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
    return(0);
}

/***EOF***/
