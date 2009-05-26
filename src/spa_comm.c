/* $Id$
 *****************************************************************************
 *
 * File:    spa_comm.c
 *
 * Author:  Damien S. Stuart (dstuart@dstuart.org)
 *          Michael Rash (mbr@cipherdyne.org)
 *
 * Purpose: Network-related functions for the fwknop client
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
#include "spa_comm.h"

/* Function to generate a header checksum.
*/
unsigned short
chksum(unsigned short *buf, int nbytes)
{
	unsigned int   sum;
	unsigned short oddbyte;

	sum = 0;
	while (nbytes > 1) {
		sum += *buf++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		oddbyte = 0;
		*((unsigned short *) &oddbyte) = *(unsigned short *) buf;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (unsigned short) ~sum;
}

/* Send the SPA data via UDP packet.
*/
int
send_spa_packet_udp(fko_ctx_t ctx, struct sockaddr_in *saddr,
    struct sockaddr_in *daddr, fko_cli_options_t *options)
{
    int res;
    char *spa_data;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        fprintf(stderr, "[*] Could not create UDP socket.\n");
        return(0);
    }

    res = fko_get_spa_data(ctx, &spa_data);

    if(res != FKO_SUCCESS)
    {
        fprintf(stderr,
            "send_spa_packet_udp: Error #%i from fko_get_spa_data: %s\n",
            res, fko_errstr(res)
        );
        return(0);
    }

    return(sendto(sock, spa_data, strlen(spa_data), 0,
        (struct sockaddr *)daddr, sizeof(*daddr)));
}

/* Send the SPA data via TCP packet.
*/
int
send_spa_packet_tcp(fko_ctx_t ctx, struct sockaddr_in *saddr,
    struct sockaddr_in *daddr, fko_cli_options_t *options)
{
    int  res;
    char pkt_data[2048] = {0}; /* Should be enough for our purposes */
    char *spa_data;
    int  sd_len;

    struct iphdr  *iph  = (struct iphdr *) pkt_data;
    struct tcphdr *tcph = (struct tcphdr *) (pkt_data + sizeof (struct iphdr));

    int hdrlen = sizeof(struct iphdr) + sizeof(struct tcphdr);

    char one   = 1;

    int sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);

    if (sock < 0) {
        fprintf(stderr, "[*] Could not create UDP socket. Error = %i\n", errno);
        return(0);
    }

    res = fko_get_spa_data(ctx, &spa_data);

    if(res != FKO_SUCCESS)
    {
        fprintf(stderr,
            "send_spa_packet_tcp: Error #%i from fko_get_spa_data: %s\n",
            res, fko_errstr(res)
        );
        return(0);
    }

    sd_len = strlen(spa_data);

    /* Put the spa data in place.
    */
    memcpy((pkt_data + hdrlen), spa_data, sd_len);

    /* Construct our own header by filling in the ip/tcp header values,
     * starting with the IP header values.
    */
    iph->ihl        = 5;
    iph->version    = 4;
    iph->tos        = 0;
    /* Total size is header plus payload */
    iph->tot_len    = hdrlen + sd_len;
    /* The value here does not matter */
    iph->id         = random() & 0xffff;
    iph->frag_off   = 0;
    iph->ttl        = 255;
    iph->protocol   = IPPROTO_TCP;
    iph->check      = 0;
    iph->saddr      = saddr->sin_addr.s_addr;
    iph->daddr      = daddr->sin_addr.s_addr;

    /* Now the TCP header values.
    */
    tcph->source    = saddr->sin_port;
    tcph->dest      = daddr->sin_port;
    tcph->seq       = htonl(1);
    tcph->ack_seq   = 0;
    tcph->doff      = 5;
    tcph->res1      = 0;
    /* TCP flags */
    tcph->fin       = 0;
    tcph->syn       = 1;
    tcph->rst       = 0;
    tcph->psh       = 0;
    tcph->ack       = 0;
    tcph->urg       = 0;

    tcph->res2      = 0;
    tcph->window    = htons(32767);
    tcph->check     = 0;
    tcph->urg_ptr   = 0;

    /* No we can compute our checksum.
    */
    iph->check = chksum((unsigned short *)pkt_data, iph->tot_len);

    /* Make sure the kernel knows the header is included in the data so it
     * doesn't try to insert its own header into the packet.
    */
    if ((res = setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) < 0)
        fprintf (stderr, "[*] send_spa_packet_tcp: setsockopt: error %i - Cannot set HDRINCL!\n", errno);

    return(sendto (sock, pkt_data, iph->tot_len, 0,
        (struct sockaddr *)daddr, sizeof(*daddr)));
}

/* Send the SPA data via ICMP packet.
*/
int
send_spa_packet_icmp(fko_ctx_t ctx, struct sockaddr_in *saddr,
    struct sockaddr_in *daddr, fko_cli_options_t *options)
{
    int res;
    char pkt_data[2048] = {0};
    char *spa_data;
    int  sd_len;

    struct iphdr  *iph    = (struct iphdr *) pkt_data;
    struct icmphdr *icmph = (struct icmphdr *) (pkt_data + sizeof (struct iphdr));

    int hdrlen = sizeof(struct iphdr) + sizeof(struct icmphdr);

    char one   = 1;

    int sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);

    if (sock < 0) {
        fprintf(stderr, "[*] Could not create UDP socket. Error = %i\n", errno);
        return(0);
    }

    res = fko_get_spa_data(ctx, &spa_data);

    if(res != FKO_SUCCESS)
    {
        fprintf(stderr,
            "send_spa_packet_tcp: Error #%i from fko_get_spa_data: %s\n",
            res, fko_errstr(res)
        );
        return(0);
    }

    sd_len = strlen(spa_data);

    /* Put the spa data in place.
    */
    memcpy((pkt_data + hdrlen), spa_data, sd_len);

    /* Construct our own header by filling in the ip/icmp header values,
     * starting with the IP header values.
    */
    iph->ihl        = 5;
    iph->version    = 4;
    iph->tos        = 0;
    /* Total size is header plus payload */
    iph->tot_len    = hdrlen + sd_len;
    /* The value here does not matter */
    iph->id         = random() & 0xffff;
    iph->frag_off   = 0;
    iph->ttl        = 255;
    iph->protocol   = IPPROTO_ICMP;
    iph->check      = 0;
    iph->saddr      = saddr->sin_addr.s_addr;
    iph->daddr      = daddr->sin_addr.s_addr;

    /* Now the ICMP header values.
    */
    icmph->type     = ICMP_ECHOREPLY; /* Make it an echo reply */
    icmph->code     = 0;
    icmph->checksum = 0;

    /* No we can compute our checksum.
    */
    iph->check = chksum((unsigned short *)pkt_data, iph->tot_len);
    icmph->checksum = chksum((unsigned short *)icmph, sizeof(struct icmphdr) + sd_len);

    /* Make sure the kernel knows the header is included in the data so it
     * doesn't try to insert its own header into the packet.
    */
    if ((res = setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) < 0)
        fprintf (stderr, "[*] send_spa_packet_tcp: setsockopt: error %i - Cannot set HDRINCL!\n", errno);

    return(sendto (sock, pkt_data, iph->tot_len, 0,
        (struct sockaddr *)daddr, sizeof(*daddr)));
}

/* Function used to send the SPA data.
*/
int
send_spa_packet(fko_ctx_t ctx, fko_cli_options_t *options)
{
    int rv = 0;
    struct sockaddr_in saddr, daddr;

#ifdef WIN32
    WSADATA wsa_data;

    rv = WSAStartup( MAKEWORD(1,1), &wsa_data );
    if( rv != 0 )
    {
        fprintf(stderr, "[*] Winsock initialization error %d\n", rv );
        return(0);
    }
#endif

    /* initialize to zeros
    */
    memset(&saddr, 0, sizeof(saddr));
    memset(&daddr, 0, sizeof(daddr));

    saddr.sin_family = AF_INET;
    daddr.sin_family = AF_INET;

    /* set source address and port
    */
    if (options->src_port)
        saddr.sin_port = htons(options->src_port);
    else
        saddr.sin_port = INADDR_ANY;  /* default */

    if (options->spoof_ip_src_str[0] != 0x00)
        saddr.sin_addr.s_addr = inet_addr(options->spoof_ip_src_str);
    else
        saddr.sin_addr.s_addr = INADDR_ANY;  /* default */

    /* set destination address and port */
    daddr.sin_port = htons(options->port);
    daddr.sin_addr.s_addr = inet_addr(options->spa_server_ip_str);

    if (options->proto == IPPROTO_UDP)
        rv = send_spa_packet_udp(ctx, &saddr, &daddr, options);
    else if (options->proto == IPPROTO_TCP)
        rv = send_spa_packet_tcp(ctx, &saddr, &daddr, options);
    else if (options->proto == IPPROTO_ICMP)
        rv = send_spa_packet_icmp(ctx, &saddr, &daddr, options);

    return rv;
}

/* Function to write SPA packet data to the filesystem
*/
int write_spa_packet_data(fko_ctx_t ctx, fko_cli_options_t *options)
{
    FILE   *fp;
    char   *spa_data;
    int     res;

    if (options->save_packet_file_append) {
        if((fp = fopen(options->save_packet_file, "a")) == NULL) {
            return 0;
        }
    } else {
        unlink(options->save_packet_file);
        if((fp = fopen(options->save_packet_file, "w")) == NULL) {
            return 0;
        }
    }

    res = fko_get_spa_data(ctx, &spa_data);

    if(res != FKO_SUCCESS)
    {
        fprintf(stderr,
            "write_spa_packet_data: Error #%i from fko_get_spa_data: %s\n",
            res, fko_errstr(res)
        );
        exit(1);
    }

    fprintf(fp, "%s\n",
        (spa_data == NULL) ? "<NULL>" : spa_data);

    fclose(fp);

    return 1;
}

/***EOF***/
