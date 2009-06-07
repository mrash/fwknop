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
    while (nbytes > 1)
    {
        sum += *buf++;
        nbytes -= 2;
    }

    if (nbytes == 1)
    {
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
send_spa_packet_udp(char *spa_data, int sd_len, struct sockaddr_in *saddr,
    struct sockaddr_in *daddr, fko_cli_options_t *options)
{
    int     sock, res;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (sock < 0)
    {
        perror("[*] send_spa_packet_udp: create socket: ");
        return(sock);
    }

    res = sendto(sock, spa_data, sd_len, 0,
        (struct sockaddr *)daddr, sizeof(*daddr));

    if(res < 0)
    {
        perror("[*] send_spa_packet_udp: sendto error: ");
    }
    else if(res != sd_len)
    {
        fprintf(stderr, "[#] Warning: bytes sent (%i) not spa data length (%i).\n",
            res, sd_len);
    }

#ifdef WIN32
	closesocket(sock);
#else
    close(sock);
#endif

    return(res);
}

/* Send the SPA data packet via an established TCP connection.
*/
int
send_spa_packet_tcp(char *spa_data, int sd_len, struct sockaddr_in *saddr,
    struct sockaddr_in *daddr, fko_cli_options_t *options)
{
    int  res;

    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sock < 0)
    {
        perror("[*] send_spa_packet_tcp: create socket: ");
        return(sock);
    }

    res = connect(sock, (struct sockaddr *)daddr, sizeof(*daddr));
    if(res < 0)
    {
        perror("[*] send_spa_packet_tcp: connect: ");
#ifdef WIN32
		closesocket(sock);
#else
		close(sock);
#endif
        return(-1);
    }

    res = send(sock, spa_data, sd_len, 0);

    if(res < 0)
    {
        perror("[*] send_spa_packet_tcp: send error: ");
    }
    else if(res != sd_len)
    {
        fprintf(stderr, "[#] Warning: bytes sent (%i) not spa data length (%i).\n",
            res, sd_len);
    }

#ifdef WIN32
	closesocket(sock);
#else
    close(sock);
#endif

    return(res);
}

/* Send the SPA data via raw TCP packet.
*/
int
send_spa_packet_tcp_raw(char *spa_data, int sd_len, struct sockaddr_in *saddr,
    struct sockaddr_in *daddr, fko_cli_options_t *options)
{
#ifdef WIN32
    fprintf(stderr, "[*] send_spa_packet_tcp_raw: raw packets are not yet supported.\n");
    return(-1);
#else
    int  sock, res;
    char pkt_data[2048] = {0}; /* Should be enough for our purposes */

    struct iphdr  *iph  = (struct iphdr *) pkt_data;
    struct tcphdr *tcph = (struct tcphdr *) (pkt_data + sizeof (struct iphdr));

    int hdrlen = sizeof(struct iphdr) + sizeof(struct tcphdr);

    /* Values for setsockopt.
    */
    int         one     = 1;
    const int  *so_val  = &one;

    sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
    {
        perror("[*] send_spa_packet_tcp_raw: create socket: ");
        return(sock);
    }

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
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, so_val, sizeof(one)) < 0)
        perror("[*] send_spa_packet_tcp_raw: setsockopt HDRINCL: ");

    res = sendto (sock, pkt_data, iph->tot_len, 0,
        (struct sockaddr *)daddr, sizeof(*daddr));

    if(res < 0)
    {
        perror("[*] send_spa_packet_tcp_raw: sendto error: ");
    }
    else if(res != sd_len)
    {
        fprintf(stderr, "[#] Warning: bytes sent (%i) not spa data length (%i).\n",
            res, sd_len);
    }

    close(sock);

    return(res);

#endif /* !WIN32 */
}

/* Send the SPA data via ICMP packet.
*/
int
send_spa_packet_icmp(char *spa_data, int sd_len, struct sockaddr_in *saddr,
    struct sockaddr_in *daddr, fko_cli_options_t *options)
{
#ifdef WIN32
    fprintf(stderr, "[*] send_spa_packet_icmp: raw packets are not yet supported.\n");
    return(-1);
#else
    int res;
    char pkt_data[2048] = {0};

    struct iphdr  *iph    = (struct iphdr *) pkt_data;
    struct icmphdr *icmph = (struct icmphdr *) (pkt_data + sizeof (struct iphdr));

    int hdrlen = sizeof(struct iphdr) + sizeof(struct icmphdr);

    /* Values for setsockopt.
    */
    int         one     = 1;
    const int  *so_val  = &one;

    int sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);

    if (sock < 0)
    {
        perror("[*] send_spa_packet_icmp: create socket: ");
        return(sock);
    }

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
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, so_val, sizeof(one)) < 0)
        perror("[*] send_spa_packet_icmp: setsockopt HDRINCL: ");

    res = sendto (sock, pkt_data, iph->tot_len, 0,
        (struct sockaddr *)daddr, sizeof(*daddr));

    if(res < 0)
    {
        perror("[*] send_spa_packet_icmp: sendto error: ");
    }
    else if(res != sd_len)
    {
        fprintf(stderr, "[#] Warning: bytes sent (%i) not spa data length (%i).\n",
            res, sd_len);
    }

    close(sock);

    return(res);

#endif /* !WIN32 */
}

/* Function used to send the SPA data.
*/
int
send_spa_packet(fko_ctx_t ctx, fko_cli_options_t *options)
{
    int                 res, sd_len;
    char               *spa_data;

    struct sockaddr_in  saddr, daddr;

#ifdef WIN32
    WSADATA wsa_data;
#endif

    /* Get our spa data here.
    */
    res = fko_get_spa_data(ctx, &spa_data);

    if(res != FKO_SUCCESS)
    {
        fprintf(stderr,
            "send_spa_packet: Error #%i from fko_get_spa_data: %s\n",
            res, fko_errstr(res)
        );
        return(-1);
    }

    sd_len = strlen(spa_data);

#ifdef WIN32
    /* Winsock needs to be initialized...
    */
    res = WSAStartup( MAKEWORD(1,1), &wsa_data );
    if( res != 0 )
    {
        fprintf(stderr, "[*] Winsock initialization error %d\n", res );
        return(-1);
    }
#endif

    memset(&saddr, 0, sizeof(saddr));
    memset(&daddr, 0, sizeof(daddr));

    saddr.sin_family = AF_INET;
    daddr.sin_family = AF_INET;

    /* Set source address and port
    */
    if (options->src_port)
        saddr.sin_port = htons(options->src_port);
    else
        saddr.sin_port = INADDR_ANY;  /* default */

    if (options->spoof_ip_src_str[0] != 0x00)
        saddr.sin_addr.s_addr = inet_addr(options->spoof_ip_src_str);
    else
        saddr.sin_addr.s_addr = INADDR_ANY;  /* default */

    /* Set destination address and port
    */
    daddr.sin_port = htons(options->port);
    daddr.sin_addr.s_addr = inet_addr(options->spa_server_ip_str);

    errno = 0;

    switch (options->proto)
    {
        case FKO_PROTO_UDP:
            res = send_spa_packet_udp(spa_data, sd_len, &saddr, &daddr, options);
            break;

        case FKO_PROTO_TCP:
            res = send_spa_packet_tcp(spa_data, sd_len, &saddr, &daddr, options);
            break;

        case FKO_PROTO_TCP_RAW:
            res = send_spa_packet_tcp_raw(spa_data, sd_len, &saddr, &daddr, options);
            break;

        case FKO_PROTO_ICMP:
            res = send_spa_packet_icmp(spa_data, sd_len, &saddr, &daddr, options);
            break;

        default:
            /* --DSS XXX: What to we really want to do here? */
            fprintf(stderr, "[*] %i is not a valid or supported protocol.\n",
                options->proto);
            res = -1;
    }

    return res;
}

/* Function to write SPA packet data to the filesystem
*/
int write_spa_packet_data(fko_ctx_t ctx, fko_cli_options_t *options)
{
    FILE   *fp;
    char   *spa_data;
    int     res;

    res = fko_get_spa_data(ctx, &spa_data);

    if(res != FKO_SUCCESS)
    {
        fprintf(stderr,
            "write_spa_packet_data: Error #%i from fko_get_spa_data: %s\n",
            res, fko_errstr(res)
        );

        return(-1);
    }

    if (options->save_packet_file_append)
    {
        fp = fopen(options->save_packet_file, "a");
    }
    else
    {
        unlink(options->save_packet_file);
        fp = fopen(options->save_packet_file, "w");
    }

    if(fp == NULL)
    {
        perror("write_spa_packet_data: ");
        return(-1);
    }

    fprintf(fp, "%s\n",
        (spa_data == NULL) ? "<NULL>" : spa_data);

    fclose(fp);

    return(0);
}

/***EOF***/
