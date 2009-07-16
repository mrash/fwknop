/*
 *****************************************************************************
 *
 * File:    spa_comm.h
 *
 * Author:  Damien Stuart (dstuart@dstuart.org)
 *
 * Purpose: Header file for fwknop client test program.
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
#ifndef SPA_COMM_H
#define SPA_COMM_H

#include "fwknop_common.h"
#include <errno.h>
#include <netdb.h>

#ifdef WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #if HAVE_SYS_SOCKET_H
    #include <sys/socket.h>
  #endif
#endif

/* We will roll our own packet header structs. */
    
/* The IP header
*/
struct iphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
  #error       "Please fix <bits/endian.h>"
#endif
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
};

/* The TCP header
*/
struct tcphdr
{
    unsigned short source;
    unsigned short dest;
    unsigned int seq;
    unsigned int ack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned short res1:4;
    unsigned short doff:4;
    unsigned short fin:1;
    unsigned short syn:1;
    unsigned short rst:1;
    unsigned short psh:1;
    unsigned short ack:1;
    unsigned short urg:1;
    unsigned short res2:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned short doff:4;
    unsigned short res1:4;
    unsigned short res2:2;
    unsigned short urg:1;
    unsigned short ack:1;
    unsigned short psh:1;
    unsigned short rst:1;
    unsigned short syn:1;
    unsigned short fin:1;
#else
  #error "Adjust your <bits/endian.h> defines"
#endif
    unsigned short window;
    unsigned short check;
    unsigned short urg_ptr;
};

/* The ICMP header
*/
struct icmphdr
{
    unsigned char type;                 /* message type */
    unsigned char code;                 /* type sub-code */
    unsigned short checksum;
    union
    {
        struct
        {
            unsigned short  id;
            unsigned short  sequence;
        } echo;                         /* echo datagram */
        unsigned int    gateway;        /* gateway address */
        struct
        {
            unsigned short  __unused;
            unsigned short  mtu;
        } frag;                         /* path mtu discovery */
    } un;
};

/* for sending SPA packets over HTTP
*/
#define HTTP_MAX_REQUEST_LEN    2000  /* bytes - reasonable maximum */

#define ICMP_ECHOREPLY          0   /* Echo Reply */
#define ICMP_DEST_UNREACH       3   /* Destination Unreachable */
#define ICMP_SOURCE_QUENCH      4   /* Source Quench */
#define ICMP_REDIRECT           5   /* Redirect (change route) */
#define ICMP_ECHO               8   /* Echo Request */
#define ICMP_TIME_EXCEEDED      11  /* Time Exceeded */
#define ICMP_PARAMETERPROB      12  /* Parameter Problem */
#define ICMP_TIMESTAMP          13  /* Timestamp Request */
#define ICMP_TIMESTAMPREPLY     14  /* Timestamp Reply */
#define ICMP_INFO_REQUEST       15  /* Information Request */
#define ICMP_INFO_REPLY         16  /* Information Reply */
#define ICMP_ADDRESS            17  /* Address Mask Request */
#define ICMP_ADDRESSREPLY       18  /* Address Mask Reply */


/* Function Prototypes
*/
int send_spa_packet(fko_ctx_t ctx, fko_cli_options_t *options);
int write_spa_packet_data(fko_ctx_t ctx, fko_cli_options_t *options);

#endif  /* SPA_COMM_H */
