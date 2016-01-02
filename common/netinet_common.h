/**
 * \file common/netinet_common.h
 *
 * \brief Header file for common network packet structures.  We roll our
 *          own (actually copy) here in an effort to reduce the cross-
 *          platform "hoop-jumping" we would need to do.
 */

/*  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
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
#ifndef NETINET_COMMON_H
#define NETINET_COMMON_H

#ifdef WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #if HAVE_SYS_SOCKET_H
    #include <sys/socket.h>
  #endif
  #if HAVE_NETDB_H
    #include <netdb.h>
  #endif
  #if HAVE_NETINET_IN_H
    #include <netinet/in.h>
  #endif
  #if PLATFORM_OPENBSD  /* OpenBSD hack due to autoconf net/if.h difficulties */
    #include <net/if.h>
    #include <net/ethertypes.h>
    #include <netinet/if_ether.h>
    #ifndef ETHER_IS_VALID_LEN
      #define ETHER_IS_VALID_LEN(x) \
        ((x) >= ETHER_MIN_LEN && (x) <= ETHER_MAX_LEN)
    #endif
  #endif
  #if HAVE_ARPA_INET_H
    #include <arpa/inet.h>
  #endif
  #if HAVE_NET_ETHERNET_H
    #include <net/ethernet.h>
  #elif HAVE_SYS_ETHERNET_H
    #include <sys/ethernet.h> /* Seems to be where Solaris puts it. */
    /* Also probably need to define ETHER_IS_VALID_LEN here */
    #ifndef ETHER_IS_VALID_LEN
      #define ETHER_IS_VALID_LEN(x) \
        ((x) >= ETHERMIN && (x) <= ETHERMAX)
    #endif
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

/* The UDP header
*/
struct udphdr {
    unsigned short source;              /* source port */
    unsigned short dest;                /* destination port */
    unsigned short len;                 /* udp length */
    unsigned short check;               /* udp checksum */
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
            unsigned short  __notused;
            unsigned short  mtu;
        } frag;                         /* path mtu discovery */
    } un;
};

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

#endif  /* NETINET_COMMON_H */
