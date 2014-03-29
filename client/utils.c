/*
 *****************************************************************************
 *
 * File:    utils.c
 *
 * Purpose: General/Generic functions for the fwknop client.
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
#include "common.h"
#include "fwknop_common.h"
#include "utils.h"
#ifndef WIN32
#include <arpa/inet.h>
#endif

static void *get_in_addr(struct sockaddr *sa);

/**
 * Structure to handle a protocol string and its associated integer value
 */
typedef struct fko_protocol
{
    const char  str[PROTOCOL_BUFSIZE];      /*!< String which represents a protocol value for the FKO library */
    int         val;                        /*!< Value of the protocol according to the FKO library */
} fko_protocol_t;

static fko_protocol_t fko_protocol_array[] =
{
    { "udpraw", FKO_PROTO_UDP_RAW   },
    { "udp",    FKO_PROTO_UDP       },
    { "tcpraw", FKO_PROTO_TCP_RAW   },
    { "tcp",    FKO_PROTO_TCP       },
    { "icmp",   FKO_PROTO_ICMP      },
    { "http",   FKO_PROTO_HTTP      }
};

int
verify_file_perms_ownership(const char *file)
{
    int res = 1;

#if HAVE_STAT
    struct stat st;

    /* Every file that the fwknop client deals with should be owned
     * by the user and permissions set to 600 (user read/write)
    */
    if((stat(file, &st)) == 0)
    {
        /* Make sure it is a regular file
        */
        if(S_ISREG(st.st_mode) != 1 && S_ISLNK(st.st_mode) != 1)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                "[-] file: %s is not a regular file or symbolic link.",
                file
            );
            /* when we start in enforcing this instead of just warning
             * the user
            res = 0;
            */
        }

        if((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != (S_IRUSR|S_IWUSR))
        {
            log_msg(LOG_VERBOSITY_ERROR,
                "[-] file: %s permissions should only be user read/write (0600, -rw-------)",
                file
            );
            /* when we start in enforcing this instead of just warning
             * the user
            res = 0;
            */
        }

        if(st.st_uid != getuid())
        {
            log_msg(LOG_VERBOSITY_ERROR, "[-] file: %s not owned by current effective user id",
                file);
            /* when we start in enforcing this instead of just warning
             * the user
            res = 0;
            */
        }
    }
    else
    {
        /* if the path doesn't exist, just return, but otherwise something
         * went wrong
        */
        if(errno != ENOENT)
        {
            log_msg(LOG_VERBOSITY_ERROR, "[-] stat() against file: %s returned: %s",
                file, strerror(errno));
            res = 0;
        }
    }
#endif

    return res;
}

/**
 * @brief Grab the sin address from the sockaddr structure.
 *
 * This function returns the sin address as a sockaddr_in or sockaddr_in6
 * structure according to the family set (ipv4 or ipv6) in the sockaddr
 * structure.
 *
 * @param sa sockaddr strcuture
 *
 * @return the sin addr if the sa family is AF_INET or the sin6_addr otherwise.
 */
static void *
get_in_addr(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET)
  {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }

  else
  {
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
  }
}

/**
 * @brief  Resolve a domain name as an ip adress.
 *
 * @param dns_str    Name of the host to resolve.
 * @param hints      Hints to reduce the number of result from getaddrinfo()
 * @param ip_str     String where to store the resolve ip address
 * @param ip_bufsize Number of bytes available in the ip_str buffer
 *
 * @return 0 if successful, 1 if an error occured.
 */
int
resolve_dest_adr(const char *dns_str, struct addrinfo *hints, char *ip_str, size_t ip_bufsize)
{
    int                 error;      /* Function error return code */
    struct addrinfo    *result;     /* Result of getaddrinfo() */
    struct addrinfo    *rp;         /* Element of the linked list returned by getaddrinfo() */
#if WIN32 && WINVER <= 0x0600
	struct sockaddr_in *in;
	char			   *win_ip;
#else
    struct sockaddr_in *sai_remote; /* Remote host information as a sockaddr_in structure */
#endif

    /* Try to resolve the host name */
    error = getaddrinfo(dns_str, NULL, hints, &result);
    if (error != 0)
        fprintf(stderr, "resolve_dest_adr() : %s\n", gai_strerror(error));

    else
    {
        error = 1;

        /* Go through the linked list of addrinfo structures */
        for (rp = result; rp != NULL; rp = rp->ai_next)
        {
            memset(ip_str, 0, ip_bufsize);
#if WIN32 && WINVER <= 0x0600
			/* On older Windows systems (anything before Vista?),
			 * we use inet_ntoa for now.
			*/
			in = (struct sockaddr_in*)(rp->ai_addr);
			win_ip = inet_ntoa(in->sin_addr);

			if (win_ip != NULL && (strlcpy(ip_str, win_ip, ip_bufsize) > 0))
#else
            sai_remote = (struct sockaddr_in *)get_in_addr((struct sockaddr *)(rp->ai_addr));
            if (inet_ntop(rp->ai_family, sai_remote, ip_str, ip_bufsize) != NULL)
#endif
			{
                error = 0;
                break;
            }
            else
                log_msg(LOG_VERBOSITY_ERROR, "resolve_dest_adr() : inet_ntop (%d) - %s",
                        errno, strerror(errno));
        }

        /* Free our result from getaddrinfo() */
        freeaddrinfo(result);
    }

    return error;
}

/**
 * @brief Return a protocol string according to a protocol integer value
 *
 * This function checks if the protocol integer is valid, and write the protocol
 * string associated.
 *
 * @param proto protocol inetger value (UDP_RAW, UDP, TCPRAW...)
 * @param proto_str Buffer to write the protocol string
 * @param proto_size size of the protocol string buffer
 *
 * @return -1 if the protocol integer value is not supported, 0 otherwise
 */
short
proto_inttostr(int proto, char *proto_str, size_t proto_size)
{
    short           proto_error = -1;
    unsigned char   ndx_proto;          /* Index for the fko_protocol_t structure */

    /* Initialize the protocol string */
    memset(proto_str, 0, proto_size);

    /* Look into the fko_protocol_array to find out the right protocol */
    for (ndx_proto = 0 ; ndx_proto < ARRAY_SIZE(fko_protocol_array) ; ndx_proto++)
    {
        /* If the protocol matches, grab it */
        if (fko_protocol_array[ndx_proto].val == proto)
        {
            strlcpy(proto_str, fko_protocol_array[ndx_proto].str, proto_size);
            proto_error = 0;
            break;
        }
    }

    return proto_error;

}

/**
 * @brief Convert a protocol string to its integer value.
 *
 * @param pr_str Protocol string (UDP_RAW, UDP, TCPRAW...)
 *
 * @return -1 if the protocol string is not supported, otherwise the protocol value
 */
short
proto_strtoint(const char *pr_str)
{
    unsigned char   ndx_proto;          /* Index for the fko_protocol_t structure */
    int             proto_int = -1;     /* Protocol integer value */

    /* Look into the fko_protocol_array to find out the right protocol */
    for (ndx_proto = 0 ; ndx_proto < ARRAY_SIZE(fko_protocol_array) ; ndx_proto++)
    {
        /* If the protocol matches, grab it */
        if (strcasecmp(pr_str, fko_protocol_array[ndx_proto].str) == 0)
        {
            proto_int = fko_protocol_array[ndx_proto].val;
            break;
        }
    }

    return proto_int;
}

/***EOF***/
