/*
 *****************************************************************************
 *
 * File:    utils.h
 *
 * Author:  Damien Stuart (dstuart@dstuart.org)
 *
 * Purpose: Header file for utils.c client test program.
 *
 * Copyright 2009-2013 Damien Stuart (dstuart@dstuart.org)
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
#ifndef UTILS_H
#define UTILS_H

#if HAVE_CONFIG_H
  #include "config.h"
#endif

#include <sys/types.h>
#ifdef WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #if HAVE_SYS_SOCKET_H
    #include <sys/socket.h>
  #endif
  #include <netdb.h>
#endif

#define PROTOCOL_BUFSIZE    16      /*!< Maximum number of chars for a protocol string (TCP for example) */

#define FD_INVALID          -1
#define FD_IS_VALID(x)      ((x)>=0)

/* Prototypes
*/
void    hex_dump(const unsigned char *data, const int size);
int     is_base64(const unsigned char *buf, const unsigned short int len);
int     set_file_perms(const char *file);
int     verify_file_perms_ownership(const char *file);
int     resolve_dest_adr(const char *dns_str, struct addrinfo *hints, char *ip_str, size_t ip_bufsize);
short   proto_inttostr(int proto, char *proto_str, size_t proto_size);
short   proto_strtoint(const char *pr_str);

#endif  /* UTILS_H */
