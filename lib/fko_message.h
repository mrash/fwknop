/*
 *****************************************************************************
 *
 * File:    fko_message.h
 *
 * Author:  Michael Rash
 *
 * Purpose: Provide validation functions for SPA messages
 *
 * Copyright 2012 Michael Rash (mbr@cipherdyne.org)
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

#ifndef FKO_MESSAGE_H
#define FKO_MESSAGE_H 1

#if HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
#endif
#include <arpa/inet.h>

#define MAX_PROTO_STR_LEN   4  /* tcp, udp, icmp for now */
#define MAX_PORT_STR_LEN    5

/* SPA message format validation functions.
*/
int validate_cmd_msg(const char *msg);
int validate_access_msg(const char *msg);
int validate_proto_port_spec(const char *msg);
int validate_nat_access_msg(const char *msg);
int got_allow_ip(const char *msg);

#endif /* FKO_MESSAGE_H */

/***EOF***/
