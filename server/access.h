/*
 ******************************************************************************
 *
 * File:    access.h
 *
 * Author:  Damien Stuart
 *
 * Purpose: Header file for fwknopd access.c.
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
 ******************************************************************************
*/
#ifndef ACCESS_H
#define ACCESS_H

#define PROTO_TCP   6
#define PROTO_UDP   17

/* Function Prototypes
*/
void parse_access_file(fko_srv_options_t *opts);
acc_stanza_t* acc_check_source(fko_srv_options_t *opts, const uint32_t ip);
int acc_check_port_access(acc_stanza_t *acc, char *port_str);
int acc_check_gpg_remote_id(acc_stanza_t *acc, const char *gpg_id);
void dump_access_list(const fko_srv_options_t *opts);
void expand_acc_port_list(acc_port_list_t **plist, char *plist_str);
void free_acc_stanzas(fko_srv_options_t *opts);
void free_acc_port_list(acc_port_list_t *plist);

#endif /* ACCESS_H */

/***EOF***/
