/*
 ******************************************************************************
 *
 * File:    cmd_opts.h
 *
 * Author:  Damien Stuart
 *
 * Purpose: Header file for fwknopd command line options.
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
#ifndef CMD_OPTS_H
#define CMD_OPTS_H

/* Long options values (for those that may not have a short option).
*/
enum {
    FW_LIST         = 0x200,
    GPG_HOME_DIR,
    ROTATE_DIGEST_CACHE,
    NOOP /* Just to be a marker for the end */
};

/* Our getopt_long options string.
*/
#define GETOPTS_OPTION_STRING "a:c:C:Dfhi:Kl:O:P:RSvV"

/* Our program command-line options...
*/
static struct option cmd_opts[] =
{
    {"access-file",         1, NULL, 'a'},
    {"config-file",         1, NULL, 'c'},
    {"packet-limit",        1, NULL, 'C'},
    {"dump-config",         0, NULL, 'D'},
    {"foreground",          0, NULL, 'f'},
    {"help",                0, NULL, 'h'},
    {"interface",           1, NULL, 'i'},
    {"kill",                0, NULL, 'K'},
    {"fw-list",             0, NULL, FW_LIST },
    {"gpg-home-dir",        1, NULL, GPG_HOME_DIR },
    {"locale",              1, NULL, 'l' },
    {"rotate-digest-cache", 0, NULL, ROTATE_DIGEST_CACHE },
    {"override-config",     1, NULL, 'O' },
    {"pcap-filter",         1, NULL, 'P'},
    {"restart",             0, NULL, 'R'},
    {"status",              0, NULL, 'S'},
    {"verbose",             0, NULL, 'v'},
    {"version",             0, NULL, 'V'},
    {0, 0, 0, 0}
};

#endif /* CMD_OPTS_H */

/***EOF***/
