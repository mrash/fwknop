/*
 ******************************************************************************
 *
 * File:    cmd_opts.h
 *
 * Author:  Damien Stuart
 *
 * Purpose: Header file for fwknop command line options.
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

/* Long options values (for those without a short option).
*/
enum {
    FKO_DIGEST_NAME     = 0x100,
    NAT_LOCAL,
    NAT_PORT,
    NAT_RAND_PORT,
    TIME_OFFSET_MINUS,
    TIME_OFFSET_PLUS,
    NO_SAVE_ARGS,
    SHOW_LAST_ARGS,
    RESOLVE_URL,
    /* Put GPG-related items below the following line */
    GPG_ENCRYPTION      = 0x200,
    GPG_RECIP_KEY,
    GPG_SIGNER_KEY,
    GPG_HOME_DIR,
    GPG_AGENT,
    NOOP /* Just to be a marker for the end */
};


/* Our getopt_long options string.
*/
#define GETOPTS_OPTION_STRING "a:A:bB:C:D:f:gG:hH:lm:n:N:p:P:Q:rRsS:Tu:U:vV"

/* Our program command-line options...
*/
static struct option cmd_opts[] =
{
    {"allow-ip",            1, NULL, 'a'},
    {"access",              1, NULL, 'A'},
    {"save-packet-append",  0, NULL, 'b'},
    {"save-packet",         1, NULL, 'B'},
    {"no-save-args",        0, NULL, NO_SAVE_ARGS},
    {"server-cmd",          1, NULL, 'C'},
    {"digest-type",         1, NULL, FKO_DIGEST_NAME},
    {"destination",         1, NULL, 'D'},
    {"fw-timeout",          1, NULL, 'f'},
    {"gpg-encryption",      0, NULL, 'g'},
    {"gpg-recipient-key",   1, NULL, GPG_RECIP_KEY },
    {"gpg-signer-key",      1, NULL, GPG_SIGNER_KEY },
    {"gpg-home-dir",        1, NULL, GPG_HOME_DIR },
    {"gpg-agent",           0, NULL, GPG_AGENT },
    {"get-key",             1, NULL, 'G'},
    {"help",                0, NULL, 'h'},
    {"http-proxy",          1, NULL, 'H'},
    {"last-cmd",            0, NULL, 'l'},
    {"nat-access",          1, NULL, 'N'},
    {"named-config",        1, NULL, 'n'},
    {"nat-local",           0, NULL, NAT_LOCAL},
    {"nat-port",            1, NULL, NAT_PORT},
    {"nat-rand-port",       0, NULL, NAT_RAND_PORT},
    {"server-port",         1, NULL, 'p'},
    {"server-proto",        1, NULL, 'P'},
    {"spoof-src",           1, NULL, 'Q'},
    {"rand-port",           0, NULL, 'r'},
    {"resolve-ip-http",     0, NULL, 'R'},
    {"resolve-url",         1, NULL, RESOLVE_URL},
    {"show-last",           0, NULL, SHOW_LAST_ARGS},
    {"source-ip",           0, NULL, 's'},
    {"source-port",         1, NULL, 'S'},
    {"test",                0, NULL, 'T'},
    {"time-offset-plus",    1, NULL, TIME_OFFSET_PLUS},
    {"time-offset-minus",   1, NULL, TIME_OFFSET_MINUS},
    {"user-agent",          1, NULL, 'u'},
    {"spoof-user",          1, NULL, 'U'},
    {"verbose",             0, NULL, 'v'},
    {"version",             0, NULL, 'V'},
    {0, 0, 0, 0}
};

#endif /* CMD_OPTS_H */

/***EOF***/
