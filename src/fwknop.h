/*
 *****************************************************************************
 *
 * File:    fwknop.h
 *
 * Author:  Michael Rash (mbr@cipherdyne.org)
 *
 * Purpose: Header file for fwknop client test program.
 *
 * Copyright (C) 2009 Michael Rash (mbr@cipherdyne.org)
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
 *
 * $Id$
 *
*/

#ifndef __FWKNOP_H__
#define __FWKNOP_H__

/* includes
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <netinet/in.h>
#include "fko.h"

/* defines
*/
#define FKO_PW "BubbaWasHere"
#define FKO_DEFAULT_PROTO IPPROTO_UDP
#define FKO_DEFAULT_PORT 62201
#define MAX_IP_STR_LEN 16
#define CMDL_NO_ARG 0
#define CMDL_HAS_ARG 1

/* for command argument processing
*/
typedef struct {
    unsigned char spa_server_ip_str[MAX_IP_STR_LEN];  /* -s */
    unsigned char spoof_ip_src_str[MAX_IP_STR_LEN];  /* -s */
    int proto;
    int port;
    int src_port;  /* only used with --Source-port */

    int quiet;   /* --quiet mode */
    int verbose; /* --verbose mode */
    int version; /* --Version */
    int test;
} cmdl_opts;

/* prototypes
*/
static int send_spa_packet(fko_ctx_t ctx, cmdl_opts *options);
static int send_spa_packet_udp(fko_ctx_t ctx, struct sockaddr_in *saddr,
    struct sockaddr_in *addr, cmdl_opts *options);
static int send_spa_packet_tcp(fko_ctx_t ctx, struct sockaddr_in *saddr,
    struct sockaddr_in *addr, cmdl_opts *options);
static int send_spa_packet_icmp(fko_ctx_t ctx, cmdl_opts *options);

static void display_ctx(fko_ctx_t ctx);
static void hex_dump(unsigned char *data, int size);
static void process_cmd_line(cmdl_opts *options, int argc, char **argv);
static void validate_options(cmdl_opts *options);
static void usage(void);

#endif  /* __FWKNOP_H__ */
