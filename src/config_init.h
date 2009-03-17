/*
 ******************************************************************************
 *
 * File:    fwknop.h
 *
 * Author:  Damien Stuart
 *
 * Purpose: Header file for fwknop config_init.
 *
 * Copyright (C) 2008 Damien Stuart (dstuart@dstuart.org)
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
 ******************************************************************************
*/
#ifndef CONFIG_INIT_H
#define CONFIG_INIT_H

#include <getopt.h>
#include <sys/stat.h>

/* Long options values (for those without a short option).
*/
enum {
    FKO_DIGEST_NAME     = 0x100,
    /* Put GPG-related items below the following line */
    GPG_ENCRYPTION      = 0x200,
    GPG_RECIP_KEY,
    GPG_SIGNER_KEY,
    GPG_HOME_DIR,
    GPG_AGENT,
    NOOP /* Just to be a marker for the end */
};

/* Our program command-line options...
*/
static struct option cmd_opts[] =
{
    {"access",              1, NULL, 'A'},
    {"destination",         1, NULL, 'D'},
    {"allow-ip",            1, NULL, 'a'},
    {"server-port",         1, NULL, 'p'},
    {"server-proto",        1, NULL, 'P'},
    {"source-port",         1, NULL, 'S'},
    {"spoof-src",           1, NULL, 'Q'},
    {"spoof-user",          1, NULL, 'U'},
    {"get-key",             1, NULL, 'G'},
    {"quiet",               0, NULL, 'q'},
    {"debug",               0, NULL, 'd'},
    {"test",                0, NULL, 'T'},
    {"no-save",             0, NULL, 'n'},
    {"verbose",             0, NULL, 'v'},
    {"version",             0, NULL, 'V'},
    {"help",                0, NULL, 'h'},
    {"digest-type",         1, NULL, FKO_DIGEST_NAME},
    {"gpg-encryption",      0, NULL, 'g'},
    {"gpg-recipient-key",   1, NULL, GPG_RECIP_KEY },
    {"gpg-signer-key",      1, NULL, GPG_SIGNER_KEY },
    {"gpg-home-dir",        1, NULL, GPG_HOME_DIR },
    {"gpg-agent",           0, NULL, GPG_AGENT },
    {0, 0, 0, 0}
};

/* Track config options set via command-line.
 * --DSS: XXX: These will need to be reviewed...
*/
typedef struct opts_track {
    unsigned int got_destination:1;
    unsigned int got_server_port:1;
    unsigned int got_server_proto:1;
    unsigned int got_config_file:1;
    unsigned int got_source_port:1;
    unsigned int got_spoof_src:1;
} opts_track_t;

/* Function Prototypes
*/
void config_init(fko_cli_options_t *options, int argc, char **argv);
void usage(void);

#endif /* CONFIG_INIT_H */

/***EOF***/
