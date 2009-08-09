/*
 ******************************************************************************
 *
 * File:    fwknop.h
 *
 * Author:  Damien Stuart
 *
 * Purpose: Header file for fwknopd config_init.
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
 ******************************************************************************
*/
#ifndef CONFIG_INIT_H
#define CONFIG_INIT_H

#include <getopt.h>
#include <sys/stat.h>

/* Long options values (for those without a short option).
*/
enum {
    GPG_HOME_DIR    = 0x200,
    NOOP /* Just to be a marker for the end */
};

/* Our program command-line options...
*/
static struct option cmd_opts[] =
{
    {"gpg-home-dir",        1, NULL, GPG_HOME_DIR },
    {"help",                0, NULL, 'h'},
    {"verbose",             0, NULL, 'v'},
    {"version",             0, NULL, 'V'},
    {0, 0, 0, 0}
};

/* Track config options set via command-line.
 * --DSS: XXX: These will need to be reviewed...
*/
typedef struct opts_track {
    unsigned int got_server_port:1;
} opts_track_t;

/* Function Prototypes
*/
void config_init(fko_srv_options_t *options, int argc, char **argv);
void usage(void);

#endif /* CONFIG_INIT_H */

/***EOF***/
