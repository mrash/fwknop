/*
 ******************************************************************************
 *
 * File:    config_init.c
 *
 * Author:  Damien Stuart
 *
 * Purpose: Command-line and config file processing for fwknop server.
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
#include "fwknopd_common.h"
#include "config_init.h"
#include "getopt.h"
#include "utils.h"
#include "ctype.h"

/* Take an index and a string value. malloc the space for the value
 * and assign it to the array at the specified index.
*/
void
set_config_entry(fko_srv_options_t *opts, int var_ndx, char *value)
{
    int slen;

    /* Sanity check the index value.
    */
    if(var_ndx < 0 || var_ndx >= NUMBER_OF_CONFIG_ENTRIES)
    {
        fprintf(stderr, "Index value of %i is not valid\n", var_ndx);
        exit(EXIT_FAILURE);
    }

    /* Make sure we have a valid value.
    */
    if(value == NULL)
    {
        fprintf(stderr, "Config value for index %i was NULL\n", var_ndx);
        exit(EXIT_FAILURE);
    }

    slen = strlen(value) + 1;

    opts->config_ent[var_ndx] = malloc(slen);

    if(opts->config_ent[var_ndx] == NULL)
    {
        fprintf(stderr, "*Fatal memory allocation error!\n");
        exit(EXIT_FAILURE);
    }

    strlcpy(opts->config_ent[var_ndx], value, slen);
 
    return;
}

/* Parse the config file...
*/
static void
parse_config_file(fko_srv_options_t *options, opts_track_t *ot)
{
    FILE           *cfile_ptr;
    unsigned int    numLines = 0;
    unsigned int    i, good_ent;

    char            conf_line_buf[MAX_LINE_LEN] = {0};
    char            var[MAX_LINE_LEN]  = {0};
    char            val[MAX_LINE_LEN]  = {0};

    struct stat     st;

    /* First see if the config file exists.  If it doesn't, complain
     * and go on with program defaults.
    */
    if(stat(options->config_ent[CONF_CONFIG_FILE], &st) != 0)
    {
        fprintf(stderr,
            "** Config file: '%s' was not found. Attempting to continue with defaults...\n",
            options->config_ent[CONF_CONFIG_FILE]
        );

        return;
    }

    if ((cfile_ptr = fopen(options->config_ent[CONF_CONFIG_FILE], "r")) == NULL)
    {
        fprintf(stderr, "[*] Could not open config file: %s\n",
                options->config_ent[CONF_CONFIG_FILE]);
        exit(EXIT_FAILURE);
    }

    while ((fgets(conf_line_buf, MAX_LINE_LEN, cfile_ptr)) != NULL)
    {
        numLines++;
        conf_line_buf[MAX_LINE_LEN-1] = '\0';

        /* Get past comments and empty lines (note: we only look at the
         * first character.
        */
        if(IS_EMPTY_LINE(conf_line_buf[0]))
            continue;

        if(sscanf(conf_line_buf, "%s %[^;\n\r]", var, val) != 2)
        {
            fprintf(stderr,
                "*Invalid config file entry at line %i.\n - '%s'",
                numLines, conf_line_buf
            );
            continue;
        }

        /*
        fprintf(stderr, "LINE: %s\tVar: %s, Val: '%s'\n", conf_line_buf, var, val);
        */

        good_ent = 0;
        for(i=0; i<NUMBER_OF_CONFIG_ENTRIES; i++)
        {
            if(CONF_VAR_IS(config_ent_map[i], var))
            {
                set_config_entry(options, i, val);
                good_ent++;
                break;
            }
        }

        if(good_ent == 0)
            fprintf(stderr, "*Ignoring unknown configuration parameter: '%s'\n");
    }

    fclose(cfile_ptr);

    return;
}

/* Sanity and bounds checks for the various options.
*/
static void
validate_options(fko_srv_options_t *options)
{
    /*** TODO: put stuff here ***/

    return;
}

/* Initialize program configuration via config file and/or command-line
 * switches.
*/
void
config_init(fko_srv_options_t *options, int argc, char **argv)
{
    int                 cmd_arg, index;
    struct opts_track   ot;

    /* Zero out options and opts_track.
    */
    memset(options, 0x00, sizeof(fko_srv_options_t));
    memset(&ot, 0x00, sizeof(ot));

    /* Establish a few defaults such as UDP/62201 for sending the SPA
     * packet (can be changed with --server-proto/--server-port)
    */

    while ((cmd_arg = getopt_long(argc, argv,
            "c:Dhi:KO:RSvV", cmd_opts, &index)) != -1) {

        switch(cmd_arg) {
            case 'c':
                set_config_entry(options, CONF_CONFIG_FILE, optarg);
                break;
            case 'D':
                options->dump_config = 1;
                break;
            case FIREWALL_LIST:
                fprintf(stderr, "*NOT IMPLEMENTED YET*\n");
                // TODO: Add this...
                //list_firewall_rules();
                exit(EXIT_SUCCESS);
                break;
            case FIREWALL_FLUSH:
                fprintf(stderr, "*NOT IMPLEMENTED YET*\n");
                // TODO: Add this...
                //flush_firewall_rules();
                exit(EXIT_SUCCESS);
                break;
            case FIREWALL_LOG:
                set_config_entry(options, FIREWALL_LOG, optarg);
                break;
            case GPG_HOME_DIR:
                set_config_entry(options, GPG_HOME_DIR, optarg);
                break;
            case GPG_KEY:
                set_config_entry(options, GPG_KEY, optarg);
                break;
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
                break;
            case 'i':
                set_config_entry(options, CONF_PCAP_INTF, optarg);
                break;
            case 'K':
                fprintf(stderr, "*NOT IMPLEMENTED YET*\n");
                // TODO: Add this...
                //kill_fwknopd();
                exit(EXIT_SUCCESS);
                break;
            case 'O':
                set_config_entry(options, CONF_OVERRIDE_CONFIG, optarg);
                break;
            case 'R':
                fprintf(stderr, "*NOT IMPLEMENTED YET*\n");
                // TODO: Add this...
                //restart_fwknopd();
                exit(EXIT_SUCCESS);
                break;
            case 'S':
                fprintf(stderr, "*NOT IMPLEMENTED YET*\n");
                // TODO: Add this...
                //fwkop_status();
                exit(EXIT_SUCCESS);
                break;
            case 'v':
                options->verbose = 1;
                break;
            case 'V':
                fprintf(stdout, "fwknopd server %s\n", MY_VERSION);
                exit(EXIT_SUCCESS);
                break;
            default:
                usage();
                exit(EXIT_FAILURE);
        }
    }

    /* Parse configuration file to populate any params not already specified
     * via command-line options
    */
    parse_config_file(options, &ot);

    /* Now that we have all of our options set, we can validate them.
    */
    validate_options(options);

    return;
}

/* Dump the configuration
*/
void
dump_config(fko_srv_options_t *opts)
{
    int i;
    char *var, *val;

    fprintf(stderr, "Current fwknopd config settings:\n");

    for(i=0; i<NUMBER_OF_CONFIG_ENTRIES; i++)
        fprintf(stderr, "%3i. %-28s =  '%s'\n",
            i,
            config_ent_map[i],
            (opts->config_ent[i] == NULL) ? "<not set>" : opts->config_ent[i]
        );
}

/* Print usage message...
*/
void
usage(void)
{
    fprintf(stderr, "\n%s server version %s\n%s\n\n", MY_NAME, MY_VERSION, MY_DESC);
    fprintf(stderr,
      "Usage: fwknopd [options]\n\n"
      " -h, --help              - Print this usage message and exit.\n"
      " -c, --config-file       - Specify an alternate configuration file.\n"
      " -D, --dump-config       - Dump the current fwknop configuration values.\n"
      "     --fw-list           - List all active rules in the FWKNOP Netfilter chain.\n"
      "     --fw-flush          - Flush all rules in the FWKNOP Netfilter chain.\n"
      "     --fw-log            - Specify the path to the Netfilter log file that is\n"
      "                           parsed when running in 'os-mode'.\n"
      " -i, --interface         - Specify interface to listen for incoming SPA\n"
      "                           packets.\n"
      " -K, --kill              - Kill the currently running fwknopd.\n"
      "     --gpg-home-dir      - Specify the GPG home directory.\n"
      "     --gpg-key           - Specify the GPG key ID used for decryption.\n"
      " -O, --override-config   - \n"
      " -R, --restart           - Force the currently running fwknopd to restart.\n"
      " -S, --status            - Display the status of any running fwknopd process.\n"
      " -v, --verbose           - Set verbose mode.\n"
      " -V, --version           - Print version number.\n"
      "\n"
    );

    return;
}

/***EOF***/
