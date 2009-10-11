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
    int space_needed;

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

    /* If this particular entry was already set (i.e. not NULL), then
     * assume it needs to be freed first.
    */
    if(opts->config[var_ndx] != NULL)
        free(opts->config[var_ndx]);

    space_needed = strlen(value) + 1;

    opts->config[var_ndx] = malloc(space_needed);

    if(opts->config[var_ndx] == NULL)
    {
        fprintf(stderr, "*Fatal memory allocation error!\n");
        exit(EXIT_FAILURE);
    }

    strlcpy(opts->config[var_ndx], value, space_needed);
 
    return;
}

/* Given a config parameter name, return its index or -1 if not found.
*/
int
config_entry_index(fko_srv_options_t *opts, char *var)
{
    int i;

    for(i=0; i<NUMBER_OF_CONFIG_ENTRIES; i++)
        if(opts->config[i] != NULL && CONF_VAR_IS(var, config_map[i]))
            return(i);
 
    return(-1);
}

/* Free the config memory
*/
void
free_configs(fko_srv_options_t *opts)
{
    int i;

    for(i=0; i<NUMBER_OF_CONFIG_ENTRIES; i++)
        if(opts->config[i] != NULL)
            free(opts->config[i]);
}

/* Parse the config file...
*/
static void
parse_config_file(fko_srv_options_t *opts, char *config_file)
{
    FILE           *cfile_ptr;
    unsigned int    numLines = 0;
    unsigned int    i, good_ent;
    int             cndx;

    char            conf_line_buf[MAX_LINE_LEN] = {0};
    char            var[MAX_LINE_LEN]  = {0};
    char            val[MAX_LINE_LEN]  = {0};
    char            tmp1[MAX_LINE_LEN]  = {0};
    char            tmp2[MAX_LINE_LEN]  = {0};

    struct stat     st;

    /* First see if the config file exists.  If it doesn't, complain
     * and go on with program defaults.
    */
    if(stat(config_file, &st) != 0)
    {
        fprintf(stderr, "[*] Config file: '%s' was not found.\n",
            config_file);

        exit(EXIT_FAILURE);
    }

    if ((cfile_ptr = fopen(config_file, "r")) == NULL)
    {
        fprintf(stderr, "[*] Could not open config file: %s\n",
            config_file);
        perror(NULL);

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
                "*Invalid config file entry in %s at line %i.\n - '%s'",
                config_file, numLines, conf_line_buf
            );
            continue;
        }

        /*
        fprintf(stderr,
            "CONF FILE: %s, LINE: %s\tVar: %s, Val: '%s'\n",
            config_file, conf_line_buf, var, val
        );
        */

        good_ent = 0;
        for(i=0; i<NUMBER_OF_CONFIG_ENTRIES; i++)
        {
            if(CONF_VAR_IS(config_map[i], var))
            {
                /* First check to see if we need to do a varable expansion
                 * on this value.  Note: this only supports one expansion and
                 * only if the value starts with the variable.
                */
                if(*val == '$')
                {
                    if(sscanf((val+1), "%[A-Z_]%s", tmp1, tmp2))
                    {
                        if((cndx = config_entry_index(opts, tmp1)) >= 0)
                        {
                            strlcpy(val, opts->config[cndx], MAX_LINE_LEN);
                            strlcat(val, tmp2, MAX_LINE_LEN);
                        }
                    }
                }

                set_config_entry(opts, i, val);
                good_ent++;
                break;
            }
        }

        if(good_ent == 0)
            fprintf(stderr,
                "*Ignoring unknown configuration parameter: '%s' in %s\n",
                var, config_file
            );
    }

    fclose(cfile_ptr);

    return;
}

/* Sanity and bounds checks for the various options.
*/
static void
validate_options(fko_srv_options_t *opts)
{
    /* If a HOSTNAME was specified in the config file, set the opts->hostname
     * value to it.
    */
    if(opts->config[CONF_HOSTNAME] != NULL && opts->config[CONF_HOSTNAME][0] != '\0')
        strlcpy(opts->hostname, opts->config[CONF_HOSTNAME], MAX_HOSTNAME_LEN);

    /* Some options just trigger some output of information, or trigger an
     * external function, but do not actually start fwknopd.  If any of those
     * are set, we can return here an skip the validation routines as all
     * other options will be ignored anyway.
     *
     * These are also mutually exclusive (for now).
    */
    if((opts->dump_config + opts->kill + opts->restart + opts->status) == 1)
        return;

    if((opts->dump_config + opts->kill + opts->restart + opts->status) > 1)
    {
        fprintf(stderr,
            "The -D, -K, -R, and -S options are mutually exclusive.  Pick only one.\n"
        );
        exit(EXIT_FAILURE);
    }

    /* TODO: Add more validation and sanity checks... --DSS */


    return;
}

/* Initialize program configuration via config file and/or command-line
 * switches.
*/
void
config_init(fko_srv_options_t *opts, int argc, char **argv)
{
    int             cmd_arg, index;
    unsigned char   got_conf_file = 0, got_override_config = 0;

    char            override_file[MAX_LINE_LEN];
    char           *ndx, *cmrk;

    /* Zero out options and opts_track.
    */
    memset(opts, 0x00, sizeof(fko_srv_options_t));

    /* First, set any default or otherwise static settings here.  Some may
     * end up being overwritten via config file or command-line.
    */
    /* Default Hostname (or unknown if gethostname cannot tell us).
    */
    if(gethostname(opts->hostname, MAX_HOSTNAME_LEN-1) < 0)
        strcpy(opts->hostname, "UNKNOWN");

    /* In case this is a re-config.
    */
    optind = 0;

    /* First, scan the command-line args for an alternate configuration
     * file.  If we find it, use it, otherwise use the default.
     * We also grab any override config files as well.
    */
    while ((cmd_arg = getopt_long(argc, argv,
            GETOPTS_OPTION_STRING, cmd_opts, &index)) != -1) {

        /* Look for configuration file arg.
        */
        if(cmd_arg == 'c')
        {
            set_config_entry(opts, CONF_CONFIG_FILE, optarg);
            got_conf_file++;

            /* If we already have the config_override option, we are done.
            */
            if(got_override_config > 0)
                break;
        }

        /* Look for override configuration file arg.
        */
        if(cmd_arg == 'O')
        {
            set_config_entry(opts, CONF_OVERRIDE_CONFIG, optarg);
            got_conf_file++;

            /* If we already have the conf_file option, we are done.
            */
            if(got_conf_file > 0)
                break;
        }
    }

    /* If no alternate configuration file was specified, we use the
     * default.
    */
    if(opts->config[CONF_CONFIG_FILE] == NULL)
        set_config_entry(opts, CONF_CONFIG_FILE, DEF_CONFIG_FILE);

    /* Parse configuration file to populate any params not already specified
     * via command-line options.
    */
    parse_config_file(opts, opts->config[CONF_CONFIG_FILE]);

    /* If there are override configuration entries, process them
     * here.
    */
    if(opts->config[CONF_OVERRIDE_CONFIG] != NULL)
    {
        /* Make a copy of the overrid_config string so we can munge it.
        */
        strlcpy(override_file, opts->config[CONF_OVERRIDE_CONFIG], MAX_LINE_LEN);

        ndx  = override_file;
        cmrk = strchr(ndx, ',');

        if(cmrk == NULL)
        {
            /* Only one to process...
            */
            parse_config_file(opts, ndx);

        } else {
            /* Walk the string pulling the next config override
             * at the comma delimiters.
            */
            while(cmrk != NULL) {
                *cmrk = '\0';
                parse_config_file(opts, ndx);
                ndx = cmrk + 1;
                cmrk = strchr(ndx, ',');
            }

            /* Process the last entry
            */
            parse_config_file(opts, ndx);
        }
    }

    /* Reset the options index so we can run through them again.
    */
    optind = 0;

    /* Last, but not least, we process command-line options (some of which
     * may override configuration file options.
    */
    while ((cmd_arg = getopt_long(argc, argv,
            GETOPTS_OPTION_STRING, cmd_opts, &index)) != -1) {

        switch(cmd_arg) {
            case 'c':
                /* This was handled earlier */
                break;
            case 'D':
                opts->dump_config = 1;
                break;
            case 'f':
                opts->foreground = 1;
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
            case GPG_HOME_DIR:
                set_config_entry(opts, CONF_GPG_HOME_DIR, optarg);
                break;
            case GPG_KEY:
                set_config_entry(opts, CONF_GPG_KEY, optarg);
                break;
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
                break;
            case 'i':
                set_config_entry(opts, CONF_PCAP_INTF, optarg);
                break;
            case 'K':
                opts->kill = 1;
                break;
            case 'O':
                /* This was handled earlier */
                break;
            case 'R':
                opts->restart = 1;
                break;
            case 'S':
                opts->status = 1;
                break;
            case 'v':
                opts->verbose = 1;
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

    /* Now that we have all of our options set, and we are actually going to
     * start fwknopd, we can validate them.
    */
    validate_options(opts);

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
            config_map[i],
            (opts->config[i] == NULL) ? "<not set>" : opts->config[i]
        );

    fprintf(stderr, "\n");

    fprintf(stderr, "Hostname is set to '%s'.\n", opts->hostname);

    fprintf(stderr, "\n");
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
