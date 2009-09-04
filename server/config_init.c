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

/* Routine to extract the configuration value from a line in the config
 * file.
*/
int
get_char_val(const char *var_name, char *dest, char *lptr)
{
    int i, var_char_ctr = 0;
    char *tmp_ptr;

    tmp_ptr = lptr;

    /* var_name is guaranteed to be NULL-terminated.
    */
    for (i=0; i < (int)strlen(var_name); i++)
        if (tmp_ptr[i] != var_name[i])
            return 0;

    tmp_ptr += i;

    /* First char after varName better be a space or tab  or '='.
    */
    if (*tmp_ptr != ' ' && *tmp_ptr != '\t' && *tmp_ptr != '=')
        return 0;

    /* Walk past the delimiter.
    */
    while (*tmp_ptr == ' ' || *tmp_ptr == '\t' || *tmp_ptr == '=')
        tmp_ptr++;

    while (var_char_ctr < MAX_LINE_LEN && tmp_ptr[var_char_ctr] != '\n'
            && tmp_ptr[var_char_ctr] != '\0')
        var_char_ctr++;

    if (tmp_ptr[var_char_ctr] != '\n' || var_char_ctr >= MAX_LINE_LEN)
        return 0;

    strncpy(dest, tmp_ptr, var_char_ctr);

    dest[var_char_ctr] = '\0';

    return 1;
}

/* Parse the config file...
static void
parse_config_file(fko_svr_options_t *options, opts_track_t *ot)
{
    FILE           *cfile_ptr;
    unsigned int    numLines = 0;

    char            conf_line_buf[MAX_LINE_LEN] = {0};
    char            tmp_char_buf[MAX_LINE_LEN]  = {0};
    char           *lptr;

    struct stat     st;

    * First see if the config file exists.  If it doesn't, and was
     * specified via command-line, then error out.  Otherwise, complain
     * and go on with program defaults.
    *
    if(stat(options->config_file, &st) != 0)
    {
        if(ot->got_config_file)
        {
            fprintf(stderr, "[*] Could not open config file: %s\n",
                options->config_file);
            exit(EXIT_FAILURE);
        }

        fprintf(stderr,
            "** Config file was not found. Attempting to continue with defaults...\n"
        );

        return;
    }

    if ((cfile_ptr = fopen(options->config_file, "r")) == NULL)
    {
        fprintf(stderr, "[*] Could not open config file: %s\n",
                options->config_file);
        exit(EXIT_FAILURE);
    }

    while ((fgets(conf_line_buf, MAX_LINE_LEN, cfile_ptr)) != NULL)
    {
        numLines++;
        conf_line_buf[MAX_LINE_LEN-1] = '\0';
        lptr = conf_line_buf;

        memset(tmp_char_buf, 0x0, MAX_LINE_LEN);

        while (*lptr == ' ' || *lptr == '\t' || *lptr == '=')
            lptr++;

        * Get past comments and empty lines.
        *
        if (*lptr == '#' || *lptr == '\n' || *lptr == '\r' || *lptr == '\0' || *lptr == ';')
            continue;
    }

    fclose(cfile_ptr);

    return;
}
*/

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
                strlcpy(options->config_file, optarg, MAX_PATH_LEN);
                break;
            case 'D':
                fprintf(stderr, "*NOT IMPLEMENTED YET*\n");
                // TODO: Add this...
                //dump_config();
                exit(EXIT_SUCCESS);
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
                strlcpy(options->firewall_log, optarg, MAX_PATH_LEN);
                break;
            case GPG_HOME_DIR:
                strlcpy(options->gpg_home_dir, optarg, MAX_PATH_LEN);
                break;
            case GPG_KEY:
                strlcpy(options->gpg_key, optarg, MAX_GPG_KEY_ID);
                break;
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
                break;
            case 'i':
                strlcpy(options->net_interface, optarg, MAX_PATH_LEN);
                break;
            case 'K':
                fprintf(stderr, "*NOT IMPLEMENTED YET*\n");
                // TODO: Add this...
                //kill_fwknopd();
                exit(EXIT_SUCCESS);
                break;
            case 'O':
                strlcpy(options->override_config, optarg, MAX_PATH_LEN);
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
    //parse_config_file(options, &ot);

    /* Now that we have all of our options set, we can validate them.
    */
    validate_options(options);

    return;
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
