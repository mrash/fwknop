/*
 ******************************************************************************
 *
 * File:    config_init.c
 *
 * Author:  Damien Stuart
 *
 * Purpose: Command-line and config file processing for fwknop client.
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
#include "fwknop_common.h"
#include "config_init.h"

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
    for (i=0; i < strlen(var_name); i++)
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
*/
static void
parse_config_file(fko_cli_options_t *options, struct opts_track* ot)
{
    FILE           *cfile_ptr;
    unsigned int    numLines = 0;

    char            conf_line_buf[MAX_LINE_LEN] = {0};
    char            tmp_char_buf[MAX_LINE_LEN]  = {0};
    char           *lptr;

    struct stat     st;

    /* First see if the config file exists.  If it doesn't, and was
     * specified via command-line, then error out.  Otherwise, complain
     * and go on with program defaults.
    */
    if(stat(options->config_file, &st) != 0)
    {
        if(ot->got_config_file)
        {
            fprintf(stderr, "[*] Could not open config file: %s\n",
                options->config_file);
            exit(1);
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

        /* Get past comments and empty lines.
        */
        if (*lptr == '#' || *lptr == '\n' || *lptr == '\r' || *lptr == '\0' || *lptr == ';')
            continue;

/*--DSS TODO: Figure out what to put here
 
        if (ot->got_device == 0 || options->interface.name[0] == '\0')
            get_char_val("XXXX", options->interface.name, lptr);


        if (ot->got_snaplen == 0 && get_char_val("SNAPLEN", tmp_char_buf, lptr))
            options->snapLen = atoi(tmp_char_buf);
*/
    }

    fclose(cfile_ptr);

    return;
}

/* Sanity and bounds checks for the various options.
*/
static void
validate_options(fko_cli_options_t *options)
{
    char    *tmpc;

    /* Gotta have a Destination unless we are just testing or getting the
     * the version.
    */
    if (!options->test && !options->version
        && options->spa_server_ip_str[0] == 0x0)
    {
        fprintf(stderr,
            "[*] Must use --destination unless --test mode is used\n");
        exit(1);
    }

    /* If we are using gpg, we mush have the signer and recipient set.
    */
    if(options->use_gpg)
    {
        if(options->gpg_recipient_key == NULL
            || strlen(options->gpg_recipient_key) == 0)
        {
            fprintf(stderr,
                "[*] Must specify --gpg-recipient-key when GPG is used.\n");
            exit(1);
        }

        if(options->gpg_signer_key == NULL
            || strlen(options->gpg_signer_key) == 0)
        {
            fprintf(stderr,
                "[*] Must specify --gpg-signer-key when GPG is used.\n");
            exit(1);
        }
    }

    return;
}

/* Initialize program configuration via config file and/or command-line
 * switches.
*/
void
config_init(fko_cli_options_t *options, int argc, char **argv)
{
    int                 cmd_arg, index;
    unsigned int        tmpint;

    struct opts_track   ot;

    /* Zero out options and opts_track.
    */
    memset(options, 0x00, sizeof(fko_cli_options_t));
    memset(&ot, 0x00, sizeof(ot));

    /* Establish a few defaults such as UDP/62201 for sending the SPA
     * packet (can be changed with --Server-proto/--Server-port)
    */
    options->proto = FKO_DEFAULT_PROTO;
    options->port  = FKO_DEFAULT_PORT;

    while ((cmd_arg = getopt_long(argc, argv,
            "A:a:D:G:S:Q:p:P:ghqdTvVn", cmd_opts, &index)) != -1) {
        switch(cmd_arg) {
            case 'A':
                strlcpy(options->access_str, optarg, MAX_LINE_LEN);
                break;
            case 'D':
                strlcpy(options->spa_server_ip_str, optarg, MAX_IP_STR_LEN);
                break;
            case 'a':
                strlcpy(options->allow_ip_str, optarg, MAX_IP_STR_LEN);
                break;
            case 'G':
                strlcpy(options->get_key_file, optarg, MAX_PATH_LEN);
                break;
            case 'Q':
                strlcpy(options->spoof_ip_src_str, optarg, MAX_IP_STR_LEN);
                break;
            case 'U':
                strlcpy(options->spoof_user, optarg, MAX_USERNAME_LEN);
                break;
            case 'p':
                options->port = atoi(optarg);
                if (options->port < 0 || options->port > 65535) {
                    fprintf(stderr, "[*] Unrecognized port: %s\n", optarg);
                    exit(1);
                }
                break;
            case 'P':
                if (strncmp(optarg, "udp", strlen("udp")) == 0)
                    options->proto = IPPROTO_UDP;
                else if (strncmp(optarg, "tcp", strlen("tcp")) == 0)
                    options->proto = IPPROTO_TCP;
                else if (strncmp(optarg, "icmp", strlen("icmp")) == 0)
                    options->proto = IPPROTO_ICMP;
                else {
                    fprintf(stderr, "[*] Unrecognized protocol: %s\n", optarg);
                    exit(1);
                }
                break;
            case 'S':
                options->src_port = atoi(optarg);
                if (options->port < 0 || options->port > 65535) {
                    fprintf(stderr, "[*] Unrecognized port: %s\n", optarg);
                    exit(1);
                }
                break;
            case 'q':
                options->quiet = 1;
                break;
            case 'n':
                options->no_save = 1;
                break;
            case 'T':
                options->test = 1;
                break;
            case 'd':
                options->debug = 1;
                break;
            case 'v':
                options->verbose = 1;
                break;
            case 'V':
                options->version = 1;
                break;
            case 'h':
                usage();
                exit(0);
            case FKO_DIGEST_NAME:
                if(strncasecmp(optarg, "md5", 3) == 0)
                    options->digest_type = FKO_DIGEST_MD5;
                else if(strncasecmp(optarg, "sha1", 4) == 0)
                    options->digest_type = FKO_DIGEST_SHA1;
                else if(strncasecmp(optarg, "sha256", 6) == 0)
                    options->digest_type = FKO_DIGEST_SHA256;
                else
                {
                    fprintf(stderr, "* Invalid digest type: %s\n", optarg);
                    exit(1);
                }
                break;
            case 'g':
            case GPG_ENCRYPTION:
                options->use_gpg = 1;
                break;
            case GPG_RECIP_KEY:
                options->use_gpg = 1;
                strlcpy(options->gpg_recipient_key, optarg, MAX_GPG_KEY_ID);
                break;
            case GPG_SIGNER_KEY:
                options->use_gpg = 1;
                strlcpy(options->gpg_signer_key, optarg, MAX_GPG_KEY_ID);
                break;
            case GPG_HOME_DIR:
                options->use_gpg = 1;
                strlcpy(options->gpg_home_dir, optarg, MAX_PATH_LEN);
                break;
            case GPG_AGENT:
                options->use_gpg = 1;
                options->use_gpg_agent = 1;
                break;
            default:
                usage();
                exit(1);
        }
    }

    /* Parse configuration file to populate any params not already specified
     * via command-line options
    */
    //--DSS XXX: We will use this when we have a config file to use.
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
    fprintf(stderr, "\n%s version %s\n%s\n\n", MY_NAME, MY_VERSION, MY_DESC);
    fprintf(stderr,
      "Usage: fwknop -A <port list> [-s|-R|-a] -D <spa_server> [options]\n\n"
      " -h, --help              - Print this usage message and exit.\n"
      " -c, --config-file       - Specify an alternate configuration file.\n"
      " -A, --access            - Provide a list of ports/protocols to open\n"
      "                           on the server.\n"
      " -a, --allow-ip          - Specify IP address to allow within the SPA\n"
      "                           packet.\n"
      " -D, --destination       - Specify the IP address of the fwknop server.\n"
      " -p, --server-port       - Set the destination port for outgoing SPA\n"
      "                           packet.\n"
      " -P, --source-protocol   - Set the protocol (UDP, TCP, ICMP) for the\n"
      "                           outgoing SPA packet.\n"
      " -S, --source-port       - Set the source port for outgoing SPA packet.\n"
      " -Q, --spoof-source      - Set the source IP for outgoing SPA packet.\n"
      " -U, --spoof-user        - Set the username within outgoing SPA packet.\n"
      " -q, --quiet             - Perform fwknop functions quietly.\n"
      " -G, --get-key           - Load an encryption key/password from a file.\n"
      " -T, --test              - Build the SPA packet but do not send it over\n"
      "                           the network.\n"
      " -d, --debug             - Set debug mode.\n"
      " -v, --verbose           - Set verbose mode.\n"
      " -V, --version           - Print version number.\n"
      "     --digest-type       - Speciy the message digest algorithm to use.\n"
      "                           (md5, sha1, or sha256 (default)).\n"
      "     --gpg-encryption    - Use GPG encyrption (default is Rijndael).\n"
      "     --gpg-recipient-key - Specify the recipient GPG key name or ID.\n"
      "     --gpg-signer-key    - Specify the signer's GPG key name or ID.\n"
      "     --gpg-home-dir      - Specify the GPG home directory.\n"
      "     --gpg-agent         - Use GPG agent if available.\n"
      "\n"
    );

    return;
}

/***EOF***/
