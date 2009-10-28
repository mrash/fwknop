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

/* Parse any time offset from the command line
*/
static int
parse_time_offset(char *offset_str)
{
    int i, j;
    int offset      = 0;
    int offset_type = TIME_OFFSET_SECONDS;
    int os_len      = strlen(offset_str);

    char offset_digits[MAX_TIME_STR_LEN];

    j=0;
    for (i=0; i < os_len; i++) {
        if (isdigit(offset_str[i])) {
            offset_digits[j] = offset_str[i];
            j++;
        } else if (offset_str[i] == 'm' || offset_str[i] == 'M') {
            offset_type = TIME_OFFSET_MINUTES;
            break;
        } else if (offset_str[i] == 'h' || offset_str[i] == 'H') {
            offset_type = TIME_OFFSET_HOURS;
            break;
        } else if (offset_str[i] == 'd' || offset_str[i] == 'D') {
            offset_type = TIME_OFFSET_DAYS;
            break;
        }
    }

    offset_digits[j] = '\0';

    if (j < 1) {
        fprintf(stderr, "[*] Invalid time offset: %s", offset_str);
        exit(EXIT_FAILURE);
    }

    offset = atoi(offset_digits);

    if (offset < 0) {
        fprintf(stderr, "[*] Invalid time offset: %s", offset_str);
        exit(EXIT_FAILURE);
    }

    /* Apply the offset_type value
    */
    offset *= offset_type;

    return offset;
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

        /* Get past comments and empty lines.
        */
        if (*lptr == '#' || *lptr == '\n' || *lptr == '\r' || *lptr == '\0' || *lptr == ';')
            continue;

/*--DSS TODO: Figure out what to put here (these are just samples below)
 
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
    /* Gotta have a Destination unless we are just testing or getting the
     * the version, and must use one of [-s|-R|-a].
    */
    if(!options->test && !options->version && !options->show_last_command)
    {
        if (options->spa_server_str[0] == 0x0)
        {
            fprintf(stderr,
                "[*] Must use --destination unless --test mode is used\n");
            exit(EXIT_FAILURE);
        }
        if (!options->resolve_ip_http && options->allow_ip_str[0] == 0x0)
        {
            fprintf(stderr,
                "[*] Must use one of [-s|-R|-a] to specify IP for SPA access.\n");
            exit(EXIT_FAILURE);
        }

    }

    if(options->resolve_ip_http || options->spa_proto == FKO_PROTO_HTTP)
        if (options->http_user_agent[0] == '\0')
            snprintf(options->http_user_agent, HTTP_MAX_USER_AGENT_LEN,
                "%s%s", "Fwknop/", MY_VERSION);

    if(options->http_proxy[0] != 0x0 && options->spa_proto != FKO_PROTO_HTTP)
    {
        fprintf(stderr,
            "[*] Cannot set --http-proxy with a non-HTTP protocol.\n");
        exit(EXIT_FAILURE);
    }

    /* If we are using gpg, we must at least have the recipient set.
    */
    if(options->use_gpg)
    {
        if(options->gpg_recipient_key == NULL
            || strlen(options->gpg_recipient_key) == 0)
        {
            fprintf(stderr,
                "[*] Must specify --gpg-recipient-key when GPG is used.\n");
            exit(EXIT_FAILURE);
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
    struct opts_track   ot;

    /* Zero out options and opts_track.
    */
    memset(options, 0x00, sizeof(fko_cli_options_t));
    memset(&ot, 0x00, sizeof(ot));

    /* Establish a few defaults such as UDP/62201 for sending the SPA
     * packet (can be changed with --server-proto/--server-port)
    */
    options->spa_proto    = FKO_DEFAULT_PROTO;
    options->spa_dst_port = FKO_DEFAULT_PORT;
    options->fw_timeout   = -1;

    while ((cmd_arg = getopt_long(argc, argv,
            "a:A:bB:C:D:f:gG:hH:m:nN:p:P:qQ:rRsS:Tu:U:vV", cmd_opts, &index)) != -1) {

        switch(cmd_arg) {
            case 'a':
                strlcpy(options->allow_ip_str, optarg, MAX_IP_STR_LEN);
                break;
            case 'A':
                strlcpy(options->access_str, optarg, MAX_LINE_LEN);
                break;
            case 'b':
                options->save_packet_file_append = 1;
                break;
            case 'B':
                strlcpy(options->save_packet_file, optarg, MAX_PATH_LEN);
                break;
            case 'C':
                strlcpy(options->server_command, optarg, MAX_LINE_LEN);
                break;
            case 'D':
                strlcpy(options->spa_server_str, optarg, MAX_SERVER_STR_LEN);
                break;
            case 'f':
                options->fw_timeout = atoi(optarg);
                if (options->fw_timeout < 0) {
                    fprintf(stderr, "[*] --fw-timeout must be >= 0\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'g':
            case GPG_ENCRYPTION:
                options->use_gpg = 1;
                break;
            case 'G':
                strlcpy(options->get_key_file, optarg, MAX_PATH_LEN);
                break;
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
            case 'H':
                options->spa_proto = FKO_PROTO_HTTP;
                strlcpy(options->http_proxy, optarg, MAX_PATH_LEN);
                break;
            case 'm':
            case FKO_DIGEST_NAME:
                if(strncasecmp(optarg, "md5", 3) == 0)
                    options->digest_type = FKO_DIGEST_MD5;
                else if(strncasecmp(optarg, "sha1", 4) == 0)
                    options->digest_type = FKO_DIGEST_SHA1;
                else if(strncasecmp(optarg, "sha256", 6) == 0)
                    options->digest_type = FKO_DIGEST_SHA256;
                else if(strncasecmp(optarg, "sha384", 6) == 0)
                    options->digest_type = FKO_DIGEST_SHA384;
                else if(strncasecmp(optarg, "sha512", 6) == 0)
                    options->digest_type = FKO_DIGEST_SHA512;
                else
                {
                    fprintf(stderr, "* Invalid digest type: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'n':
                options->no_save = 1;
                break;
            case 'N':
                strlcpy(options->nat_access_str, optarg, MAX_LINE_LEN);
                break;
            case 'p':
                options->spa_dst_port = atoi(optarg);
                if (options->spa_dst_port < 0 || options->spa_dst_port > 65535) {
                    fprintf(stderr, "[*] Unrecognized port: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'P':
                if (strncmp(optarg, "udp", strlen("udp")) == 0)
                    options->spa_proto = FKO_PROTO_UDP;
                else if (strncmp(optarg, "tcpraw", strlen("tcpraw")) == 0)
                    options->spa_proto = FKO_PROTO_TCP_RAW;
                else if (strncmp(optarg, "tcp", strlen("tcp")) == 0)
                    options->spa_proto = FKO_PROTO_TCP;
                else if (strncmp(optarg, "icmp", strlen("icmp")) == 0)
                    options->spa_proto = FKO_PROTO_ICMP;
                else if (strncmp(optarg, "http", strlen("http")) == 0)
                    options->spa_proto = FKO_PROTO_HTTP;
                else {
                    fprintf(stderr, "[*] Unrecognized protocol: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'q':
                options->quiet = 1;
                break;
            case 'Q':
                strlcpy(options->spoof_ip_src_str, optarg, MAX_IP_STR_LEN);
                break;
            case 'r':
                options->rand_port = 1;
                break;
            case 'R':
                options->resolve_ip_http = 1;
                break;
            case SHOW_LAST_ARGS:
                options->show_last_command = 1;
                break;
            case 's':
                strlcpy(options->allow_ip_str, "0.0.0.0", MAX_IP_STR_LEN);
                break;
            case 'S':
                options->spa_src_port = atoi(optarg);
                if (options->spa_src_port < 0 || options->spa_src_port > 65535) {
                    fprintf(stderr, "[*] Unrecognized port: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'T':
                options->test = 1;
                break;
            case 'u':
                strlcpy(options->http_user_agent, optarg, HTTP_MAX_USER_AGENT_LEN);
                break;
            case 'U':
                strlcpy(options->spoof_user, optarg, MAX_USERNAME_LEN);
                break;
            case 'v':
                options->verbose = 1;
                break;
            case 'V':
                options->version = 1;
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
            case NAT_LOCAL:
                options->nat_local = 1;
                break;
            case NAT_RAND_PORT:
                options->nat_rand_port = 1;
                break;
            case NAT_PORT:
                options->nat_port = atoi(optarg);
                if (options->nat_port < 0 || options->nat_port > 65535) {
                    fprintf(stderr, "[*] Unrecognized port: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case TIME_OFFSET_PLUS:
                options->time_offset_plus = parse_time_offset(optarg);
                break;
            case TIME_OFFSET_MINUS:
                options->time_offset_minus = parse_time_offset(optarg);
                break;
            case NO_SAVE_ARGS:
                options->no_save_args = 1;
                break;
            default:
                usage();
                exit(EXIT_FAILURE);
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
    fprintf(stderr, "\n%s client version %s\n%s\n\n", MY_NAME, MY_VERSION, MY_DESC);
    fprintf(stderr,
      "Usage: fwknop -A <port list> [-s|-R|-a] -D <spa_server> [options]\n\n"
      " -h, --help                  Print this usage message and exit.\n"
      " -c, --config-file           Specify an alternate configuration file.\n"
      " -A, --access                Provide a list of ports/protocols to open\n"
      "                             on the server.\n"
      " -B, --save-packet           Save the generated packet data to the\n"
      "                             specified file.\n"
      " -a, --allow-ip              Specify IP address to allow within the SPA\n"
      "                             packet.\n"
      " -D, --destination           Specify the IP address of the fwknop server.\n"
      " -N, --nat-access            Gain NAT access to an internal service\n"
      "                             protected by the fwknop server.\n"
      " -p, --server-port           Set the destination port for outgoing SPA\n"
      "                             packet.\n"
      " -P, --server-proto          Set the protocol (udp, tcp, tcpraw, icmp) for\n"
      "                             the outgoing SPA packet. Note: The 'tcpraw'\n"
      "                             and 'icmp' modes use raw sockets and thus\n"
      "                             require root access to run.\n"
      " -s, --source-ip             Tell the fwknopd server to accept whatever\n"
      "                             source IP the SPA packet has as the IP that\n"
      "                             needs access (not recommended, and the\n"
      "                             fwknopd server can ignore such requests).\n"
      " -S, --source-port           Set the source port for outgoing SPA packet.\n"
      " -Q, --spoof-source          Set the source IP for outgoing SPA packet.\n"
      " -R, --resolve-ip-http       Resolve the external network IP by\n"
      "                             connecting to the URL:\n"
      "                             http://"
      HTTP_RESOLVE_HOST
      HTTP_RESOLVE_URL
      "\n"
      " -u, --user-agent            Set the HTTP User-Agent for resolving the\n"
      "                             external IP via -R, or for sending SPA\n"
      "                             packets over HTTP.\n"
      " -U, --spoof-user            Set the username within outgoing SPA packet.\n"
      " -q, --quiet                 Perform fwknop functions quietly.\n"
      " -G, --get-key               Load an encryption key/password from a file.\n"
      " -r, --rand-port             Send the SPA packet over a randomly assigned\n"
      "                             port (requires a broader pcap filter on the\n"
      "                             server side than the default of udp 62201).\n"
      " -T, --test                  Build the SPA packet but do not send it over\n"
      "                             the network.\n"
      " -v, --verbose               Set verbose mode.\n"
      " -V, --version               Print version number.\n"
      " -m, --digest-type           Speciy the message digest algorithm to use.\n"
      "                             (md5, sha1, or sha256 (default)).\n"
      " -f, --fw-timeout            Specify SPA server firewall timeout from the\n"
      "                             client side.\n"
      "     --gpg-encryption        Use GPG encyrption (default is Rijndael).\n"
      "     --gpg-recipient-key     Specify the recipient GPG key name or ID.\n"
      "     --gpg-signer-key        Specify the signer's GPG key name or ID.\n"
      "     --gpg-home-dir          Specify the GPG home directory.\n"
      "     --gpg-agent             Use GPG agent if available.\n"
      "     --nat-local             Access a local service via a forwarded port\n"
      "                             on the fwknopd server system.\n"
      "     --nat-port              Specify the port to forward to access a\n"
      "                             service via NAT.\n"
      "     --nat-rand-port         Have the fwknop client assign a random port\n"
      "                             for NAT access.\n"
      "     --show-last             Show the last fwknop command line arguments.\n"
      "     --time-offset-plus      Add time to outgoing SPA packet timestamp.\n"
      "     --time-offset-minus     Subtract time from outgoing SPA packet\n"
      "                             timestamp.\n"
      "\n"
    );

    return;
}

/***EOF***/
