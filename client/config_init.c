/*
 ******************************************************************************
 *
 * File:    config_init.c
 *
 * Author:  Damien Stuart
 *
 * Purpose: Command-line and config file processing for fwknop client.
 *
 * Copyright 2009-2010 Damien Stuart (dstuart@dstuart.org)
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
#include "fwknop_common.h"
#include "config_init.h"
#include "cmd_opts.h"
#include "utils.h"

/* Convert a digest_type string to its integer value.
*/
static int
digest_strtoint(const char *dt_str)
{
    if(strcasecmp(dt_str, "md5") == 0)
        return(FKO_DIGEST_MD5);
    else if(strcasecmp(dt_str, "sha1") == 0)
        return(FKO_DIGEST_SHA1);
    else if(strcasecmp(dt_str, "sha256") == 0)
        return(FKO_DIGEST_SHA256);
    else if(strcasecmp(dt_str, "sha384") == 0)
        return(FKO_DIGEST_SHA384);
    else if(strcasecmp(dt_str, "sha512") == 0)
        return(FKO_DIGEST_SHA512);
    else
        return(-1);
}

/* Convert a protocol string to its intger value.
*/
static int
proto_strtoint(const char *pr_str)
{
    if (strcasecmp(pr_str, "udp") == 0)
        return(FKO_PROTO_UDP);
    else if (strcasecmp(pr_str, "tcpraw") == 0)
        return(FKO_PROTO_TCP_RAW);
    else if (strcasecmp(pr_str, "tcp") == 0)
        return(FKO_PROTO_TCP);
    else if (strcasecmp(pr_str, "icmp") == 0)
        return(FKO_PROTO_ICMP);
    else if (strcasecmp(pr_str, "http") == 0)
        return(FKO_PROTO_HTTP);
    else
        return(-1);
}

/* Parse any time offset from the command line
*/
static int
parse_time_offset(const char *offset_str)
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
        fprintf(stderr, "Invalid time offset: %s", offset_str);
        exit(EXIT_FAILURE);
    }

    offset = atoi(offset_digits);

    if (offset < 0) {
        fprintf(stderr, "Invalid time offset: %s", offset_str);
        exit(EXIT_FAILURE);
    }

    /* Apply the offset_type value
    */
    offset *= offset_type;

    return offset;
}

static int
create_fwknoprc(const char *rcfile)
{
    FILE    *rc;

    fprintf(stderr, "Creating initial rc file: %s.\n", rcfile);

    if ((rc = fopen(rcfile, "w")) == NULL)
    {
        fprintf(stderr, "Unable to create rc file: %s: %s\n",
            rcfile, strerror(errno));
        return(-1);
    }

    fprintf(rc,
        "# .fwknoprc\n"
        "##############################################################################\n"
        "#\n"
        "# Firewall Knock Operator (fwknop) client rc file.\n"
        "#\n"
        "# This file contains user-specific fwknop client configuration default\n"
        "# and named parameter sets for specific invocations of the fwknop client.\n"
        "#\n"
        "# Each section (or stanza) is identified and started by a line in this\n"
        "# file that contains a single identifier surrounded by square brackets.\n"
        "#\n"
        "# The parameters within the stanza typicaly match corresponding client \n"
        "# command-line parameters.\n"
        "#\n"
        "# The first one should always be `[default]' as it defines the global\n"
        "# default settings for the user. These override the program defaults\n"
        "# for these parameter.  If a named stanza is used, its entries will\n"
        "# override any of the default.  Command-line options will trump them\n"
        "# all.\n"
        "#\n"
        "# Subsequent stanzas will have only the overriding and destination\n"
        "# specific parameters.\n"
        "#\n"
        "# Lines starting with `#' and empty lines are ignored.\n"
        "#\n"
        "# See the fwknop.8 man page for a complete list of valid parameters\n"
        "# and their values.\n"
        "#\n"
        "##############################################################################\n"
        "#\n"
        "# We start with the 'default' stanza.  Uncomment and edit for your\n"
        "# preferences.  The client will use its build-in default for those items\n"
        "# that are commented out.\n"
        "#\n"
        "[default]\n"
        "\n"
        "#DIGEST_TYPE         sha256\n"
        "#FW_TIMEOUT          30\n"
        "#SPA_SERVER_PORT     62201\n"
        "#SPA_SERVER_PROTO    udp\n"
        "#ALLOW_IP            <ip addr>\n"
        "#SPOOF_USER          <username>\n"
        "#SPOOF_SOURCE_IP     <IPaddr>\n"
        "#TIME_OFFSET         0\n"
        "#USE_GPG             N\n"
        "#GPG_HOMEDIR         /path/to/.gnupg\n"
        "#GPG_SIGNER          <signer ID>\n"
        "#GPG_RECIPIENT       <recipient ID>\n"
        "\n"
        "# User-provided named stanzas:\n"
        "\n"
        "# Example for a destination server of 192.168.1.20 to open access to \n"
        "# SSH for an IP that is resoved exteranlly, and one with a NAT request\n"
        "# for a specific source IP that maps port 8088 on the server\n"
        "# to port 88 on 192.168.1.55 with timeout.\n"
        "#\n"
        "#[myssh]\n"
        "#SPA_SERVER          192.168.1.20\n"
        "#ACCESS              tcp/22\n"
        "#ALLOW_IP            resolve\n"
        "#\n"
        "#[mynatreq]\n"
        "#SPA_SERVER          192.168.1.20\n"
        "#ACCESS              tcp/8088\n"
        "#ALLOW_IP            10.21.2.6\n"
        "#NAT_ACCESS          192.168.1.55,88\n"
        "#CLIENT_TIMEOUT      60\n"
        "#\n"
        "\n"
        "###EOF###\n"
    );

    fclose(rc);

    return(0);
}

static int
parse_rc_param(fko_cli_options_t *options, const char *var, char * val)
{
    int     tmpint;

    /* Digest Type */
    if(CONF_VAR_IS(var, "DIGEST_TYPE"))
    {
        tmpint = digest_strtoint(val);
        if(tmpint < 0)
            return(-1);
        else
            options->digest_type = tmpint;
    }
    /* Server protocol */
    else if(CONF_VAR_IS(var, "SPA_SERVER_PROTO"))
    {
        tmpint = proto_strtoint(val);
        if(tmpint < 0)
            return(-1);
        else
            options->spa_proto = tmpint;
    }
    /* Server port */
    else if(CONF_VAR_IS(var, "SPA_SERVER_PORT"))
    {
        tmpint = atoi(val);
        if(tmpint < 0 || tmpint > MAX_PORT)
            return(-1);
        else
            options->spa_dst_port = tmpint;
    }
    /* Source port */
    else if(CONF_VAR_IS(var, "SPA_SOURCE_PORT"))
    {
        tmpint = atoi(val);
        if(tmpint < 0 || tmpint > MAX_PORT)
            return(-1);
        else
            options->spa_src_port = tmpint;
    }
    /* Firewall rule timeout */
    else if(CONF_VAR_IS(var, "FW_TIMEOUT"))
    {
        tmpint = atoi(val);
        if(tmpint < 0)
            return(-1);
        else
            options->fw_timeout = tmpint;
    }
    /* Allow IP */
    else if(CONF_VAR_IS(var, "ALLOW_IP"))
    {
        /* In case this was set previously
        */
        options->resolve_ip_http = 0;

        /* use source, resolve, or an actual IP
        */
        if(strcasecmp(val, "source") == 0)
            strlcpy(options->allow_ip_str, "0.0.0.0", 8);
        else if(strcasecmp(val, "resolve") == 0)
            options->resolve_ip_http = 1;
        else /* Assume IP address */
            strlcpy(options->allow_ip_str, val, MAX_IPV4_STR_LEN);
    }
    /* Time Offset */
    else if(CONF_VAR_IS(var, "TIME_OFFSET"))
    {
        if(val[0] == '-')
        {
            val++;
            options->time_offset_minus = parse_time_offset(val);
        }
        else
            options->time_offset_plus = parse_time_offset(val);
    }
    /* Use GPG ? */
    else if(CONF_VAR_IS(var, "USE_GPG"))
    {
        if(val[0] == 'y' || val[0] == 'Y')
            options->use_gpg = 1;
    }
    /* GPG Recipient */
    else if(CONF_VAR_IS(var, "GPG_RECIPIENT"))
    {
        strlcpy(options->gpg_recipient_key, val, MAX_GPG_KEY_ID);
    }
    /* GPG Signer */
    else if(CONF_VAR_IS(var, "GPG_SIGNER"))
    {
        strlcpy(options->gpg_signer_key, val, MAX_GPG_KEY_ID);
    }
    /* GPG Homedir */
    else if(CONF_VAR_IS(var, "GPG_HOMEDIR"))
    {
        strlcpy(options->gpg_home_dir, val, MAX_PATH_LEN);
    }
    /* Spoof User */
    else if(CONF_VAR_IS(var, "SPOOF_USER"))
    {
        strlcpy(options->spoof_user, val, MAX_USERNAME_LEN);
    }
    /* Spoof Source IP */
    else if(CONF_VAR_IS(var, "SPOOF_SOURCE_IP"))
    {
        strlcpy(options->spoof_ip_src_str, val, MAX_IPV4_STR_LEN);
    }
    /* ACCESS request */
    else if(CONF_VAR_IS(var, "ACCESS"))
    {
        strlcpy(options->access_str, val, MAX_LINE_LEN);
    }
    /* SPA Server (destination) */
    else if(CONF_VAR_IS(var, "SPA_SERVER"))
    {
        strlcpy(options->spa_server_str, val, MAX_SERVER_STR_LEN);
    }
    /* Rand port ? */
    else if(CONF_VAR_IS(var, "RAND_PORT"))
    {
        if(val[0] == 'y' || val[0] == 'Y')
            options->rand_port = 1;
    }
    /* Key file */
    else if(CONF_VAR_IS(var, "KEY_FILE"))
    {
        strlcpy(options->get_key_file, val, MAX_PATH_LEN);
    }
    /* NAT Access Request */
    else if(CONF_VAR_IS(var, "NAT_ACCESS"))
    {
        strlcpy(options->nat_access_str, val, MAX_PATH_LEN);
    }
    /* HTTP User Agent */
    else if(CONF_VAR_IS(var, "HTTP_USER_AGENT"))
    {
        strlcpy(options->http_user_agent, val, HTTP_MAX_USER_AGENT_LEN);
    }
    /* Resolve URL */
    else if(CONF_VAR_IS(var, "RESOLVE_URL"))
    {
        if(options->resolve_url != NULL)
            free(options->resolve_url);
        tmpint = strlen(val)+1;
        options->resolve_url = malloc(tmpint);
        if(options->resolve_url == NULL)
        {
            fprintf(stderr, "Memory allocation error for resolve URL.\n");
            exit(EXIT_FAILURE);
        }
        strlcpy(options->resolve_url, val, tmpint);
    }
    /* NAT Local ? */
    else if(CONF_VAR_IS(var, "NAT_LOCAL"))
    {
        if(val[0] == 'y' || val[0] == 'Y')
            options->nat_local = 1;
    }
    /* NAT rand port ? */
    else if(CONF_VAR_IS(var, "NAT_RAND_PORT"))
    {
        if(val[0] == 'y' || val[0] == 'Y')
            options->nat_rand_port = 1;
    }
    /* NAT port */
    else if(CONF_VAR_IS(var, "NAT_PORT"))
    {
        tmpint = atoi(val);
        if(tmpint < 0 || tmpint > MAX_PORT)
            return(-1);
        else
            options->nat_port = tmpint;
    }

    return(0);
}

/* Process (create if necessary) the users ~/.fwknoprc file.
*/
static void
process_rc(fko_cli_options_t *options)
{
    FILE    *rc;
    int     line_num = 0;
    int     rcf_offset;
    char    line[MAX_LINE_LEN];
    char    rcfile[MAX_PATH_LEN];
    char    curr_stanza[MAX_LINE_LEN] = {0};
    char    var[MAX_LINE_LEN]  = {0};
    char    val[MAX_LINE_LEN]  = {0};

    char    *ndx, *emark, *homedir;

#ifdef WIN32
    homedir = getenv("USERPROFILE");
#else
    homedir = getenv("HOME");
#endif

    if(homedir == NULL)
    {
        fprintf(stderr, "Warning: Unable to determine HOME directory.\n"
            " No .fwknoprc file processed.\n");
        return;
    }

    memset(rcfile, 0x0, MAX_PATH_LEN);

    strlcpy(rcfile, homedir, MAX_PATH_LEN);

    rcf_offset = strlen(rcfile);

    /* Sanity check the path to .fwknoprc.
     * The preceeding path plus the path separator and '.fwknoprc' = 11
     * cannot exceed MAX_PATH_LEN.
    */
    if(rcf_offset > (MAX_PATH_LEN - 11))
    {
        fprintf(stderr, "Warning: Path to .fwknoprc file is too long.\n"
            " No .fwknoprc file processed.\n");
        return;
    }

    rcfile[rcf_offset] = PATH_SEP;
    strlcat(rcfile, ".fwknoprc", MAX_PATH_LEN);

    /* Open the rc file for reading, if it does not exist, then create
     * an initial .fwknoprc file with defaults and go on.
    */
    if ((rc = fopen(rcfile, "r")) == NULL)
    {
        if(errno == ENOENT)
        {
            if(create_fwknoprc(rcfile) != 0)
                return;
        }
        else
            fprintf(stderr, "Unable to open rc file: %s: %s\n",
                rcfile, strerror(errno));

        return;
    }

    /* Read in and parse the rc file parameters.
    */
    while ((fgets(line, MAX_LINE_LEN, rc)) != NULL)
    {
        line_num++;
        line[MAX_LINE_LEN-1] = '\0';

        ndx = line;

        /* Skip any leading whitespace.
        */
        while(isspace(*ndx))
            ndx++;

        /* Get past comments and empty lines (note: we only look at the
         * first character.
        */
        if(IS_EMPTY_LINE(line[0]))
            continue;

        if(*ndx == '[')
        {
            ndx++;
            emark = strchr(ndx, ']');
            if(emark == NULL)
            {
                fprintf(stderr, "Unterminated stanza line: '%s'.  Skipping.\n",
                    line);
                continue;
            }

            *emark = '\0';

            strlcpy(curr_stanza, ndx, MAX_LINE_LEN);

            if(options->verbose > 3)
                fprintf(stderr,
                    "RC FILE: %s, LINE: %s\tSTANZA: %s:\n",
                    rcfile, line, curr_stanza
                );

            continue;
        }

        if(sscanf(line, "%s %[^;\n\r#]", var, val) != 2)
        {
            fprintf(stderr,
                "*Invalid entry in %s at line %i.\n - '%s'",
                rcfile, line_num, line
            );
            continue;
        }

        /* Remove any colon that may be on the end of the var
        */
        if((ndx = strrchr(var, ':')) != NULL)
            *ndx = '\0';

        if(options->verbose > 3)
            fprintf(stderr,
                "RC FILE: %s, LINE: %s\tVar: %s, Val: '%s'\n",
                rcfile, line, var, val
            );

        /* We do not proceed with parsing until we know we are in
         * a stanza.
        */
        if(strlen(curr_stanza) < 1)
            continue;

        /* Process the values. We assume we will see the default stanza
         * first, then if a named-stanza is specified, we process its
         * entries as well.
        */
        if(strcasecmp(curr_stanza, "default") == 0)
        {
            if(parse_rc_param(options, var, val) < 0)
                fprintf(stderr, "Parameter error in %s, line %i: var=%s, val=%s\n",
                    rcfile, line_num, var, val);
        }
        else if(options->use_rc_stanza[0] != '\0'
          && strncasecmp(curr_stanza, options->use_rc_stanza, MAX_LINE_LEN)==0)
        {
            options->got_named_stanza = 1;
            if(parse_rc_param(options, var, val) < 0)
                fprintf(stderr,
                    "Parameter error in %s, stanza: %s, line %i: var=%s, val=%s\n",
                    rcfile, curr_stanza, line_num, var, val);
        }

    } /* end while fgets rc */
    fclose(rc);
}

/* Sanity and bounds checks for the various options.
*/
static void
validate_options(fko_cli_options_t *options)
{
    /* Gotta have a Destination unless we are just testing or getting the
     * the version, and must use one of [-s|-R|-a].
    */
    if(!options->test
        && !options->version
        && !options->show_last_command
        && !options->run_last_command)
    {
        if(options->use_rc_stanza[0] != 0x0 && options->got_named_stanza == 0)
        {
            fprintf(stderr, "Named configuration stanza: [%s] was not found.\n",
                options->use_rc_stanza);

            exit(EXIT_FAILURE);
        }

        if (options->spa_server_str[0] == 0x0)
        {
            fprintf(stderr,
                "Must use --destination unless --test mode is used\n");
            exit(EXIT_FAILURE);
        }

        if (options->resolve_url != NULL)
            options->resolve_ip_http = 1;

        if (!options->resolve_ip_http && options->allow_ip_str[0] == 0x0)
        {
            fprintf(stderr,
                "Must use one of [-s|-R|-a] to specify IP for SPA access.\n");
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
            "Cannot set --http-proxy with a non-HTTP protocol.\n");
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
                "Must specify --gpg-recipient-key when GPG is used.\n");
            exit(EXIT_FAILURE);
        }
    }

    return;
}

/* Establish a few defaults such as UDP/62201 for sending the SPA
 * packet (can be changed with --server-proto/--server-port)
*/
static void
set_defaults(fko_cli_options_t *options)
{
    options->spa_proto    = FKO_DEFAULT_PROTO;
    options->spa_dst_port = FKO_DEFAULT_PORT;
    options->fw_timeout   = -1;

    return;
}

/* Initialize program configuration via config file and/or command-line
 * switches.
*/
void
config_init(fko_cli_options_t *options, int argc, char **argv)
{
    int                 cmd_arg, index;

    /* Zero out options and opts_track.
    */
    memset(options, 0x00, sizeof(fko_cli_options_t));

    /* Make sure a few reasonable defaults are set
    */
    set_defaults(options);

    /* First pass over cmd_line args to see if a named-stanza in the 
     * rc file is used.
    */
    while ((cmd_arg = getopt_long(argc, argv,
            GETOPTS_OPTION_STRING, cmd_opts, &index)) != -1) {
        switch(cmd_arg) {
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
            case 'n':
                options->no_save_args = 1;
                strlcpy(options->use_rc_stanza, optarg, MAX_LINE_LEN);
                break;
            case 'v':
                options->verbose++;
                break;
        }
    }

    /* First process the .fwknoprc file.
    */
    process_rc(options);

    /* Reset the options index so we can run through them again.
    */
    optind = 0;

    while ((cmd_arg = getopt_long(argc, argv,
            GETOPTS_OPTION_STRING, cmd_opts, &index)) != -1) {

        switch(cmd_arg) {
            case 'a':
                strlcpy(options->allow_ip_str, optarg, MAX_IPV4_STR_LEN);
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
                    fprintf(stderr, "--fw-timeout must be >= 0\n");
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
            case 'l':
                options->run_last_command = 1;
                break;
            case 'm':
            case FKO_DIGEST_NAME:
                if((options->digest_type = digest_strtoint(optarg)) < 0)
                {
                    fprintf(stderr, "* Invalid digest type: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case NO_SAVE_ARGS:
                options->no_save_args = 1;
                break;
            case 'n':
                /* We already handled this earlier, so we do nothing here
                */
                break;
            case 'N':
                strlcpy(options->nat_access_str, optarg, MAX_LINE_LEN);
                break;
            case 'p':
                options->spa_dst_port = atoi(optarg);
                if (options->spa_dst_port < 0 || options->spa_dst_port > MAX_PORT)
                {
                    fprintf(stderr, "Unrecognized port: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'P':
                if((options->spa_proto = proto_strtoint(optarg)) < 0)
                {
                    fprintf(stderr, "Unrecognized protocol: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'Q':
                strlcpy(options->spoof_ip_src_str, optarg, MAX_IPV4_STR_LEN);
                break;
            case 'r':
                options->rand_port = 1;
                break;
            case 'R':
                options->resolve_ip_http = 1;
                break;
            case RESOLVE_URL:
                if(options->resolve_url != NULL)
                    free(options->resolve_url);
                options->resolve_url = malloc(strlen(optarg)+1);
                if(options->resolve_url == NULL)
                {
                    fprintf(stderr, "Memory allocation error for resolve URL.\n");
                    exit(EXIT_FAILURE);
                }
                strlcpy(options->resolve_url, optarg, strlen(optarg)+1);
                break;
            case SHOW_LAST_ARGS:
                options->show_last_command = 1;
                break;
            case 's':
                strlcpy(options->allow_ip_str, "0.0.0.0", MAX_IPV4_STR_LEN);
                break;
            case 'S':
                options->spa_src_port = atoi(optarg);
                if (options->spa_src_port < 0 || options->spa_src_port > MAX_PORT)
                {
                    fprintf(stderr, "Unrecognized port: %s\n", optarg);
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
                /* Handled earlier.
                */
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
                if (options->nat_port < 0 || options->nat_port > MAX_PORT)
                {
                    fprintf(stderr, "Unrecognized port: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case TIME_OFFSET_PLUS:
                options->time_offset_plus = parse_time_offset(optarg);
                break;
            case TIME_OFFSET_MINUS:
                options->time_offset_minus = parse_time_offset(optarg);
                break;
            default:
                usage();
                exit(EXIT_FAILURE);
        }
    }

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
    fprintf(stdout, "\n%s client version %s\n%s\n\n", MY_NAME, MY_VERSION, MY_DESC);
    fprintf(stdout,
      "Usage: fwknop -A <port list> [-s|-R|-a] -D <spa_server> [options]\n\n"
      " -h, --help                  Print this usage message and exit.\n"
      " -A, --access                Provide a list of ports/protocols to open\n"
      "                             on the server.\n"
      " -B, --save-packet           Save the generated packet data to the\n"
      "                             specified file.\n"
      " -a, --allow-ip              Specify IP address to allow within the SPA\n"
      "                             packet.\n"
      " -C, --server-cmd            Specify a command that the fwknop server will\n"
      "                             execute on behalf of the fwknop client..\n"
      " -D, --destination           Specify the IP address of the fwknop server.\n"
      " -n, --named-config          Specify an named configuration stanza in the\n"
      "                             '$HOME/.fwknoprc' file to provide some of all\n"
      "                             of the configuration parameters.\n"
      " -N, --nat-access            Gain NAT access to an internal service\n"
      "                             protected by the fwknop server.\n"
      " -p, --server-port           Set the destination port for outgoing SPA\n"
      "                             packet.\n"
      " -P, --server-proto          Set the protocol (udp, tcp, http, tcpraw,\n"
      "                             icmp) for the outgoing SPA packet.\n"
      "                             Note: The 'tcpraw' and 'icmp' modes use raw\n"
      "                             sockets and thus require root access to use.\n"
      " -s, --source-ip             Tell the fwknopd server to accept whatever\n"
      "                             source IP the SPA packet has as the IP that\n"
      "                             needs access (not recommended, and the\n"
      "                             fwknopd server can ignore such requests).\n"
      " -S, --source-port           Set the source port for outgoing SPA packet.\n"
      " -Q, --spoof-source          Set the source IP for outgoing SPA packet.\n"
      " -R, --resolve-ip-http       Resolve the external network IP by\n"
      "                             connecting to a URL such as the default of:\n"
      "                             http://" HTTP_RESOLVE_HOST HTTP_RESOLVE_URL "\n"
      "                             This can be overridden with the --resolve-url\n"
      "                             option.\n"
      "     --resolve-url           Override the default URL used for resolving\n"
      "                             the source IP address.\n"
      " -u, --user-agent            Set the HTTP User-Agent for resolving the\n"
      "                             external IP via -R, or for sending SPA\n"
      "                             packets over HTTP.\n"
      " -H, --http-proxy            Specify an HTTP proxy host through which the\n"
      "                             SPA packet will be sent.  The port can also be\n"
      "                             specified here by following the host/ip with\n"
      "                             \":<port>\".\n"
      " -U, --spoof-user            Set the username within outgoing SPA packet.\n"
      " -l, --last-cmd              Run the fwknop client with the same command\n"
      "                             line args as the last time it was executed\n"
      "                             (args are read from the ~/.fwknop.run file).\n"
      " -G, --get-key               Load an encryption key/password from a file.\n"
      " -r, --rand-port             Send the SPA packet over a randomly assigned\n"
      "                             port (requires a broader pcap filter on the\n"
      "                             server side than the default of udp 62201).\n"
      " -T, --test                  Build the SPA packet but do not send it over\n"
      "                             the network.\n"
      " -v, --verbose               Set verbose mode.\n"
      " -V, --version               Print version number.\n"
      " -m, --digest-type           Specify the message digest algorithm to use.\n"
      "                             (md5, sha1, or sha256 (default)).\n"
      " -f, --fw-timeout            Specify SPA server firewall timeout from the\n"
      "                             client side.\n"
      "     --gpg-encryption        Use GPG encryption (default is Rijndael).\n"
      "     --gpg-recipient-key     Specify the recipient GPG key name or ID.\n"
      "     --gpg-signer-key        Specify the signer's GPG key name or ID.\n"
      "     --gpg-home-dir          Specify the GPG home directory.\n"
      "     --gpg-agent             Use GPG agent if available.\n"
      "     --no-save-args          Do not save fwknop command line args to the\n"
      "                             $HOME/fwknop.run file\n"
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
