/**
 ******************************************************************************
 *
 * \file    config_init.c
 *
 * \author  Damien Stuart
 *
 * \brief   Command-line and config file processing for fwknop client.
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
#include "netinet_common.h"
#include "config_init.h"
#include "cmd_opts.h"
#include "utils.h"
#include <sys/stat.h>
#include <fcntl.h>

#define RC_PARAM_TEMPLATE           "%-24s    %s\n"             /*!< Template to define param = val in a rc file */
#define RC_SECTION_DEFAULT          "default"                   /*!< Name of the default section in fwknoprc */
#define RC_SECTION_TEMPLATE         "[%s]\n"                    /*!< Template to define a section in a rc file */
#define FWKNOP_CLI_ARG_BM(x)        ((uint32_t)(1 << (x)))      /*!< Bitmask command line arg */
#define FWKNOPRC_OFLAGS             (O_WRONLY|O_CREAT|O_EXCL)   /*!< O_flags used to create an fwknoprc file with the open function */
#define FWKNOPRC_MODE               (S_IRUSR|S_IWUSR)           /*!< mode used to create an fwknoprc file with the open function */
#define PARAM_YES_VALUE             "Y"                         /*!< String which represents a YES value for a parameter in fwknoprc */
#define PARAM_NO_VALUE              "N"                         /*!< String which represents a NO value for a parameter in fwknoprc */
#define ARRAY_SIZE(t)               (sizeof(t) / sizeof(t[0]))  /*!< Macro to get the number of elements of an array */


typedef struct
{
    char name[MAX_LINE_LEN];
    char val[MAX_LINE_LEN];
} TParam;

enum
{
    FWKNOP_CLI_ARG_DIGEST_TYPE = 0,
    FWKNOP_CLI_ARG_SPA_SERVER_PROTO,
    FWKNOP_CLI_ARG_SPA_SERVER_PORT,
    FWKNOP_CLI_ARG_SPA_SOURCE_PORT,
    FWKNOP_CLI_ARG_FW_TIMEOUT,
    FWKNOP_CLI_ARG_ALLOW_IP,
    FWKNOP_CLI_ARG_TIME_OFFSET,
    FWKNOP_CLI_ARG_ENCRYPTION_MODE,
    FWKNOP_CLI_ARG_USE_GPG,
    FWKNOP_CLI_ARG_USE_GPG_AGENT,
    FWKNOP_CLI_ARG_GPG_RECIPIENT,
    FWKNOP_CLI_ARG_GPG_SIGNER,
    FWKNOP_CLI_ARG_GPG_HOMEDIR,
    FWKNOP_CLI_ARG_SPOOF_USER,
    FWKNOP_CLI_ARG_SPOOF_SOURCE_IP,
    FWKNOP_CLI_ARG_ACCESS,
    FWKNOP_CLI_ARG_SPA_SERVER,
    FWKNOP_CLI_ARG_RAND_PORT,
    FWKNOP_CLI_ARG_KEY_RIJNDAEL,
    FWKNOP_CLI_ARG_KEY_RIJNDAEL_BASE64,
    FWKNOP_CLI_ARG_HMAC_DIGEST_TYPE,
    FWKNOP_CLI_ARG_KEY_HMAC_BASE64,
    FWKNOP_CLI_ARG_KEY_HMAC,
    FWKNOP_CLI_ARG_USE_HMAC,
    FWKNOP_CLI_ARG_KEY_FILE,
    FWKNOP_CLI_ARG_NAT_ACCESS,
    FWKNOP_CLI_ARG_HTTP_USER_AGENT,
    FWKNOP_CLI_ARG_RESOLVE_URL,
    FWKNOP_CLI_ARG_NAT_LOCAL,
    FWKNOP_CLI_ARG_NAT_RAND_PORT,
    FWKNOP_CLI_ARG_NAT_PORT,
    FWKNOP_CLI_ARG_NB
} fwknop_cli_arg_t;

const char* fwknop_cli_key_tab[FWKNOP_CLI_ARG_NB] =
{
    "DIGEST_TYPE",
    "SPA_SERVER_PROTO",
    "SPA_SERVER_PORT",
    "SPA_SOURCE_PORT",
    "FW_TIMEOUT",
    "ALLOW_IP",
    "TIME_OFFSET",
    "ENCRYPTION_MODE",
    "USE_GPG",
    "USE_GPG_AGENT",
    "GPG_RECIPIENT",
    "GPG_SIGNER",
    "GPG_HOMEDIR",
    "SPOOF_USER",
    "SPOOF_SOURCE_IP",
    "ACCESS",
    "SPA_SERVER",
    "RAND_PORT",
    "KEY",
    "KEY_BASE64",
    "HMAC_DIGEST_TYPE",
    "HMAC_KEY_BASE64",
    "HMAC_KEY",
    "USE_HMAC",
    "KEY_FILE",
    "NAT_ACCESS",
    "HTTP_USER_AGENT",
    "RESOLVE_URL",
    "NAT_LOCAL",
    "NAT_RAND_PORT",
    "NAT_PORT"
};

/**
 * \brief Set a string as a Yes or No value according to a boolean (0 or 1).
 *
 * This function checks whether a value is set to zero or not, and updates a
 * string to a YES_NO parameter value.
 * The string must be zeroed before being passed to the function.
 *
 * \param val Variable to check
 * \param s String where to store the YES_NO value.
 * \param len Number of bytes avaialble for the s buffer.
 */
static void
bool_to_yesno(int val, char* s, size_t len)
{
    if (val == 0)
        strlcpy(s, PARAM_NO_VALUE, len);
    else
        strlcpy(s, PARAM_YES_VALUE, len);
}

/**
 * @brief Is a string formatted as YES string.
 *
 * @param s String to check for a YES string
 *
 * @return 1 if the string match the YES pattern, 0 otherwise
 */
static int
is_yes_str(const char *s)
{
    int valid;

    if (strcasecmp(PARAM_YES_VALUE, s) == 0)
        valid = 1;
    else
        valid = 0;

    return valid;
}

/**
 * \brief Check if a section is in a line and fetch it.
 *
 * This function parses a NULL terminated string in order to find a section,
 * something like [mysection]. If it succeeds, the stanza is retrieved.
 *
 * \param line String containing a line from the rc file to check for a section
 * \param line_size size of the line buffer
 * \param rc_section String to store the section found
 * \param rc_section_size Size of the rc_section buffer
 *
 * \return 1 if a section was found, 0 otherwise
 */
static int
is_rc_section(const char* line, uint16_t line_size, char* rc_section, uint16_t rc_section_size)
{
    char    *ndx, *emark;
    char    buf[MAX_LINE_LEN];
    int     section_found = 0;

    if (line_size < sizeof(buf))
    {
        memset (buf, 0, sizeof(buf));
        strlcpy(buf, line, sizeof(buf));

        ndx = buf;

        while(isspace(*ndx))
            ndx++;

        if(*ndx == '[')
        {
            ndx++;
            emark = strchr(ndx, ']');
            if(emark != NULL)
            {
                *emark = '\0';
                memset(rc_section, 0, rc_section_size);
                strlcpy(rc_section, ndx, rc_section_size);
                section_found = 1;
            }
            else
            {
            }
        }
    }
    else
    {
    }

    return section_found;
}

/**
 * Grab a variable and its value from a rc line.
 *
 * \param line  Line to parse for a variable
 * \param param Parameter structure where to store the variable name and its value
 *
 * \return 0 if no variable has been found, 1 otherwise.
 */
static int
is_rc_param(const char *line, TParam *param)
{
    char    var[MAX_LINE_LEN] = {0};
    char    val[MAX_LINE_LEN] = {0};
    char    *ndx;

    /* Fetch the variable and its value */
    if(sscanf(line, "%s %[^ ;\t\n\r#]", var, val) != 2)
    {
        log_msg(LOG_VERBOSITY_WARNING,
            "*Invalid entry in '%s'", line);
        return 0;
    }

    /* Remove any colon that may be on the end of the var */
    if((ndx = strrchr(var, ':')) != NULL)
        *ndx = '\0';

    /* Even though sscanf should automatically add a terminating
     * NULL byte, an assumption is made that the input arrays are
     * big enough, so we'll force a terminating NULL byte regardless
     */
    var[MAX_LINE_LEN-1] = 0x0;
    val[MAX_LINE_LEN-1] = 0x0;


    /* Copy back the val and var in the structure */
    strlcpy(param->name, var, sizeof(param->name));
    strlcpy(param->val, val, sizeof(param->val));

    return 1;
}

/* Convert a protocol string to its intger value.
*/
static int
proto_strtoint(const char *pr_str)
{
    if (strcasecmp(pr_str, "udpraw") == 0)
        return(FKO_PROTO_UDP_RAW);
    else if (strcasecmp(pr_str, "udp") == 0)
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

/**
 * \brief Return a prototype string according to a prototype integer value
 *
 * This function checks the prototype integer is valid, and write the prototype
 * string associated.
 *
 * \param proto Prototype inetger value (UDP_RAW, UDP, TCPRAW...)
 * \param proto_str Buffer to write the prototype string
 * \param proto_size size of the prototype string buffer
 *
 * \return 1 if the digest integer value is not supported, 0 otherwise
 */
static int
proto_inttostr(unsigned int proto, char* pr_str, size_t pr_size)
{
    uint8_t proto_not_valid = 0;

    memset(pr_str, 0, pr_size);

    switch (proto)
    {
        case FKO_PROTO_UDP_RAW:
            strlcpy(pr_str, "UDPRAW", pr_size);
            break;
        case FKO_PROTO_UDP:
            strlcpy(pr_str, "UDP", pr_size);
            break;
        case FKO_PROTO_TCP_RAW:
            strlcpy(pr_str, "TCPRAW", pr_size);
            break;
        case FKO_PROTO_TCP:
            strlcpy(pr_str, "TCP", pr_size);
            break;
        case FKO_PROTO_ICMP:
            strlcpy(pr_str, "ICMP", pr_size);
            break;
        default:
            proto_not_valid = 1;
            break;
    }

    return proto_not_valid;
}

/* Assign path to fwknop rc file
*/
static void
set_rc_file(char *rcfile, fko_cli_options_t *options)
{
    int     rcf_offset;
    char    *homedir;

    memset(rcfile, 0x0, MAX_PATH_LEN);

    if(options->rc_file[0] == 0x0)
    {
#ifdef WIN32
        homedir = getenv("USERPROFILE");
#else
        homedir = getenv("HOME");
#endif

        if(homedir == NULL)
        {
            log_msg(LOG_VERBOSITY_ERROR, "Warning: Unable to determine HOME directory.\n"
                " No .fwknoprc file processed.");
            exit(EXIT_FAILURE);
        }

        strlcpy(rcfile, homedir, MAX_PATH_LEN);

        rcf_offset = strlen(rcfile);

        /* Sanity check the path to .fwknoprc.
         * The preceeding path plus the path separator and '.fwknoprc' = 11
         * cannot exceed MAX_PATH_LEN.
         */
        if(rcf_offset > (MAX_PATH_LEN - 11))
        {
            log_msg(LOG_VERBOSITY_ERROR, "Warning: Path to .fwknoprc file is too long.\n"
                " No .fwknoprc file processed.");
            exit(EXIT_FAILURE);
        }

        rcfile[rcf_offset] = PATH_SEP;
        strlcat(rcfile, ".fwknoprc", MAX_PATH_LEN);
    }
    else
    {
        strlcpy(rcfile, options->rc_file, MAX_PATH_LEN);
    }

    /* Check rc file permissions - if anything other than user read/write,
     * then throw a warning.  This change was made to help ensure that the
     * client consumes a proper rc file with strict permissions set (thanks
     * to Fernando Arnaboldi from IOActive for pointing this out).
    */
    verify_file_perms_ownership(rcfile);

    return;
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
    int is_err;

    char offset_digits[MAX_TIME_STR_LEN];

    j=0;
    for (i=0; i < os_len; i++) {
        if (isdigit(offset_str[i])) {
            offset_digits[j] = offset_str[i];
            j++;
            if(j >= MAX_TIME_STR_LEN)
            {
                log_msg(LOG_VERBOSITY_ERROR, "Invalid time offset: %s", offset_str);
                exit(EXIT_FAILURE);
            }
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
        log_msg(LOG_VERBOSITY_ERROR, "Invalid time offset: %s", offset_str);
        exit(EXIT_FAILURE);
    }

    offset = strtol_wrapper(offset_digits, 0, (2 << 15),
            EXIT_UPON_ERR, &is_err);

    /* Apply the offset_type value
    */
    offset *= offset_type;

    return offset;
}

static int
create_fwknoprc(const char *rcfile)
{
    FILE *rc = NULL;
    int   rcfile_fd = -1;

    log_msg(LOG_VERBOSITY_NORMAL,"[*] Creating initial rc file: %s.\n", rcfile);

    /* Try to create the initial rcfile with user read/write rights only.
     * If the rcfile already exists, an error is returned */
    rcfile_fd = open(rcfile, FWKNOPRC_OFLAGS ,FWKNOPRC_MODE);

    // If an error occured ...
    if (rcfile_fd == -1) {
            log_msg(LOG_VERBOSITY_WARNING, "Unable to create initial rc file: %s: %s",
                rcfile, strerror(errno));
            return(-1);
    }

    // Free the rcfile descriptor
    close(rcfile_fd);

    if ((rc = fopen(rcfile, "w")) == NULL)
    {
        log_msg(LOG_VERBOSITY_WARNING, "Unable to write default setup to rcfile: %s: %s",
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
        "# preferences.  The client will use its built-in default for those items\n"
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
        "# SSH for an IP that is resolved externally, and one with a NAT request\n"
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
    );

    fclose(rc);

    return(0);
}

static int
parse_rc_param(fko_cli_options_t *options, const char *var, char * val)
{
    int tmpint, is_err;
    int conf_key_ndx;       /* Index on the fwknop conf variable in the fwknop_cli_key_tab array */
    int parse_error = 0;    /* 0 if the variable has been successfully processed, < 0 otherwise */

    log_msg(LOG_VERBOSITY_DEBUG, "add_rc_param() : Parsing variable %s...", var);

    /* Go through the fwknop_cli_arg to find out which variable
     * we should work on. */
    for(conf_key_ndx=0 ; conf_key_ndx<ARRAY_SIZE(fwknop_cli_key_tab) ; conf_key_ndx++)
    {
        if (CONF_VAR_IS(var, fwknop_cli_key_tab[conf_key_ndx]))
            break;
    }

    /* Digest Type */
    if (conf_key_ndx == FWKNOP_CLI_ARG_DIGEST_TYPE)
    {
        tmpint = digest_strtoint(val);
        if(tmpint < 0)
            parse_error = -1;
        else
            options->digest_type = tmpint;
    }
    /* Server protocol */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_SPA_SERVER_PROTO)
    {
        tmpint = proto_strtoint(val);
        if(tmpint < 0)
            parse_error = -1;
        else
            options->spa_proto = tmpint;
    }
    /* Server port */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_SPA_SERVER_PORT)
    {
        tmpint = strtol_wrapper(val, 0, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
        if(is_err == FKO_SUCCESS)
            options->spa_dst_port = tmpint;
        else
            parse_error = -1;
    }
    /* Source port */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_SPA_SOURCE_PORT)
    {
        tmpint = strtol_wrapper(val, 0, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
        if(is_err == FKO_SUCCESS)
            options->spa_src_port = tmpint;
        else
            parse_error = -1;
    }
    /* Firewall rule timeout */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_FW_TIMEOUT)
    {
        tmpint = strtol_wrapper(val, 0, (2 << 15), NO_EXIT_UPON_ERR, &is_err);
        if(is_err == FKO_SUCCESS)
            options->fw_timeout = tmpint;
        else
            parse_error = -1;
    }
    /* Allow IP */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_ALLOW_IP)
    {
        /* In case this was set previously
        */
        options->resolve_ip_http = 0;

        /* use source, resolve, or an actual IP
        */
        if(strcasecmp(val, "source") == 0)
            strlcpy(options->allow_ip_str, "0.0.0.0", sizeof(options->allow_ip_str));
        else if(strcasecmp(val, "resolve") == 0)
            options->resolve_ip_http = 1;
        else /* Assume IP address */
            strlcpy(options->allow_ip_str, val, sizeof(options->allow_ip_str));
    }
    /* Time Offset */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_TIME_OFFSET)
    {
        if(val[0] == '-')
        {
            val++;
            options->time_offset_minus = parse_time_offset(val);
        }
        else
            options->time_offset_plus = parse_time_offset(val);
    }
    /* symmetric encryption mode */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_ENCRYPTION_MODE)
    {
        tmpint = enc_mode_strtoint(val);
        if(tmpint < 0)
            parse_error = -1;
        else
            options->encryption_mode = tmpint;
    }
    /* Use GPG ? */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_USE_GPG)
    {
        if (is_yes_str(val))
            options->use_gpg = 1;
        else;
    }
    /* Use GPG Agent ? */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_USE_GPG_AGENT)
    {
        if (is_yes_str(val))
            options->use_gpg_agent = 1;
        else;
    }
    /* GPG Recipient */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_GPG_RECIPIENT)
    {
        strlcpy(options->gpg_recipient_key, val, sizeof(options->gpg_recipient_key));
    }
    /* GPG Signer */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_GPG_SIGNER)
    {
        strlcpy(options->gpg_signer_key, val, sizeof(options->gpg_signer_key));
    }
    /* GPG Homedir */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_GPG_HOMEDIR)
    {
        strlcpy(options->gpg_home_dir, val, sizeof(options->gpg_home_dir));
    }
    /* Spoof User */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_SPOOF_USER)
    {
        strlcpy(options->spoof_user, val, sizeof(options->spoof_user));
    }
    /* Spoof Source IP */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_SPOOF_SOURCE_IP)
    {
        strlcpy(options->spoof_ip_src_str, val, sizeof(options->spoof_ip_src_str));
    }
    /* ACCESS request */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_ACCESS)
    {
        strlcpy(options->access_str, val, sizeof(options->access_str));
    }
    /* SPA Server (destination) */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_SPA_SERVER)
    {
        strlcpy(options->spa_server_str, val, sizeof(options->spa_server_str));
    }
    /* Rand port ? */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_RAND_PORT)
    {
        if (is_yes_str(val))
            options->rand_port = 1;
        else;
    }
    /* Rijndael key */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_KEY_RIJNDAEL)
    {
        strlcpy(options->key, val, sizeof(options->key));
        options->have_key = 1;
    }
    /* Rijndael key (base-64 encoded) */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_KEY_RIJNDAEL_BASE64)
    {
        if (! is_base64((unsigned char *) val, strlen(val)))
        {
            log_msg(LOG_VERBOSITY_WARNING,
                "KEY_BASE64 argument '%s' doesn't look like base64-encoded data.",
                val);
            parse_error = -1;
        }
        strlcpy(options->key_base64, val, sizeof(options->key_base64));
        options->have_base64_key = 1;
    }
    /* HMAC digest type */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_HMAC_DIGEST_TYPE)
    {
        tmpint = hmac_digest_strtoint(val);
        if(tmpint < 0)
        {
            log_msg(LOG_VERBOSITY_WARNING,
                    "HMAC_DIGEST_TYPE argument '%s' must be one of {md5,sha1,sha256,sha384,sha512}",
                    val);
            parse_error = -1;
        }
        else
        {
            options->hmac_type = tmpint;
        }
    }
    /* HMAC key (base64 encoded) */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_KEY_HMAC_BASE64)
    {
        if (! is_base64((unsigned char *) val, strlen(val)))
        {
            log_msg(LOG_VERBOSITY_WARNING,
                "HMAC_KEY_BASE64 argument '%s' doesn't look like base64-encoded data.",
                val);
            parse_error = -1;
        }
        strlcpy(options->hmac_key_base64, val, sizeof(options->hmac_key_base64));
        options->have_hmac_base64_key = 1;
        options->use_hmac = 1;
    }

    /* HMAC key */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_KEY_HMAC)
    {
        strlcpy(options->hmac_key, val, sizeof(options->hmac_key));
        options->have_hmac_key = 1;
        options->use_hmac = 1;
    }

    /* Key file */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_KEY_FILE)
    {
        strlcpy(options->get_key_file, val, sizeof(options->get_key_file));
    }
    /* NAT Access Request */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_NAT_ACCESS)
    {
        strlcpy(options->nat_access_str, val, sizeof(options->nat_access_str));
    }
    /* HTTP User Agent */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_HTTP_USER_AGENT)
    {
        strlcpy(options->http_user_agent, val, sizeof(options->http_user_agent));
    }
    /* Resolve URL */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_RESOLVE_URL)
    {
        if(options->resolve_url != NULL)
            free(options->resolve_url);
        tmpint = strlen(val)+1;
        options->resolve_url = malloc(tmpint);
        if(options->resolve_url == NULL)
        {
            log_msg(LOG_VERBOSITY_ERROR,"Memory allocation error for resolve URL.");
            exit(EXIT_FAILURE);
        }
        strlcpy(options->resolve_url, val, tmpint);
    }
    /* NAT Local ? */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_NAT_LOCAL)
    {
        if (is_yes_str(val))
            options->nat_local = 1;
        else;
    }
    /* NAT rand port ? */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_NAT_RAND_PORT)
    {
        if (is_yes_str(val))
            options->nat_rand_port = 1;
        else;
    }
    /* NAT port */
    else if (conf_key_ndx == FWKNOP_CLI_ARG_NAT_PORT)
    {
        tmpint = strtol_wrapper(val, 0, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
        if(is_err == FKO_SUCCESS)
            options->nat_port = tmpint;
        else
            parse_error = -1;
    }
    /* The variable is not a configuration variable */
    else
    {
        parse_error = -1;
    }

    return(parse_error);
}

/**
 * \brief Write a cli parameter to a file handle
 *
 * This function writes into a file handle a command line parameter
 *
 * \param fhandle File handle to write the new parameter to
 * \param arg_ndx Argument index
 * \param options FKO command line option structure
 */
static void
add_rc_param(FILE* fhandle, uint16_t arg_ndx, fko_cli_options_t *options)
{
    char    val[MAX_LINE_LEN]  = {0};

    if (arg_ndx >= FWKNOP_CLI_ARG_NB)
        return;

    if (fhandle == NULL)
        return;

    /* Zero the val buffer */
    memset(val, 0, sizeof(val));

    /* Selecty the argument to add and store its string value into val */
    switch (arg_ndx)
    {
        case FWKNOP_CLI_ARG_DIGEST_TYPE :
            digest_inttostr(options->digest_type, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_SPA_SERVER_PROTO :
            proto_inttostr(options->spa_proto, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_SPA_SERVER_PORT :
            snprintf(val, sizeof(val)-1, "%d", options->spa_dst_port);
            break;
        case FWKNOP_CLI_ARG_SPA_SOURCE_PORT :
            snprintf(val, sizeof(val)-1, "%d", options->spa_src_port);
            break;
        case FWKNOP_CLI_ARG_FW_TIMEOUT :
            snprintf(val, sizeof(val)-1, "%d", options->fw_timeout);
            break;
        case FWKNOP_CLI_ARG_ALLOW_IP :
            strlcpy(val, options->allow_ip_str, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_TIME_OFFSET :
            if (options->time_offset_minus != 0)
                snprintf(val, sizeof(val)-1, "-%d", options->time_offset_minus);
            else if (options->time_offset_plus != 0)
                snprintf(val, sizeof(val)-1, "%d", options->time_offset_plus);
            else
            {
            }
            break;
        case FWKNOP_CLI_ARG_ENCRYPTION_MODE :
            enc_mode_inttostr(options->encryption_mode, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_USE_GPG :
            bool_to_yesno(options->use_gpg, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_USE_GPG_AGENT :
            bool_to_yesno(options->use_gpg_agent, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_GPG_RECIPIENT :
            strlcpy(val, options->gpg_recipient_key, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_GPG_SIGNER :
            strlcpy(val, options->gpg_signer_key, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_GPG_HOMEDIR :
            strlcpy(val, options->gpg_home_dir, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_SPOOF_USER :
            strlcpy(val, options->spoof_user, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_SPOOF_SOURCE_IP :
            strlcpy(val, options->spoof_ip_src_str, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_ACCESS :
            strlcpy(val, options->access_str, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_SPA_SERVER :
            strlcpy(val, options->spa_server_str, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_RAND_PORT :
            bool_to_yesno(options->rand_port, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_KEY_FILE :
            strlcpy(val, options->get_key_file, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_KEY_RIJNDAEL:
            strlcpy(val, options->key, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_KEY_RIJNDAEL_BASE64:
            strlcpy(val, options->key_base64, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_KEY_HMAC_BASE64:
            strlcpy(val, options->hmac_key_base64, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_KEY_HMAC:
            strlcpy(val, options->hmac_key, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_HMAC_DIGEST_TYPE :
            hmac_digest_inttostr(options->hmac_type, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_USE_HMAC :
            bool_to_yesno(options->use_hmac, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_NAT_ACCESS :
            strlcpy(val, options->nat_access_str, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_HTTP_USER_AGENT :
            strlcpy(val, options->http_user_agent, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_RESOLVE_URL :
            if (options->resolve_url != NULL)
                strlcpy(val, options->resolve_url, sizeof(val));
            else
            {
            }
            break;
        case FWKNOP_CLI_ARG_NAT_LOCAL :
            bool_to_yesno(options->nat_local, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_NAT_RAND_PORT :
            bool_to_yesno(options->nat_rand_port, val, sizeof(val));
            break;
        case FWKNOP_CLI_ARG_NAT_PORT :
            snprintf(val, sizeof(val)-1, "%d", options->nat_port);
            break;
        default:
            log_msg(LOG_VERBOSITY_WARNING, "Warning from add_rc_param() : Bad command line argument %u", arg_ndx);
            return;
    }

    log_msg(LOG_VERBOSITY_DEBUG, "add_rc_param() : Updating param (%u) %s to %s",
                arg_ndx, fwknop_cli_key_tab[arg_ndx], val);

    fprintf(fhandle, RC_PARAM_TEMPLATE, fwknop_cli_key_tab[arg_ndx], val);
}

/**
 * Process the fwknoprc file and lookup a section to extract its settings.
 *
 * This function aims at loading the settings for a specific section in
 * a fwknoprc file.
 *
 * \param section_name  Name of the section to lookup.
 * \param options       Fwknop option structure where settings have to
 *                      be stored.
 *
 * \return 0 if the section has been found and processed successfully
 *         a negative value if one or more errors occured
 */
static int
process_rc_section(char *section_name, fko_cli_options_t *options)
{
    FILE    *rc;
    int     line_num = 0, do_exit = 0;
    char    line[MAX_LINE_LEN];
    char    rcfile[MAX_PATH_LEN];
    char    curr_stanza[MAX_LINE_LEN] = {0};
    TParam  param;
    int     rc_section_found = 0;

    set_rc_file(rcfile, options);

    /* Open the rc file for reading, if it does not exist, then create
     * an initial .fwknoprc file with defaults and go on.
    */
    if ((rc = fopen(rcfile, "r")) == NULL)
    {
        if(errno == ENOENT)
        {
            if(create_fwknoprc(rcfile) != 0)
                return -1;
        }
        else
            log_msg(LOG_VERBOSITY_WARNING, "Unable to open rc file: %s: %s",
                rcfile, strerror(errno));

        return -1;
    }

    log_msg(LOG_VERBOSITY_DEBUG, "process_rc_section() : Parsing section '%s' ...",
                section_name);

    while ((fgets(line, MAX_LINE_LEN, rc)) != NULL)
    {
        line_num++;
        line[MAX_LINE_LEN-1] = '\0';

        /* Get past comments and empty lines (note: we only look at the
         * first character.
        */
        if(IS_EMPTY_LINE(line[0]))
            continue;

        /* Check which section we are working on */
        if (is_rc_section(line, strlen(line), curr_stanza, sizeof(curr_stanza)))
        {
            rc_section_found = (strcasecmp(curr_stanza, section_name) == 0) ? 1 : 0;

            if (strcasecmp(curr_stanza, options->use_rc_stanza) == 0)
                options->got_named_stanza = 1;

            continue;
        }

        /* We are not in the good section */
        else if (rc_section_found == 0)
            continue;

        /* We have not found a valid parameter */
        else if (is_rc_param(line, &param) == 0)
            continue;

        /* We have a valid parameter */
        else
        {
           if(parse_rc_param(options, param.name, param.val) < 0)
            {
                log_msg(LOG_VERBOSITY_WARNING,
                    "Parameter error in %s, line %i: var=%s, val=%s",
                    rcfile, line_num, param.name, param.val);
                do_exit = 1;
            }
        }
    }

    fclose(rc);

    if (do_exit)
        exit(EXIT_FAILURE);

    return 0;
}

/**
 * \brief Update the user rc file with the new parameters for a selected stanza.
 *
 * This function writes the new configuration in a temporary file and renames it
 * as the new rc file afterwards. All of the previous parameters for the
 * selected stanza are removed and replaced by the arguments from the command
 * line.
 *
 * \param options structure containing all of the fko settings
 * \param args_bitmask command line argument bitmask
 */
static void
update_rc(fko_cli_options_t *options, uint32_t args_bitmask)
{
    FILE        *rc;
    FILE        *rc_update;
    int         stanza_found = 0;
    int         stanza_updated = 0;
    char        line[MAX_LINE_LEN];
    char        rcfile[MAX_PATH_LEN];
    char        rcfile_update[MAX_PATH_LEN];
    char        curr_stanza[MAX_LINE_LEN] = {0};
    uint16_t    arg_ndx = 0;
    int         rcfile_fd = -1;

    memset(rcfile, 0, MAX_PATH_LEN);
    memset(rcfile_update, 0, MAX_PATH_LEN);

    set_rc_file(rcfile, options);

    strlcpy(rcfile_update, rcfile, sizeof(rcfile_update));
    strlcat(rcfile_update, ".updated", sizeof(rcfile_update));

    /* Create a new temporary rc file */
    rcfile_fd = open(rcfile_update, FWKNOPRC_OFLAGS, FWKNOPRC_MODE);
    if (rcfile_fd == -1)
    {
            log_msg(LOG_VERBOSITY_WARNING,
                    "update_rc() : Unable to create temporary rc file: %s: %s",
                    rcfile_update, strerror(errno));
            return;
    }
    close(rcfile_fd);

    /* Open the current rcfile and a temporary one respectively in read and
     * write mode */
    if ((rc = fopen(rcfile, "r")) == NULL)
    {
        log_msg(LOG_VERBOSITY_WARNING,
                "update_rc() : Unable to open rc file: %s: %s",
                rcfile, strerror(errno));
        return;
    }

    if ((rc_update = fopen(rcfile_update, "w")) == NULL)
    {
        log_msg(LOG_VERBOSITY_WARNING,
                "update_rc() : Unable to open rc file: %s: %s",
                rcfile_update, strerror(errno));
    }

    /* Go though the file line by line */
    stanza_found = 0;
    while ((fgets(line, MAX_LINE_LEN, rc)) != NULL)
    {
        line[MAX_LINE_LEN-1] = '\0';

        /* If we find a section... */
        if(is_rc_section(line, strlen(line), curr_stanza, sizeof(curr_stanza)) == 1)
        {
            /* and this is the one we are looking for, we add the new settings */
            if (strncasecmp(curr_stanza, options->use_rc_stanza, MAX_LINE_LEN)==0)
            {
                stanza_found = 1;
                fprintf(rc_update, RC_SECTION_TEMPLATE, curr_stanza);

                log_msg(LOG_VERBOSITY_DEBUG, "update_rc() : Updating %s stanza", curr_stanza);

                for (arg_ndx=0 ; arg_ndx<FWKNOP_CLI_ARG_NB ; arg_ndx++)
                {
                    if (FWKNOP_CLI_ARG_BM(arg_ndx) & args_bitmask)
                        add_rc_param(rc_update, arg_ndx, options);
                }

                stanza_updated = 1;

                continue;
            }
            /* otherwise we disable the stanza since it is another section */
            else
              stanza_found = 0;
        }

        /* For the current section we do not add previous settings until we
         * find an empty line*/
        if (stanza_found)
        {
            if (!IS_EMPTY_LINE(line[0]))
                continue;
            else
                stanza_found = 0;
        }

        /* Add the line to the new rcfile */
        fprintf(rc_update, "%s", line);
    }

    /* If the stanza has not been found, we append the settings to the file,
     * othewise we already updated it earlier. */
    if (stanza_updated == 0)
    {
        fprintf(rc_update, "\n[%s]\n", options->use_rc_stanza);

        log_msg(LOG_VERBOSITY_DEBUG, "update_rc() : Updating %s stanza", curr_stanza);

        for (arg_ndx=0 ; arg_ndx<FWKNOP_CLI_ARG_NB ; arg_ndx++)
        {
            if (FWKNOP_CLI_ARG_BM(arg_ndx) & args_bitmask)
                add_rc_param(rc_update, arg_ndx, options);
        }
    }

    /* Close file handles */
    fclose(rc);
    fclose(rc_update);

    /* Renamed the temporary file as the new rc file */
    if (remove(rcfile) != 0)
    {
        log_msg(LOG_VERBOSITY_WARNING,
                "update_rc() : Unable to remove %s to %s : %s",
                rcfile_update, rcfile, strerror(errno));
    }

    if (rename(rcfile_update, rcfile) != 0)
    {
        log_msg(LOG_VERBOSITY_WARNING,
                "update_rc() : Unable to rename %s to %s",
                rcfile_update, rcfile);
    }
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
        && !options->key_gen
        && !options->version
        && !options->show_last_command
        && !options->run_last_command)
    {
        if ( (options->use_rc_stanza[0] != 0x0)
            && (options->got_named_stanza == 0)
            && (options->save_rc_stanza == 0) )
        {
            log_msg(LOG_VERBOSITY_ERROR,
                    "Named configuration stanza: [%s] was not found.",
                    options->use_rc_stanza);

            exit(EXIT_FAILURE);
        }

        if ( (options->save_rc_stanza == 1)  && (options->use_rc_stanza[0] == 0) )
        {
            log_msg(LOG_VERBOSITY_ERROR,
                    "The option --save-rc-stanza must be used with the "
                    "--named-config option to specify the stanza to update.");
            exit(EXIT_FAILURE);
        }

        if (options->spa_server_str[0] == 0x0)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                "Must use --destination unless --test mode is used");
            exit(EXIT_FAILURE);
        }

        if (options->resolve_url != NULL)
            options->resolve_ip_http = 1;

        if (!options->resolve_ip_http && options->allow_ip_str[0] == 0x0)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                "Must use one of [-s|-R|-a] to specify IP for SPA access.");
            exit(EXIT_FAILURE);
        }
    }

    if(options->resolve_ip_http || options->spa_proto == FKO_PROTO_HTTP)
        if (options->http_user_agent[0] == '\0')
            snprintf(options->http_user_agent, HTTP_MAX_USER_AGENT_LEN,
                "%s%s", "Fwknop/", MY_VERSION);

    if(options->http_proxy[0] != 0x0 && options->spa_proto != FKO_PROTO_HTTP)
    {
        log_msg(LOG_VERBOSITY_ERROR,
            "Cannot set --http-proxy with a non-HTTP protocol.");
        exit(EXIT_FAILURE);
    }

    /* If we are using gpg, we must at least have the recipient set.
    */
    if(options->use_gpg)
    {
        if(options->gpg_recipient_key == NULL
            || strlen(options->gpg_recipient_key) == 0)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                "Must specify --gpg-recipient-key when GPG is used.");
            exit(EXIT_FAILURE);
        }
    }

    /* Validate HMAC digest type
    */
    if(options->use_hmac && options->hmac_type == FKO_HMAC_UNKNOWN)
        options->hmac_type = FKO_DEFAULT_HMAC_MODE;

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

    options->key_len      = FKO_DEFAULT_KEY_LEN;
    options->hmac_key_len = FKO_DEFAULT_HMAC_KEY_LEN;
    options->hmac_type    = FKO_HMAC_UNKNOWN;  /* updated when HMAC key is used */

    options->spa_icmp_type = ICMP_ECHOREPLY;  /* only used in '-P icmp' mode */
    options->spa_icmp_code = 0;               /* only used in '-P icmp' mode */

    return;
}

/* Initialize program configuration via config file and/or command-line
 * switches.
*/
void
config_init(fko_cli_options_t *options, int argc, char **argv)
{
    int         cmd_arg, index, is_err;
    uint32_t    cli_arg_bitmask = 0;

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
                strlcpy(options->use_rc_stanza, optarg, sizeof(options->use_rc_stanza));
                break;
            case SAVE_RC_STANZA:
                options->save_rc_stanza = 1;
                break;
            case 'E':
                strlcpy(options->args_save_file, optarg, sizeof(options->args_save_file));
                break;
            case RC_FILE_PATH:
                strlcpy(options->rc_file, optarg, sizeof(options->rc_file));
                break;
            case 'v':
                options->verbose++;
                break;
        }
    }

    /* Update the verbosity level for the log module */
    log_set_verbosity(LOG_DEFAULT_VERBOSITY + options->verbose);

    /* First process the .fwknoprc file.
    */
    process_rc_section(RC_SECTION_DEFAULT, options);

    /* Load the user specified stanza from .fwknoprc file */
    if ( (options->got_named_stanza) && (options->save_rc_stanza == 0) )
        process_rc_section(options->use_rc_stanza, options);

    /* Reset the options index so we can run through them again.
    */
    optind = 0;

    while ((cmd_arg = getopt_long(argc, argv,
            GETOPTS_OPTION_STRING, cmd_opts, &index)) != -1) {

        switch(cmd_arg) {
            case 'a':
                strlcpy(options->allow_ip_str, optarg, sizeof(options->allow_ip_str));
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_ALLOW_IP);
                break;
            case 'A':
                strlcpy(options->access_str, optarg, sizeof(options->access_str));
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_ACCESS);
                break;
            case 'b':
                options->save_packet_file_append = 1;
                break;
            case 'B':
                strlcpy(options->save_packet_file, optarg, sizeof(options->save_packet_file));
                break;
            case 'C':
                strlcpy(options->server_command, optarg, sizeof(options->server_command));
                break;
            case 'D':
                strlcpy(options->spa_server_str, optarg, sizeof(options->spa_server_str));
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_SPA_SERVER);
                break;
            case 'E':
                strlcpy(options->args_save_file, optarg, sizeof(options->args_save_file));
                break;
            case 'f':
                options->fw_timeout = strtol_wrapper(optarg, 0,
                        (2 << 16), NO_EXIT_UPON_ERR, &is_err);
                if(is_err != FKO_SUCCESS)
                {
                    log_msg(LOG_VERBOSITY_ERROR, "--fw-timeout must be within [%d-%d]",
                            0, (2 << 16));
                    exit(EXIT_FAILURE);
                }
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_FW_TIMEOUT);
                break;
            case 'g':
            case GPG_ENCRYPTION:
                options->use_gpg = 1;
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_USE_GPG);
                break;
            case 'G':
                strlcpy(options->get_key_file, optarg, sizeof(options->get_key_file));
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_KEY_FILE);
                break;
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
            case 'H':
                options->spa_proto = FKO_PROTO_HTTP;
                strlcpy(options->http_proxy, optarg, sizeof(options->http_proxy));
                break;
            case 'k':
                options->key_gen = 1;
                break;
            case 'K':
                options->key_gen = 1;
                strlcpy(options->key_gen_file, optarg, sizeof(options->key_gen_file));
                break;
            case KEY_RIJNDAEL:
                strlcpy(options->key, optarg, sizeof(options->key));
                options->have_key = 1;
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_KEY_RIJNDAEL);
                break;
            case KEY_RIJNDAEL_BASE64:
                if (! is_base64((unsigned char *) optarg, strlen(optarg)))
                {
                    log_msg(LOG_VERBOSITY_ERROR,
                        "Base64 encoded Rijndael argument '%s' doesn't look like base64-encoded data.",
                        optarg);
                    exit(EXIT_FAILURE);
                }
                strlcpy(options->key_base64, optarg, sizeof(options->key_base64));
                options->have_base64_key = 1;
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_KEY_RIJNDAEL_BASE64);
                break;
            case KEY_HMAC_BASE64:
                if (! is_base64((unsigned char *) optarg, strlen(optarg)))
                {
                    log_msg(LOG_VERBOSITY_ERROR,
                        "Base64 encoded HMAC argument '%s' doesn't look like base64-encoded data.",
                        optarg);
                    exit(EXIT_FAILURE);
                }
                strlcpy(options->hmac_key_base64, optarg, sizeof(options->hmac_key_base64));
                options->have_hmac_base64_key = 1;
                options->use_hmac = 1;
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_KEY_HMAC_BASE64);
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_USE_HMAC);
            case KEY_HMAC:
                strlcpy(options->hmac_key, optarg, sizeof(options->hmac_key));
                options->have_hmac_key = 1;
                options->use_hmac = 1;
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_KEY_HMAC);
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_USE_HMAC);
            case KEY_LEN:
                options->key_len = strtol_wrapper(optarg, 1,
                        MAX_KEY_LEN, NO_EXIT_UPON_ERR, &is_err);
                if(is_err != FKO_SUCCESS)
                {
                    log_msg(LOG_VERBOSITY_ERROR,
                            "Invalid key length '%s', must be in [%d-%d]",
                            optarg, 1, MAX_KEY_LEN);
                    exit(EXIT_FAILURE);
                }
                break;
            case HMAC_DIGEST_TYPE:
                if((options->hmac_type = hmac_digest_strtoint(optarg)) < 0)
                {
                    log_msg(LOG_VERBOSITY_ERROR,
                        "* Invalid hmac digest type: %s, use {md5,sha1,sha256,sha384,sha512}",
                        optarg);
                    exit(EXIT_FAILURE);
                }
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_HMAC_DIGEST_TYPE);
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_USE_HMAC);
                options->use_hmac = 1;
                break;
            case HMAC_KEY_LEN:
                options->hmac_key_len = strtol_wrapper(optarg, 1,
                        MAX_KEY_LEN, NO_EXIT_UPON_ERR, &is_err);
                if(is_err != FKO_SUCCESS)
                {
                    log_msg(LOG_VERBOSITY_ERROR,
                            "Invalid hmac key length '%s', must be in [%d-%d]",
                            optarg, 1, MAX_KEY_LEN);
                    exit(EXIT_FAILURE);
                }
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_USE_HMAC);
                options->use_hmac = 1;
                break;
            case SPA_ICMP_TYPE:
                options->spa_icmp_type = strtol_wrapper(optarg, 0,
                        MAX_ICMP_TYPE, NO_EXIT_UPON_ERR, &is_err);
                if(is_err != FKO_SUCCESS)
                {
                    log_msg(LOG_VERBOSITY_ERROR,
                            "Invalid icmp type '%s', must be in [%d-%d]",
                            optarg, 0, MAX_ICMP_TYPE);
                    exit(EXIT_FAILURE);
                }
                break;
            case SPA_ICMP_CODE:
                options->spa_icmp_code = strtol_wrapper(optarg, 0,
                        MAX_ICMP_CODE, NO_EXIT_UPON_ERR, &is_err);
                if(is_err != FKO_SUCCESS)
                {
                    log_msg(LOG_VERBOSITY_ERROR,
                            "Invalid icmp code '%s', must be in [%d-%d]",
                            optarg, 0, MAX_ICMP_CODE);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'l':
                options->run_last_command = 1;
                break;
            case 'm':
            case FKO_DIGEST_NAME:
                if((options->digest_type = digest_strtoint(optarg)) < 0)
                {
                    log_msg(LOG_VERBOSITY_ERROR,
                        "* Invalid digest type: %s, use {md5,sha1,sha256,sha384,sha512}",
                    optarg);
                    exit(EXIT_FAILURE);
                }
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_DIGEST_TYPE);
                break;
            case 'M':
            case ENCRYPTION_MODE:
                if((options->encryption_mode = enc_mode_strtoint(optarg)) < 0)
                {
                    log_msg(LOG_VERBOSITY_ERROR,
                        "* Invalid encryption mode: %s, use {cbc,ecb}",
                    optarg);
                    exit(EXIT_FAILURE);
                }
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_ENCRYPTION_MODE);
                break;
            case NO_SAVE_ARGS:
                options->no_save_args = 1;
                break;
            case 'n':
                /* We already handled this earlier, so we do nothing here
                */
                break;
            case 'N':
                strlcpy(options->nat_access_str, optarg, sizeof(options->nat_access_str));
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_NAT_ACCESS);
                break;
            case 'p':
                options->spa_dst_port = strtol_wrapper(optarg, 0,
                        MAX_PORT, EXIT_UPON_ERR, &is_err);
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_SPA_SERVER_PORT);
                break;
            case 'P':
                if((options->spa_proto = proto_strtoint(optarg)) < 0)
                {
                    log_msg(LOG_VERBOSITY_ERROR, "Unrecognized protocol: %s", optarg);
                    exit(EXIT_FAILURE);
                }
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_SPA_SERVER_PROTO);
                break;
            case 'Q':
                strlcpy(options->spoof_ip_src_str, optarg, sizeof(options->spoof_ip_src_str));
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_SPOOF_SOURCE_IP);
                break;
            case RC_FILE_PATH:
                strlcpy(options->rc_file, optarg, sizeof(options->rc_file));
                break;
            case 'r':
                options->rand_port = 1;
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_RAND_PORT);
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
                    log_msg(LOG_VERBOSITY_ERROR, "Memory allocation error for resolve URL.");
                    exit(EXIT_FAILURE);
                }
                strlcpy(options->resolve_url, optarg, strlen(optarg)+1);
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_RESOLVE_URL);
                break;
            case SHOW_LAST_ARGS:
                options->show_last_command = 1;
                break;
            case 's':
                strlcpy(options->allow_ip_str, "0.0.0.0", sizeof(options->allow_ip_str));
                break;
            case 'S':
                options->spa_src_port = strtol_wrapper(optarg, 0,
                        MAX_PORT, EXIT_UPON_ERR, &is_err);
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_SPA_SOURCE_PORT);
                break;
            case SAVE_RC_STANZA:
                /* We already handled this earlier, so we do nothing here
                */
                break;
            case 'T':
                options->test = 1;
                break;
            case 'u':
                strlcpy(options->http_user_agent, optarg, sizeof(options->http_user_agent));
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_HTTP_USER_AGENT);
                break;
            case 'U':
                strlcpy(options->spoof_user, optarg, sizeof(options->spoof_user));
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_SPOOF_USER);
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
                strlcpy(options->gpg_recipient_key, optarg, sizeof(options->gpg_recipient_key));
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_USE_GPG);
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_GPG_RECIPIENT);
                break;
            case GPG_SIGNER_KEY:
                options->use_gpg = 1;
                strlcpy(options->gpg_signer_key, optarg, sizeof(options->gpg_signer_key));
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_USE_GPG);
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_GPG_SIGNER);
                break;
            case GPG_HOME_DIR:
                options->use_gpg = 1;
                strlcpy(options->gpg_home_dir, optarg, sizeof(options->gpg_home_dir));
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_USE_GPG);
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_GPG_HOMEDIR);
                break;
            case GPG_AGENT:
                options->use_gpg = 1;
                options->use_gpg_agent = 1;
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_USE_GPG);
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_USE_GPG_AGENT);
                break;
            case NAT_LOCAL:
                options->nat_local = 1;
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_NAT_LOCAL);
                break;
            case NAT_RAND_PORT:
                options->nat_rand_port = 1;
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_NAT_RAND_PORT);
                break;
            case NAT_PORT:
                options->nat_port = strtol_wrapper(optarg, 0,
                        MAX_PORT, EXIT_UPON_ERR, &is_err);
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_NAT_PORT);
                break;
            case TIME_OFFSET_PLUS:
                options->time_offset_plus = parse_time_offset(optarg);
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_TIME_OFFSET);
                break;
            case TIME_OFFSET_MINUS:
                options->time_offset_minus = parse_time_offset(optarg);
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_TIME_OFFSET);
                break;
            case USE_HMAC:
                cli_arg_bitmask |= FWKNOP_CLI_ARG_BM(FWKNOP_CLI_ARG_USE_HMAC);
                options->use_hmac = 1;
                break;
            default:
                usage();
                exit(EXIT_FAILURE);
        }
    }

    /* Now that we have all of our options set, we can validate them */
    validate_options(options);

    /* We can upgrade our settings with the parameters set on the command
     * line by the user */
    if (options->save_rc_stanza == 1)
        update_rc(options, cli_arg_bitmask);

    return;
}

/* Print usage message...
*/
void
usage(void)
{
    log_msg(LOG_VERBOSITY_NORMAL,
            "\n%s client version %s\n%s - http://%s/fwknop/\n",
            MY_NAME, MY_VERSION, MY_DESC, HTTP_RESOLVE_HOST);
    log_msg(LOG_VERBOSITY_NORMAL,
      "Usage: fwknop -A <port list> [-s|-R|-a] -D <spa_server> [options]\n\n"
      " -h, --help                  Print this usage message and exit.\n"
      " -A, --access                Provide a list of ports/protocols to open\n"
      "                             on the server.\n"
      " -B, --save-packet           Save the generated packet data to the\n"
      "                             specified file.\n"
      " -b, --save-packet-append    Append the generated packet data to the\n"
      "                             file specified with the -B option.\n"
      " -a, --allow-ip              Specify IP address to allow within the SPA\n"
      "                             packet.\n"
      " -C, --server-cmd            Specify a command that the fwknop server will\n"
      "                             execute on behalf of the fwknop client..\n"
      " -D, --destination           Specify the IP address of the fwknop server.\n"
      " -n, --named-config          Specify an named configuration stanza in the\n"
      "                             '$HOME/.fwknoprc' file to provide some of all\n"
      "                             of the configuration parameters.\n"
      "                             If more arguments are set through the command\n"
      "                             line, the configuration is updated accordingly\n"
      " -N, --nat-access            Gain NAT access to an internal service.\n"
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
      " -k, --key-gen               Generate SPA Rijndael + HMAC keys.\n"
      " -K, --key-gen-file          Write generated Rijndael + HMAC keys to a\n"
      "                             file\n"
      "     --key-rijndael          Specify the Rijndael key. Since the password is\n"
      "                             visible to utilities (like 'ps' under Unix) this\n"
      "                             form should only be used where security is not\n"
      "                             important.\n"
      "     --key-base64-rijndael   Specify the base64 encoded Rijndael key. Since\n"
      "                             the password is visible to utilities (like 'ps'\n"
      "                             under Unix) this form should only be used where\n"
      "                             security is not important.\n"
      "     --key-base64-hmac       Specify the base64 encoded HMAC key. Since the\n"
      "                             password is visible to utilities (like 'ps'\n"
      "                             under Unix) this form should only be used where\n"
      "                             security is not important.\n"
      " -r, --rand-port             Send the SPA packet over a randomly assigned\n"
      "                             port (requires a broader pcap filter on the\n"
      "                             server side than the default of udp 62201).\n"
      " -T, --test                  Build the SPA packet but do not send it over\n"
      "                             the network.\n"
      " -v, --verbose               Set verbose mode (may specify multiple times).\n"
      " -V, --version               Print version number.\n"
      " -m, --digest-type           Specify the message digest algorithm to use.\n"
      "                             (md5, sha1, sha256, sha384, or sha512). The\n"
      "                             default is sha256.\n"
      " -f, --fw-timeout            Specify SPA server firewall timeout from the\n"
      "                             client side.\n"
      "     --hmac-digest-type      Set the HMAC digest algorithm (default is\n"
      "                             sha256). Options are md5, sha1, sha256,\n"
      "                             sha384, or sha512.\n"
      "     --icmp-type             Set the ICMP type (used with '-P icmp')\n"
      "     --icmp-code             Set the ICMP code (used with '-P icmp')\n"
      "     --gpg-encryption        Use GPG encryption (default is Rijndael).\n"
      "     --gpg-recipient-key     Specify the recipient GPG key name or ID.\n"
      "     --gpg-signer-key        Specify the signer's GPG key name or ID.\n"
      "     --gpg-home-dir          Specify the GPG home directory.\n"
      "     --gpg-agent             Use GPG agent if available.\n"
      "     --no-save-args          Do not save fwknop command line args to the\n"
      "                             $HOME/fwknop.run file\n"
      "     --rc-file               Specify path to the fwknop rc file (default\n"
      "                             is $HOME/.fwknoprc)\n"
      "     --save-rc-stanza        Save command line arguments to the\n"
      "                             $HOME/.fwknoprc stanza specified with the\n"
      "                             -n option.\n"
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
    );

    return;
}

