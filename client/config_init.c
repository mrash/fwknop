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

#define RC_PARAM_TEMPLATE           "%-24s    %s\n"                     /*!< Template to define param = val in a rc file */
#define RC_SECTION_DEFAULT          "default"                           /*!< Name of the default section in fwknoprc */
#define RC_SECTION_TEMPLATE         "[%s]\n"                            /*!< Template to define a section in a rc file */
#define FWKNOPRC_OFLAGS             (O_WRONLY|O_CREAT|O_EXCL)           /*!< O_flags used to create an fwknoprc file with the open function */
#define FWKNOPRC_MODE               (S_IRUSR|S_IWUSR)                   /*!< mode used to create an fwknoprc file with the open function */
#define PARAM_YES_VALUE             "Y"                                 /*!< String which represents a YES value for a parameter in fwknoprc */
#define PARAM_NO_VALUE              "N"                                 /*!< String which represents a NO value for a parameter in fwknoprc */
#define POSITION_TO_BITMASK(x)      ((uint32_t)(1) << ((x) % 32))       /*!< Macro do get a bitmask from a position */
#define BITMASK_ARRAY_SIZE          2                                   /*!< Number of 32bits integer used to handle bitmask in the fko_var_bitmask_t structure */
#define LF_CHAR                     0x0A                                /*!< Hexadecimal value associated to the LF char */

/**
 * Structure to handle long bitmask.
 *
 * The structure is built as an array of unsigned 32 bits integer to be able to
 * easily increase the size of the bitmask.
 * This bitmask can contains at most (BITMASK_ARRAY_SIZE * 32) values.
 */
typedef struct fko_var_bitmask
{
    uint32_t dw[BITMASK_ARRAY_SIZE];        /*!< Array of bitmasks */
} fko_var_bitmask_t;

/**
 * Structure to handle a variable in an rcfile (name and value)
 */
typedef struct rc_file_param
{
    char name[MAX_LINE_LEN];    /*!< Variable name */
    char val[MAX_LINE_LEN];     /*!< Variable value */
} rc_file_param_t;

/**
 * Structure to identify a configuration variable (name and position)
 */
typedef struct fko_var
{
    const char      name[32];   /*!< Variable name in fwknoprc */
    unsigned int    pos;        /*!< Variable position from the fwknop_cli_arg_t enumeration */
} fko_var_t;

enum
{
    FWKNOP_CLI_FIRST_ARG = 0,
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
    FWKNOP_CLI_ARG_HMAC_KEY_FILE,
    FWKNOP_CLI_ARG_NAT_ACCESS,
    FWKNOP_CLI_ARG_HTTP_USER_AGENT,
    FWKNOP_CLI_ARG_RESOLVE_URL,
    FWKNOP_CLI_ARG_NAT_LOCAL,
    FWKNOP_CLI_ARG_NAT_RAND_PORT,
    FWKNOP_CLI_ARG_NAT_PORT,
    FWKNOP_CLI_ARG_VERBOSE,
    FWKNOP_CLI_ARG_RESOLVE_IP_HTTP,
    FWKNOP_CLI_LAST_ARG
} fwknop_cli_arg_t;

static fko_var_t fko_var_array[FWKNOP_CLI_LAST_ARG] =
{
    { "DIGEST_TYPE",        FWKNOP_CLI_ARG_DIGEST_TYPE          },
    { "SPA_SERVER_PROTO",   FWKNOP_CLI_ARG_SPA_SERVER_PROTO     },
    { "SPA_SERVER_PORT",    FWKNOP_CLI_ARG_SPA_SERVER_PORT      },
    { "SPA_SOURCE_PORT",    FWKNOP_CLI_ARG_SPA_SOURCE_PORT      },
    { "FW_TIMEOUT",         FWKNOP_CLI_ARG_FW_TIMEOUT           },
    { "ALLOW_IP",           FWKNOP_CLI_ARG_ALLOW_IP             },
    { "TIME_OFFSET",        FWKNOP_CLI_ARG_TIME_OFFSET          },
    { "ENCRYPTION_MODE",    FWKNOP_CLI_ARG_ENCRYPTION_MODE      },
    { "USE_GPG",            FWKNOP_CLI_ARG_USE_GPG              },
    { "USE_GPG_AGENT",      FWKNOP_CLI_ARG_USE_GPG_AGENT        },
    { "GPG_RECIPIENT",      FWKNOP_CLI_ARG_GPG_RECIPIENT        },
    { "GPG_SIGNER",         FWKNOP_CLI_ARG_GPG_SIGNER           },
    { "GPG_HOMEDIR",        FWKNOP_CLI_ARG_GPG_HOMEDIR          },
    { "SPOOF_USER",         FWKNOP_CLI_ARG_SPOOF_USER           },
    { "SPOOF_SOURCE_IP",    FWKNOP_CLI_ARG_SPOOF_SOURCE_IP      },
    { "ACCESS",             FWKNOP_CLI_ARG_ACCESS               },
    { "SPA_SERVER",         FWKNOP_CLI_ARG_SPA_SERVER           },
    { "RAND_PORT",          FWKNOP_CLI_ARG_RAND_PORT            },
    { "KEY",                FWKNOP_CLI_ARG_KEY_RIJNDAEL         },
    { "KEY_BASE64",         FWKNOP_CLI_ARG_KEY_RIJNDAEL_BASE64  },
    { "HMAC_DIGEST_TYPE",   FWKNOP_CLI_ARG_HMAC_DIGEST_TYPE     },
    { "HMAC_KEY_BASE64",    FWKNOP_CLI_ARG_KEY_HMAC_BASE64      },
    { "HMAC_KEY",           FWKNOP_CLI_ARG_KEY_HMAC             },
    { "USE_HMAC",           FWKNOP_CLI_ARG_USE_HMAC             },
    { "KEY_FILE",           FWKNOP_CLI_ARG_KEY_FILE             },
    { "HMAC_KEY_FILE",      FWKNOP_CLI_ARG_HMAC_KEY_FILE        },
    { "NAT_ACCESS",         FWKNOP_CLI_ARG_NAT_ACCESS           },
    { "HTTP_USER_AGENT",    FWKNOP_CLI_ARG_HTTP_USER_AGENT      },
    { "RESOLVE_URL",        FWKNOP_CLI_ARG_RESOLVE_URL          },
    { "NAT_LOCAL",          FWKNOP_CLI_ARG_NAT_LOCAL            },
    { "NAT_RAND_PORT",      FWKNOP_CLI_ARG_NAT_RAND_PORT        },
    { "NAT_PORT",           FWKNOP_CLI_ARG_NAT_PORT             },
    { "VERBOSE",            FWKNOP_CLI_ARG_VERBOSE              },
    { "RESOLVE_IP_HTTP",    FWKNOP_CLI_ARG_RESOLVE_IP_HTTP      }
};

/* Array to define which conf. variables are critical and should not be
 * overwritten when a stanza is updated using the --save-rc-stanza arg
 * without the user validation */
static int critical_var_array[] =
{
    FWKNOP_CLI_ARG_KEY_RIJNDAEL,
    FWKNOP_CLI_ARG_KEY_RIJNDAEL_BASE64,
    FWKNOP_CLI_ARG_KEY_HMAC,
    FWKNOP_CLI_ARG_KEY_HMAC_BASE64,
    FWKNOP_CLI_ARG_GPG_RECIPIENT,
    FWKNOP_CLI_ARG_GPG_SIGNER
};

/**
 * @brief Generate Rijndael + HMAC keys from /dev/random (base64 encoded) and exit.
 *
 * @param options FKO command line option structure
 */
static void
generate_keys(fko_cli_options_t *options)
{
    int res;

    /* If asked, we have to generate the keys */
    if(options->key_gen)
    {
        /* Zero out the key buffers */
        memset(&(options->key_base64), 0x00, sizeof(options->key_base64));
        memset(&(options->hmac_key_base64), 0x00, sizeof(options->hmac_key_base64));

        /* Generate the key with through libfko */
        res = fko_key_gen(options->key_base64, options->key_len,
                options->hmac_key_base64, options->hmac_key_len,
                options->hmac_type);

        /* Exit upon key generation failure*/
        if(res != FKO_SUCCESS)
        {
            log_msg(LOG_VERBOSITY_ERROR, "%s: fko_key_gen: Error %i - %s",
                MY_NAME, res, fko_errstr(res));
            exit(EXIT_FAILURE);
        }

        /* Everything is ok - nothing to do */
        else;
    }

    /* No key generation asked - nothing to do */
    else;
}

/**
 * @brief Check if a variable is a critical var.
 *
 * This function check the critical_var_array table to find if the variable
 * position is available.
 *
 * @param var_pos   Fwknop configuration variable position
 *
 * @return 1 the variable is critical, 0 otherwise
 */
static int
var_is_critical(short var_pos)
{
    int ndx;            /* Index on the critical_var_array array */
    int var_found = 0;

    /* Go through the array of critical vars */
    for (ndx=0 ; ndx<ARRAY_SIZE(critical_var_array) ; ndx++)
    {
        /* and check if we find it */
        if (var_pos == critical_var_array[ndx])
        {
            var_found = 1;
            break;
        }
    }

    return var_found;
}

/**
 * @brief Add a variable to a bitmask
 *
 * This function adds the bitmask associated to a variable position, to a
 * bitmask.
 *
 * @param var_pos   Fwknop configuration variable position
 * @param bm        fko_var_bitmask_t variable to update
 */
static void
add_var_to_bitmask(short var_pos, fko_var_bitmask_t *bm)
{
    unsigned int bitmask_ndx;

    /* Look for the index on the uint32_t array we have to process */
    bitmask_ndx = var_pos / 32;

    /* Set the bitmask according to the index found */
    if (bitmask_ndx < BITMASK_ARRAY_SIZE)
        bm->dw[bitmask_ndx] |= POSITION_TO_BITMASK(var_pos);

    /* The index on the uint32_t bitmask is invalid */
    else
        log_msg(LOG_VERBOSITY_WARNING, "add_var_to_bitmask() : Bad variable position %u", var_pos);
}

/**
 * @brief Remove a variable from a bitmask
 *
 * This function removes the bitmask associated to the variable position from a
 * bitmask.
 *
 * @param var_pos   Fwknop configuration variable position
 * @param bm        fko_var_bitmask_t structure to update
 */
static void
remove_var_from_bitmask(short var_pos, fko_var_bitmask_t *bm)
{
    unsigned int bitmask_ndx;

    /* Look for the index on the uint32_t array we have to process */
    bitmask_ndx = var_pos / 32;

    /* Set the bitmask according to the index found */
    if (bitmask_ndx < BITMASK_ARRAY_SIZE)
        bm->dw[bitmask_ndx] &= ~POSITION_TO_BITMASK(var_pos);

    /* The index on the uint32_t bitmask is invalid */
    else
        log_msg(LOG_VERBOSITY_WARNING, "remove_from_bitmask() : Bad variable position %u", var_pos);
}

/**
 * @brief Return whether a variable is available in a bitmask
 *
 * The variable bitmask is looked for in the bitmask.
 *
 * @param var_pos   Fwknop configuration variable position
 * @param bm        fko_var_bitmask_t structure to check
 *
 * @return 1 if the bitmsk contains the variable, 0 otherwise.
 */
static int
bitmask_has_var(short var_pos, fko_var_bitmask_t *bm)
{
    unsigned int    bitmask_ndx;
    int             var_found = 0;

    /* Look for the index on the uint32_t array we have to process */
    bitmask_ndx = var_pos / 32;

    /* Check the bitmask according to the index found */
    if (bitmask_ndx < BITMASK_ARRAY_SIZE)
    {
        if ( bm->dw[bitmask_ndx] & POSITION_TO_BITMASK(var_pos) )
            var_found = 1;
    }

    /* The index on the uint32_t bitmask is invalid */
    else
        log_msg(LOG_VERBOSITY_WARNING, "bitmask_has_var_ndx() : Bad variable position %u", var_pos);

    return var_found;
}

/**
 * @brief Ask the user if a variable must be overwritten or not for a specific stanza
 *
 * If the user sets other chars than a 'y' char, we assume he does not want to
 * overwrite the variable.
 *
 * @param var       Variable which should be overwritten
 * @param stanza    Stanza where the variable should be overwritten
 *
 * @return 1 if the user wants to overwrite the variable, 0 otherwise
 */
static int
ask_overwrite_var(const char *var, const char *stanza)
{
    char    user_input = 'N';
    int     overwrite = 0;
    int     c;
    int     first_char = 1;;

    log_msg(LOG_VERBOSITY_NORMAL,
            "Variable '%s' found in stanza '%s'. Overwrite [N/y] ? ",
            var, stanza);

    while ((c=getchar()) != LF_CHAR)
    {
        if (first_char)
            user_input = c;
        first_char = 0;
    }

    if (user_input == 'y')
        overwrite = 1;

    return overwrite;
}

/**
 * @brief Lookup a variable in the variable array according to its name
 *
 * This function parses the fko_var_array table and try to find a match
 * for the user string, which indicates we have found a configuration variable.
 *
 * @param str       String to compare against every fwknop conf variables
 *
 * @return A pointer on the variable structure, or NULL if not found
 */
static fko_var_t *
lookup_var_by_name(const char *var_name)
{
    short       ndx;            /* Index on the the fko_var_array table */
    fko_var_t  *var = NULL;

    /* Check str against each variable available in fko_var_array */
    for (ndx=0 ; ndx<ARRAY_SIZE(fko_var_array) ; ndx++)
    {
        if (CONF_VAR_IS(var_name, fko_var_array[ndx].name))
        {
            var = &(fko_var_array[ndx]);
            break;
        }
    }

    return var;
}

/**
 * @brief Lookup a variable in the variable array according to its position
 *
 * This function parses the fko_var_array table and try to find a match
 * for the position, which indicates we have found a configuration variable.
 *
 * @param var_pos   Position to compare against every fwknop conf variables
 *
 * @return A pointer on the variable structure, or NULL if not found
 */
static fko_var_t *
lookup_var_by_position(short var_pos)
{
    short       ndx;            /* Index on the the fko_var_array table */
    fko_var_t  *var = NULL;

    /* Check str against each variable available in fko_var_array */
    for (ndx=0 ; ndx<ARRAY_SIZE(fko_var_array) ; ndx++)
    {
        if (var_pos == fko_var_array[ndx].pos)
        {
            var = &(fko_var_array[ndx]);
            break;
        }
    }

    return var;
}

/**
 * @brief Set a string as a Yes or No value according to a boolean (0 or 1).
 *
 * This function checks whether a value is set to zero or not, and updates a
 * string to a YES_NO parameter value.
 * The string must be zeroed before being passed to the function.
 *
 * @param val Variable to check
 * @param s String where to store the YES_NO value.
 * @param len Number of bytes avaialble for the s buffer.
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
 * @brief Check if a section is in a line and fetch it.
 *
 * This function parses a NULL terminated string in order to find a section,
 * something like [mysection]. If it succeeds, the stanza is retrieved.
 *
 * @param line String containing a line from the rc file to check for a section
 * @param line_size size of the line buffer
 * @param rc_section String to store the section found
 * @param rc_section_size Size of the rc_section buffer
 *
 * @return 1 if a section was found, 0 otherwise
 */
static int
is_rc_section(const char* line, uint16_t line_size, char* rc_section, uint16_t rc_section_size)
{
    char    *ndx, *emark;
    char    buf[MAX_LINE_LEN] = {0};
    int     section_found = 0;

    if (line_size < sizeof(buf))
    {
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
 * @brief Grab a variable and its value from a rc line.
 *
 * @param line  Line to parse for a variable
 * @param param Parameter structure where to store the variable name and its value
 *
 * @return 0 if no variable has been found, 1 otherwise.
 */
static int
is_rc_param(const char *line, rc_file_param_t *param)
{
    char    var[MAX_LINE_LEN] = {0};
    char    val[MAX_LINE_LEN] = {0};
    char    *ndx;

    memset(param, 0, sizeof(*param));

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

    char offset_digits[MAX_TIME_STR_LEN] = {0};

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
        "# It is this identifier (or name) that is used from the fwknop command line\n"
        "# via the '-n <name>' argument to reference the corresponding stanza.\n"
        "#\n"
        "# The parameters within the stanza typicaly match corresponding client \n"
        "# command-line parameters.\n"
        "#\n"
        "# The first one should always be `[default]' as it defines the global\n"
        "# default settings for the user. These override the program defaults\n"
        "# for these parameters.  If a named stanza is used, its entries will\n"
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
parse_rc_param(fko_cli_options_t *options, const char *var_name, char * val)
{
    int         tmpint, is_err;
    int         parse_error = 0;    /* 0 if the variable has been successfully processed, < 0 otherwise */
    fko_var_t  *var;                /* Pointer on an fwknop variable structure */

    log_msg(LOG_VERBOSITY_DEBUG, "parse_rc_param() : Parsing variable %s...", var_name);

    /* Lookup the variable according to its name. */
    var = lookup_var_by_name(var_name);

    /* The variable is not handled if its pointer is NULL */
    if (var == NULL)
        parse_error = -1;

    /* Digest Type */
    else if (var->pos == FWKNOP_CLI_ARG_DIGEST_TYPE)
    {
        tmpint = digest_strtoint(val);
        if(tmpint < 0)
            parse_error = -1;
        else
            options->digest_type = tmpint;
    }
    /* Server protocol */
    else if (var->pos == FWKNOP_CLI_ARG_SPA_SERVER_PROTO)
    {
        tmpint = proto_strtoint(val);
        if(tmpint < 0)
            parse_error = -1;
        else
            options->spa_proto = tmpint;
    }
    /* Server port */
    else if (var->pos == FWKNOP_CLI_ARG_SPA_SERVER_PORT)
    {
        tmpint = strtol_wrapper(val, 0, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
        if(is_err == FKO_SUCCESS)
            options->spa_dst_port = tmpint;
        else
            parse_error = -1;
    }
    /* Source port */
    else if (var->pos == FWKNOP_CLI_ARG_SPA_SOURCE_PORT)
    {
        tmpint = strtol_wrapper(val, 0, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
        if(is_err == FKO_SUCCESS)
            options->spa_src_port = tmpint;
        else
            parse_error = -1;
    }
    /* Firewall rule timeout */
    else if (var->pos == FWKNOP_CLI_ARG_FW_TIMEOUT)
    {
        tmpint = strtol_wrapper(val, 0, (2 << 15), NO_EXIT_UPON_ERR, &is_err);
        if(is_err == FKO_SUCCESS)
            options->fw_timeout = tmpint;
        else
            parse_error = -1;
    }
    /* Allow IP */
    else if (var->pos == FWKNOP_CLI_ARG_ALLOW_IP)
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
    else if (var->pos == FWKNOP_CLI_ARG_TIME_OFFSET)
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
    else if (var->pos == FWKNOP_CLI_ARG_ENCRYPTION_MODE)
    {
        tmpint = enc_mode_strtoint(val);
        if(tmpint < 0)
            parse_error = -1;
        else
            options->encryption_mode = tmpint;
    }
    /* Use GPG ? */
    else if (var->pos == FWKNOP_CLI_ARG_USE_GPG)
    {
        if (is_yes_str(val))
            options->use_gpg = 1;
        else;
    }
    /* Use GPG Agent ? */
    else if (var->pos == FWKNOP_CLI_ARG_USE_GPG_AGENT)
    {
        if (is_yes_str(val))
            options->use_gpg_agent = 1;
        else;
    }
    /* GPG Recipient */
    else if (var->pos == FWKNOP_CLI_ARG_GPG_RECIPIENT)
    {
        strlcpy(options->gpg_recipient_key, val, sizeof(options->gpg_recipient_key));
    }
    /* GPG Signer */
    else if (var->pos == FWKNOP_CLI_ARG_GPG_SIGNER)
    {
        strlcpy(options->gpg_signer_key, val, sizeof(options->gpg_signer_key));
    }
    /* GPG Homedir */
    else if (var->pos == FWKNOP_CLI_ARG_GPG_HOMEDIR)
    {
        strlcpy(options->gpg_home_dir, val, sizeof(options->gpg_home_dir));
    }
    /* Spoof User */
    else if (var->pos == FWKNOP_CLI_ARG_SPOOF_USER)
    {
        strlcpy(options->spoof_user, val, sizeof(options->spoof_user));
    }
    /* Spoof Source IP */
    else if (var->pos == FWKNOP_CLI_ARG_SPOOF_SOURCE_IP)
    {
        strlcpy(options->spoof_ip_src_str, val, sizeof(options->spoof_ip_src_str));
    }
    /* ACCESS request */
    else if (var->pos == FWKNOP_CLI_ARG_ACCESS)
    {
        strlcpy(options->access_str, val, sizeof(options->access_str));
    }
    /* SPA Server (destination) */
    else if (var->pos == FWKNOP_CLI_ARG_SPA_SERVER)
    {
        strlcpy(options->spa_server_str, val, sizeof(options->spa_server_str));
    }
    /* Rand port ? */
    else if (var->pos == FWKNOP_CLI_ARG_RAND_PORT)
    {
        if (is_yes_str(val))
            options->rand_port = 1;
        else;
    }
    /* Rijndael key */
    else if (var->pos == FWKNOP_CLI_ARG_KEY_RIJNDAEL)
    {
        strlcpy(options->key, val, sizeof(options->key));
        options->have_key = 1;
    }
    /* Rijndael key (base-64 encoded) */
    else if (var->pos == FWKNOP_CLI_ARG_KEY_RIJNDAEL_BASE64)
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
    else if (var->pos == FWKNOP_CLI_ARG_HMAC_DIGEST_TYPE)
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
    else if (var->pos == FWKNOP_CLI_ARG_KEY_HMAC_BASE64)
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
    else if (var->pos == FWKNOP_CLI_ARG_KEY_HMAC)
    {
        strlcpy(options->hmac_key, val, sizeof(options->hmac_key));
        options->have_hmac_key = 1;
        options->use_hmac = 1;
    }

    /* --use-hmac */
    else if (var->pos == FWKNOP_CLI_ARG_USE_HMAC)
    {
        if (is_yes_str(val))
            options->use_hmac = 1;
    }
    /* Key file */
    else if (var->pos == FWKNOP_CLI_ARG_KEY_FILE)
    {
        strlcpy(options->get_key_file, val, sizeof(options->get_key_file));
    }
    /* HMAC key file */
    else if (var->pos == FWKNOP_CLI_ARG_HMAC_KEY_FILE)
    {
        strlcpy(options->get_key_file, val,
            sizeof(options->get_hmac_key_file));
    }
    /* NAT Access Request */
    else if (var->pos == FWKNOP_CLI_ARG_NAT_ACCESS)
    {
        strlcpy(options->nat_access_str, val, sizeof(options->nat_access_str));
    }
    /* HTTP User Agent */
    else if (var->pos == FWKNOP_CLI_ARG_HTTP_USER_AGENT)
    {
        strlcpy(options->http_user_agent, val, sizeof(options->http_user_agent));
    }
    /* Resolve URL */
    else if (var->pos == FWKNOP_CLI_ARG_RESOLVE_URL)
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
    else if (var->pos == FWKNOP_CLI_ARG_NAT_LOCAL)
    {
        if (is_yes_str(val))
            options->nat_local = 1;
        else;
    }
    /* NAT rand port ? */
    else if (var->pos == FWKNOP_CLI_ARG_NAT_RAND_PORT)
    {
        if (is_yes_str(val))
            options->nat_rand_port = 1;
        else;
    }
    /* NAT port */
    else if (var->pos == FWKNOP_CLI_ARG_NAT_PORT)
    {
        tmpint = strtol_wrapper(val, 0, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
        if(is_err == FKO_SUCCESS)
            options->nat_port = tmpint;
        else
            parse_error = -1;
    }
    /* VERBOSE level */
    else if (var->pos == FWKNOP_CLI_ARG_VERBOSE)
    {
        tmpint = strtol_wrapper(val, 0, LOG_LAST_VERBOSITY - 1, NO_EXIT_UPON_ERR, &is_err);
        if(is_err == FKO_SUCCESS)
            options->verbose = tmpint;
        else
            parse_error = -1;
    }
    /* RESOLVE_IP_HTTP ? */
    else if (var->pos == FWKNOP_CLI_ARG_RESOLVE_IP_HTTP)
    {
        if (is_yes_str(val))
            options->resolve_ip_http = 1;
        else;
    }
    /* The variable is not a configuration variable */
    else
    {
        parse_error = -1;
    }

    return(parse_error);
}

/**
 * @brief Write a cli parameter to a file handle
 *
 * This function writes into a file handle a command line parameter
 *
 * @param fhandle File handle to write the new parameter to
 * @param var_pos Variable position
 * @param options FKO command line option structure
 */
static void
add_single_var_to_rc(FILE* fhandle, short var_pos, fko_cli_options_t *options)
{
    char        val[MAX_LINE_LEN] = {0};
    fko_var_t  *var;

    var = lookup_var_by_position(var_pos);

    if (var == NULL)
        return;

    if (fhandle == NULL)
        return;

    /* Select the argument to add and store its string value into val */
    switch (var->pos)
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
            else;
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
        case FWKNOP_CLI_ARG_HMAC_KEY_FILE :
            strlcpy(val, options->get_hmac_key_file, sizeof(val));
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
            else;
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
        case FWKNOP_CLI_ARG_VERBOSE:
            snprintf(val, sizeof(val)-1, "%d", options->verbose);
            break;
        case FWKNOP_CLI_ARG_RESOLVE_IP_HTTP:
            bool_to_yesno(options->resolve_ip_http, val, sizeof(val));
            break;
        default:
            log_msg(LOG_VERBOSITY_WARNING, "Warning from add_single_var_to_rc() : Bad variable position %u", var->pos);
            return;
    }

    log_msg(LOG_VERBOSITY_DEBUG, "add_single_var_to_rc() : Updating param (%u) %s to %s",
                var->pos, var->name, val);

    fprintf(fhandle, RC_PARAM_TEMPLATE, var->name, val);
}

/**
 * @brief Add configuration variables in a file
 *
 * The parameters are selected by a bitmask and extracted from the
 * fko_cli_options_t structure.
 *
 * @param rc        File handle on the file to write to
 * @param options   fko_cli_options_t structure containing the values of the parameters
 * @param bitmask   Bitmask used to select the parameters to add
 */
static void
add_multiple_vars_to_rc(FILE* rc, fko_cli_options_t *options, fko_var_bitmask_t *bitmask)
{
    short ndx = 0;      /* Index of a configuration variable in fko_var_array table */
    short position;     /* Position of the configuration variable */

    for (ndx=0 ; ndx<ARRAY_SIZE(fko_var_array) ; ndx++)
    {
        position = fko_var_array[ndx].pos;
        if (bitmask_has_var(position, bitmask))
            add_single_var_to_rc(rc, position, options);
    }
}

/**
 * @brief Process the fwknoprc file and lookup a section to extract its settings.
 *
 * This function aims at loading the settings for a specific section in
 * a fwknoprc file.
 *
 * @param section_name  Name of the section to lookup.
 * @param options       Fwknop option structure where settings have to
 *                      be stored.
 *
 * @return 0 if the section has been found and processed successfully
 *         a negative value if one or more errors occured
 */
static int
process_rc_section(char *section_name, fko_cli_options_t *options)
{
    FILE           *rc;
    int             line_num = 0, do_exit = 0;
    char            line[MAX_LINE_LEN] = {0};
    char            rcfile[MAX_PATH_LEN] = {0};
    char            curr_stanza[MAX_LINE_LEN] = {0};
    rc_file_param_t param;
    int             rc_section_found = 0;

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
 * @brief Update the user rc file with the new parameters for a selected stanza.
 *
 * This function writes the new configuration in a temporary file and renames it
 * as the new rc file afterwards. All of the previous parameters for the
 * selected stanza are removed and replaced by the arguments from the command
 * line.
 *
 * @param options structure containing all of the fko settings
 * @param args_bitmask command line argument bitmask
 */
static void
update_rc(fko_cli_options_t *options, fko_var_bitmask_t *bitmask)
{
    FILE           *rc;
    FILE           *rc_update;
    int             rcfile_fd = -1;
    int             stanza_found = 0;
    int             stanza_updated = 0;
    char            line[MAX_LINE_LEN]   = {0};
    char            rcfile[MAX_PATH_LEN] = {0};
    char            rcfile_update[MAX_PATH_LEN] = {0};
    char            curr_stanza[MAX_LINE_LEN]   = {0};
    rc_file_param_t param;                              /* Structure to contain a conf. variable name with its value  */
    fko_var_t      *var;

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
        fclose(rc);
        return;
    }

    /* Go through the file line by line */
    stanza_found = 0;
    while ((fgets(line, MAX_LINE_LEN, rc)) != NULL)
    {
        line[MAX_LINE_LEN-1] = '\0';

        /* If we find a section... */
        if(is_rc_section(line, strlen(line), curr_stanza, sizeof(curr_stanza)) == 1)
        {
            /* and we have already parsed the section we wanted to save, we
             * can update our parameters */
            if (stanza_found)
            {
                log_msg(LOG_VERBOSITY_DEBUG, "update_rc() : Updating %s stanza", options->use_rc_stanza);
                add_multiple_vars_to_rc(rc_update, options, bitmask);
                fprintf(rc_update, "\n");
                stanza_found   = 0;
                stanza_updated = 1;
            }

            /* and this is the one we are looking for, we set the stanza
             * as found */
            else if (strncasecmp(curr_stanza, options->use_rc_stanza, MAX_LINE_LEN) == 0)
                stanza_found = 1;

            /* otherwise we disable the stanza */
            else
                stanza_found = 0;
        }

        /* If we are processing a parameter for our stanza */
        else if (stanza_found)
        {
            /* and the user has specified a force option, there is no need to
             * check for critical variables */
            if (options->force_save_rc_stanza)
                continue;

            /* ask the user what to do with the critical var found in the
             * rcfile */
            else if (is_rc_param(line, &param))
            {
                if (   ((var=lookup_var_by_name(param.name)) != NULL)
                    && var_is_critical(var->pos) )
                {
                    if (ask_overwrite_var(var->name, curr_stanza))
                        continue;
                    else
                        remove_var_from_bitmask(var->pos, bitmask);
                }
                else
                    continue;
            }

            /* discard all other lines */
            else
                continue;
        }

        /* We re not processing any important variables from our stanza and no new
         * stanza */
        else;

        /* Add the line to the new rcfile */
        fprintf(rc_update, "%s", line);
    }

    /* The configuration has not been updated yet */
    if (stanza_updated == 0)
    {
        /* but the stanza has been found, We update it now. */
        if (stanza_found == 1)
            log_msg(LOG_VERBOSITY_DEBUG, "update_rc() : Updating %s stanza",
                    options->use_rc_stanza);

        /* otherwise we append the new settings to the file */
        else
        {
            fprintf(rc_update, "\n");
            log_msg(LOG_VERBOSITY_DEBUG, "update_rc() : Inserting new %s stanza",
                    options->use_rc_stanza);
            fprintf(rc_update, RC_SECTION_TEMPLATE, options->use_rc_stanza);
        }

        add_multiple_vars_to_rc(rc_update, options, bitmask);
    }

    /* otherwise we have already done everything. Nothing to do. */
    else;

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

    /* Gotta have a Destination unless we are just testing or getting the
     * the version, and must use one of [-s|-R|-a].
    */
    if(!options->test
        && !options->key_gen
        && !options->version
        && !options->show_last_command
        && !options->run_last_command)
    {
        if (options->spa_server_str[0] == 0x0)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                "Must use --destination unless --test mode is used");
            exit(EXIT_FAILURE);
        }

        if (options->resolve_url != NULL)
            options->resolve_ip_http = 1;

        if (!options->resolve_ip_http)
        {
            if(options->allow_ip_str[0] == 0x0)
            {
                log_msg(LOG_VERBOSITY_ERROR,
                    "Must use one of [-s|-R|-a] to specify IP for SPA access.");
                exit(EXIT_FAILURE);
            }
            else if(options->verbose
                    && strncmp(options->allow_ip_str, "0.0.0.0", strlen("0.0.0.0")) == 0)
            {
                log_msg(LOG_VERBOSITY_WARNING,
                    "[-] WARNING: Should use -a or -R to harden SPA against potential MITM attacks");
            }
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
        if(strlen(options->gpg_recipient_key) == 0)
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

    if(options->key_gen && options->hmac_type == FKO_HMAC_UNKNOWN)
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
    int                 cmd_arg, index, is_err;
    fko_var_bitmask_t   var_bitmask;

    /* Zero out options, opts_track and bitmask.
    */
    memset(options, 0x00, sizeof(fko_cli_options_t));
    memset(&var_bitmask, 0x00, sizeof(fko_var_bitmask_t));

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
            case NO_SAVE_ARGS:
                options->no_save_args = 1;
                break;
            case 'n':
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
                add_var_to_bitmask(FWKNOP_CLI_ARG_VERBOSE, &var_bitmask);
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
                add_var_to_bitmask(FWKNOP_CLI_ARG_ALLOW_IP, &var_bitmask);
                break;
            case 'A':
                strlcpy(options->access_str, optarg, sizeof(options->access_str));
                add_var_to_bitmask(FWKNOP_CLI_ARG_ACCESS, &var_bitmask);
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
                add_var_to_bitmask(FWKNOP_CLI_ARG_SPA_SERVER, &var_bitmask);
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
                add_var_to_bitmask(FWKNOP_CLI_ARG_FW_TIMEOUT, &var_bitmask);
                break;
            case 'g':
            case GPG_ENCRYPTION:
                options->use_gpg = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_GPG, &var_bitmask);
                break;
            case 'G':
                strlcpy(options->get_key_file, optarg, sizeof(options->get_key_file));
                add_var_to_bitmask(FWKNOP_CLI_ARG_KEY_FILE, &var_bitmask);
                break;
            case GET_HMAC_KEY:
                strlcpy(options->get_hmac_key_file, optarg,
                    sizeof(options->get_hmac_key_file));
                options->use_hmac = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_HMAC_KEY_FILE, &var_bitmask);
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
                add_var_to_bitmask(FWKNOP_CLI_ARG_KEY_RIJNDAEL, &var_bitmask);
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
                add_var_to_bitmask(FWKNOP_CLI_ARG_KEY_RIJNDAEL_BASE64, &var_bitmask);
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
                add_var_to_bitmask(FWKNOP_CLI_ARG_KEY_HMAC_BASE64, &var_bitmask);
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_HMAC, &var_bitmask);
                break;
            case KEY_HMAC:
                strlcpy(options->hmac_key, optarg, sizeof(options->hmac_key));
                options->have_hmac_key = 1;
                options->use_hmac = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_KEY_HMAC, &var_bitmask);
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_HMAC, &var_bitmask);
                break;
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
                add_var_to_bitmask(FWKNOP_CLI_ARG_HMAC_DIGEST_TYPE, &var_bitmask);
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_HMAC, &var_bitmask);
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
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_HMAC, &var_bitmask);
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
                add_var_to_bitmask(FWKNOP_CLI_ARG_DIGEST_TYPE, &var_bitmask);
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
                add_var_to_bitmask(FWKNOP_CLI_ARG_ENCRYPTION_MODE, &var_bitmask);
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
                add_var_to_bitmask(FWKNOP_CLI_ARG_NAT_ACCESS, &var_bitmask);
                break;
            case 'p':
                options->spa_dst_port = strtol_wrapper(optarg, 0,
                        MAX_PORT, EXIT_UPON_ERR, &is_err);
                add_var_to_bitmask(FWKNOP_CLI_ARG_SPA_SERVER_PORT, &var_bitmask);
                break;
            case 'P':
                if((options->spa_proto = proto_strtoint(optarg)) < 0)
                {
                    log_msg(LOG_VERBOSITY_ERROR, "Unrecognized protocol: %s", optarg);
                    exit(EXIT_FAILURE);
                }
                add_var_to_bitmask(FWKNOP_CLI_ARG_SPA_SERVER_PROTO, &var_bitmask);
                break;
            case 'Q':
                strlcpy(options->spoof_ip_src_str, optarg, sizeof(options->spoof_ip_src_str));
                add_var_to_bitmask(FWKNOP_CLI_ARG_SPOOF_SOURCE_IP, &var_bitmask);
                break;
            case RC_FILE_PATH:
                strlcpy(options->rc_file, optarg, sizeof(options->rc_file));
                break;
            case 'r':
                options->rand_port = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_RAND_PORT, &var_bitmask);
                break;
            case 'R':
                options->resolve_ip_http = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_RESOLVE_IP_HTTP, &var_bitmask);
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
                add_var_to_bitmask(FWKNOP_CLI_ARG_RESOLVE_URL, &var_bitmask);
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
                add_var_to_bitmask(FWKNOP_CLI_ARG_SPA_SOURCE_PORT, &var_bitmask);
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
                add_var_to_bitmask(FWKNOP_CLI_ARG_HTTP_USER_AGENT, &var_bitmask);
                break;
            case 'U':
                strlcpy(options->spoof_user, optarg, sizeof(options->spoof_user));
                add_var_to_bitmask(FWKNOP_CLI_ARG_SPOOF_USER, &var_bitmask);
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
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_GPG, &var_bitmask);
                add_var_to_bitmask(FWKNOP_CLI_ARG_GPG_RECIPIENT, &var_bitmask);
                break;
            case GPG_SIGNER_KEY:
                options->use_gpg = 1;
                strlcpy(options->gpg_signer_key, optarg, sizeof(options->gpg_signer_key));
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_GPG, &var_bitmask);
                add_var_to_bitmask(FWKNOP_CLI_ARG_GPG_SIGNER, &var_bitmask);
                break;
            case GPG_HOME_DIR:
                options->use_gpg = 1;
                strlcpy(options->gpg_home_dir, optarg, sizeof(options->gpg_home_dir));
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_GPG, &var_bitmask);
                add_var_to_bitmask(FWKNOP_CLI_ARG_GPG_HOMEDIR, &var_bitmask);
                break;
            case GPG_AGENT:
                options->use_gpg = 1;
                options->use_gpg_agent = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_GPG, &var_bitmask);
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_GPG_AGENT, &var_bitmask);
                break;
            case NAT_LOCAL:
                options->nat_local = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_NAT_LOCAL, &var_bitmask);
                break;
            case NAT_RAND_PORT:
                options->nat_rand_port = 1;
                add_var_to_bitmask(FWKNOP_CLI_ARG_NAT_RAND_PORT, &var_bitmask);
                break;
            case NAT_PORT:
                options->nat_port = strtol_wrapper(optarg, 0,
                        MAX_PORT, EXIT_UPON_ERR, &is_err);
                add_var_to_bitmask(FWKNOP_CLI_ARG_NAT_PORT, &var_bitmask);
                break;
            case TIME_OFFSET_PLUS:
                options->time_offset_plus = parse_time_offset(optarg);
                add_var_to_bitmask(FWKNOP_CLI_ARG_TIME_OFFSET, &var_bitmask);
                break;
            case TIME_OFFSET_MINUS:
                options->time_offset_minus = parse_time_offset(optarg);
                add_var_to_bitmask(FWKNOP_CLI_ARG_TIME_OFFSET, &var_bitmask);
                break;
            case USE_HMAC:
                add_var_to_bitmask(FWKNOP_CLI_ARG_USE_HMAC, &var_bitmask);
                options->use_hmac = 1;
                break;
            case FORCE_SAVE_RC_STANZA:
                options->force_save_rc_stanza = 1;
                break;
            default:
                usage();
                exit(EXIT_FAILURE);
        }
    }

    /* Now that we have all of our options set, we can validate them */
    validate_options(options);

    /* Do some processings */
    generate_keys(options);

    /* We can upgrade our settings with the parameters set on the command
     * line by the user */
    if (options->save_rc_stanza == 1)
    {
        /* If we are asked to generate keys, we add them to the bitmask so
         * that they can be added to the stanza when updated */
        if (options->key_gen)
        {
            add_var_to_bitmask(FWKNOP_CLI_ARG_KEY_RIJNDAEL_BASE64, &var_bitmask);
            add_var_to_bitmask(FWKNOP_CLI_ARG_KEY_HMAC_BASE64, &var_bitmask);
        }
        else;

        update_rc(options, &var_bitmask);
    }
    else;

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
      " -n, --named-config          Specify a named configuration stanza in the\n"
      "                             '$HOME/.fwknoprc' file to provide some of all\n"
      "                             of the configuration parameters.\n"
      "                             If more arguments are set through the command\n"
      "                             line, the configuration is updated accordingly\n"
      " -A, --access                Provide a list of ports/protocols to open\n"
      "                             on the server (e.g. 'tcp/22').\n"
      " -a, --allow-ip              Specify IP address to allow within the SPA\n"
      "                             packet (e.g. '123.2.3.4').  If \n"
      " -D, --destination           Specify the hostname or IP address of the\n"
      "                             fwknop server.\n"
      " -h, --help                  Print this usage message and exit.\n"
      " -B, --save-packet           Save the generated packet data to the\n"
      "                             specified file.\n"
      " -b, --save-packet-append    Append the generated packet data to the\n"
      "                             file specified with the -B option.\n"
      " -C, --server-cmd            Specify a command that the fwknop server will\n"
      "                             execute on behalf of the fwknop client..\n"
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
      " -M, --encryption-mode       Specify the encryption mode when AES is used\n"
      "                             for encrypting SPA packets.The default is CBC\n"
      "                             mode, but others can be chosen such as CFB or\n"
      "                             OFB as long as this is also specified in the\n"
      "                             access.conf file on the server side. Note that\n"
      "                             the string ``legacy'' can be specified in order\n"
      "                             to generate SPA packets with the old initialization\n"
      "                             vector strategy used by versions of *fwknop*\n"
      "                             before 2.5.\n"
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
      "     --force-stanza          Used with --save-rc-stanza to overwrite all of\n"
      "                             the variables for the specified stanza\n"
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

