/*
 ******************************************************************************
 *
 * File:    config_init.c
 *
 * Purpose: Command-line and config file processing for fwknop server.
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2014 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
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
#include "fwknopd_common.h"
#include "fwknopd_errors.h"
#include "config_init.h"
#include "access.h"
#include "cmd_opts.h"
#include "utils.h"
#include "log_msg.h"

#if FIREWALL_IPTABLES
  #include "fw_util_iptables.h"
#endif

/* Check to see if an integer variable has a value that is within a
 * specific range
*/
static void
range_check(fko_srv_options_t *opts, char *var, char *val, int low, int high)
{
    int     is_err;

    strtol_wrapper(val, low, high, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] var %s value '%s' not in the range %d-%d",
            var, val, low, high);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    return;
}

/* Take an index and a string value. malloc the space for the value
 * and assign it to the array at the specified index.
*/
static void
set_config_entry(fko_srv_options_t *opts, const int var_ndx, const char *value)
{
    int space_needed;

    /* Sanity check the index value.
    */
    if(var_ndx < 0 || var_ndx >= NUMBER_OF_CONFIG_ENTRIES)
    {
        log_msg(LOG_ERR, "[*] Index value of %i is not valid", var_ndx);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* If this particular entry was already set (i.e. not NULL), then
     * assume it needs to be freed first.
    */
    if(opts->config[var_ndx] != NULL)
        free(opts->config[var_ndx]);

    /* If we are setting it to NULL, do it and be done.
    */
    if(value == NULL)
    {
        opts->config[var_ndx] = NULL;
        return;
    }

    /* Otherwise, make the space we need and set it.
    */
    space_needed = strlen(value) + 1;

    opts->config[var_ndx] = calloc(1, space_needed);

    if(opts->config[var_ndx] == NULL)
    {
        log_msg(LOG_ERR, "[*] Fatal memory allocation error!");
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    strlcpy(opts->config[var_ndx], value, space_needed);

    return;
}

/* Given a config parameter name, return its index or -1 if not found.
*/
static int
config_entry_index(const fko_srv_options_t *opts, const char *var)
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

    free_acc_stanzas(opts);

    for(i=0; i<NUMBER_OF_CONFIG_ENTRIES; i++)
        if(opts->config[i] != NULL)
            free(opts->config[i]);
}

static void
validate_int_var_ranges(fko_srv_options_t *opts)
{
#if FIREWALL_IPFW
    int     is_err = FKO_SUCCESS;
#endif

    range_check(opts, "PCAP_LOOP_SLEEP", opts->config[CONF_PCAP_LOOP_SLEEP],
        1, RCHK_MAX_PCAP_LOOP_SLEEP);
    range_check(opts, "MAX_SPA_PACKET_AGE", opts->config[CONF_MAX_SPA_PACKET_AGE],
        1, RCHK_MAX_SPA_PACKET_AGE);
    range_check(opts, "MAX_SNIFF_BYTES", opts->config[CONF_MAX_SNIFF_BYTES],
        1, RCHK_MAX_SNIFF_BYTES);
    range_check(opts, "TCPSERV_PORT", opts->config[CONF_TCPSERV_PORT],
        1, RCHK_MAX_TCPSERV_PORT);

#if FIREWALL_IPFW
    range_check(opts, "IPFW_START_RULE_NUM", opts->config[CONF_IPFW_START_RULE_NUM],
        0, RCHK_MAX_IPFW_START_RULE_NUM);
    range_check(opts, "IPFW_MAX_RULES", opts->config[CONF_IPFW_MAX_RULES],
        1, RCHK_MAX_IPFW_MAX_RULES);
    range_check(opts, "IPFW_ACTIVE_SET_NUM", opts->config[CONF_IPFW_ACTIVE_SET_NUM],
        0, RCHK_MAX_IPFW_SET_NUM);
    range_check(opts, "IPFW_EXPIRE_SET_NUM", opts->config[CONF_IPFW_EXPIRE_SET_NUM],
        0, RCHK_MAX_IPFW_SET_NUM);
    range_check(opts, "IPFW_EXPIRE_PURGE_INTERVAL",
        opts->config[CONF_IPFW_EXPIRE_PURGE_INTERVAL],
        1, RCHK_MAX_IPFW_PURGE_INTERVAL);

    /* Make sure the active and expire sets are not identical whenever
     * they are non-zero
    */
    if((strtol_wrapper(opts->config[CONF_IPFW_ACTIVE_SET_NUM],
                    0, RCHK_MAX_IPFW_SET_NUM, NO_EXIT_UPON_ERR, &is_err) > 0
            && strtol_wrapper(opts->config[CONF_IPFW_EXPIRE_SET_NUM],
                0, RCHK_MAX_IPFW_SET_NUM, NO_EXIT_UPON_ERR, &is_err) > 0)
            && strtol_wrapper(opts->config[CONF_IPFW_ACTIVE_SET_NUM],
                0, RCHK_MAX_IPFW_SET_NUM, NO_EXIT_UPON_ERR, &is_err)
                == strtol_wrapper(opts->config[CONF_IPFW_EXPIRE_SET_NUM],
                    0, RCHK_MAX_IPFW_SET_NUM, NO_EXIT_UPON_ERR, &is_err))
    {
        log_msg(LOG_ERR,
                "[*] Cannot set identical ipfw active and expire sets.");
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] invalid integer conversion error.\n");
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

#elif FIREWALL_PF
    range_check(opts, "PF_EXPIRE_INTERVAL", opts->config[CONF_PF_EXPIRE_INTERVAL],
        1, RCHK_MAX_PF_EXPIRE_INTERVAL);

#endif /* FIREWALL type */

    return;
}

/* Parse the config file...
*/
static void
parse_config_file(fko_srv_options_t *opts, const char *config_file)
{
    FILE           *cfile_ptr;
    unsigned int    numLines = 0;
    unsigned int    i, good_ent;
    int             cndx;

    char            conf_line_buf[MAX_LINE_LEN] = {0};
    char            var[MAX_LINE_LEN]  = {0};
    char            val[MAX_LINE_LEN]  = {0};
    char            tmp1[MAX_LINE_LEN] = {0};
    char            tmp2[MAX_LINE_LEN] = {0};

    struct stat     st;

    /* Make sure the config file exists.
    */
    if(stat(config_file, &st) != 0)
    {
        log_msg(LOG_ERR, "[*] Config file: '%s' was not found.",
            config_file);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    if(verify_file_perms_ownership(config_file) != 1)
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);

    /* See the comment in the parse_access_file() function regarding security
     * here relative to a TOCTOU bug flagged by Coverity.
    */
    if ((cfile_ptr = fopen(config_file, "r")) == NULL)
    {
        log_msg(LOG_ERR, "[*] Could not open config file: %s",
            config_file);
        perror(NULL);

        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
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
            log_msg(LOG_ERR,
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
                            strlcpy(val, opts->config[cndx], sizeof(val));
                            strlcat(val, tmp2, sizeof(val));
                        }
                    }
                }

                set_config_entry(opts, i, val);
                good_ent++;
                break;
            }
        }

        if(good_ent == 0)
            log_msg(LOG_ERR,
                "[*] Ignoring unknown configuration parameter: '%s' in %s",
                var, config_file
            );
    }

    fclose(cfile_ptr);

    return;
}

/* Set defaults, and do sanity and bounds checks for the various options.
*/
static void
validate_options(fko_srv_options_t *opts)
{
    char tmp_path[MAX_PATH_LEN] = {0};

    /* If no conf dir is set in the config file, use the default.
    */
    if(opts->config[CONF_FWKNOP_CONF_DIR] == NULL)
        set_config_entry(opts, CONF_FWKNOP_CONF_DIR, DEF_CONF_DIR);

    /* If no access.conf path was specified on the command line or set in
     * the config file, use the default.
    */
    if(opts->config[CONF_ACCESS_FILE] == NULL)
        set_config_entry(opts, CONF_ACCESS_FILE, DEF_ACCESS_FILE);

    /* If the pid and digest cache files where not set in the config file or
     * via command-line, then grab the defaults. Start with RUN_DIR as the
     * files may depend on that.
    */
    if(opts->config[CONF_FWKNOP_RUN_DIR] == NULL)
        set_config_entry(opts, CONF_FWKNOP_RUN_DIR, DEF_RUN_DIR);

    if(opts->config[CONF_FWKNOP_PID_FILE] == NULL)
    {
        strlcpy(tmp_path, opts->config[CONF_FWKNOP_RUN_DIR], sizeof(tmp_path));

        if(tmp_path[strlen(tmp_path)-1] != '/')
            strlcat(tmp_path, "/", sizeof(tmp_path));

        strlcat(tmp_path, DEF_PID_FILENAME, sizeof(tmp_path));

        set_config_entry(opts, CONF_FWKNOP_PID_FILE, tmp_path);
    }

#if USE_FILE_CACHE
    if(opts->config[CONF_DIGEST_FILE] == NULL)
#else
    if(opts->config[CONF_DIGEST_DB_FILE] == NULL)
#endif
    {
        strlcpy(tmp_path, opts->config[CONF_FWKNOP_RUN_DIR], sizeof(tmp_path));

        if(tmp_path[strlen(tmp_path)-1] != '/')
            strlcat(tmp_path, "/", sizeof(tmp_path));


#if USE_FILE_CACHE
        strlcat(tmp_path, DEF_DIGEST_CACHE_FILENAME, sizeof(tmp_path));
        set_config_entry(opts, CONF_DIGEST_FILE, tmp_path);
#else
        strlcat(tmp_path, DEF_DIGEST_CACHE_DB_FILENAME, sizeof(tmp_path));
        set_config_entry(opts, CONF_DIGEST_DB_FILE, tmp_path);
#endif
    }

    /* Set remaining require CONF_ vars if they are not already set.  */

    /* PCAP capture interface - note that if '-r <pcap file>' is specified
     * on the command line, then this will override the pcap interface setting.
    */
    if(opts->config[CONF_PCAP_INTF] == NULL)
        set_config_entry(opts, CONF_PCAP_INTF, DEF_INTERFACE);

    /* PCAP Promiscuous mode.
    */
    if(opts->config[CONF_ENABLE_PCAP_PROMISC] == NULL)
        set_config_entry(opts, CONF_ENABLE_PCAP_PROMISC,
            DEF_ENABLE_PCAP_PROMISC);

    /* The packet count argument to pcap_dispatch()
    */
    if(opts->config[CONF_PCAP_DISPATCH_COUNT] == NULL)
        set_config_entry(opts, CONF_PCAP_DISPATCH_COUNT,
            DEF_PCAP_DISPATCH_COUNT);

    /* Microseconds to sleep between pcap loop iterations
    */
    if(opts->config[CONF_PCAP_LOOP_SLEEP] == NULL)
        set_config_entry(opts, CONF_PCAP_LOOP_SLEEP,
            DEF_PCAP_LOOP_SLEEP);

    /* PCAP Filter.
    */
    if(opts->config[CONF_PCAP_FILTER] == NULL)
        set_config_entry(opts, CONF_PCAP_FILTER, DEF_PCAP_FILTER);

    /* Enable SPA packet aging unless we're getting packet data
     * directly from a pcap file
    */
    if(opts->config[CONF_ENABLE_SPA_PACKET_AGING] == NULL)
    {
        if(opts->config[CONF_PCAP_FILE] == NULL)
        {
            set_config_entry(opts, CONF_ENABLE_SPA_PACKET_AGING,
                DEF_ENABLE_SPA_PACKET_AGING);
        }
        else
        {
            set_config_entry(opts, CONF_ENABLE_SPA_PACKET_AGING, "N");
        }
    }

    /* SPA packet age.
    */
    if(opts->config[CONF_MAX_SPA_PACKET_AGE] == NULL)
        set_config_entry(opts, CONF_MAX_SPA_PACKET_AGE,
            DEF_MAX_SPA_PACKET_AGE);


    /* Enable digest persistence.
    */
    if(opts->config[CONF_ENABLE_DIGEST_PERSISTENCE] == NULL)
        set_config_entry(opts, CONF_ENABLE_DIGEST_PERSISTENCE,
            DEF_ENABLE_DIGEST_PERSISTENCE);

    /* Max sniff bytes.
    */
    if(opts->config[CONF_MAX_SNIFF_BYTES] == NULL)
        set_config_entry(opts, CONF_MAX_SNIFF_BYTES, DEF_MAX_SNIFF_BYTES);

#if FIREWALL_IPTABLES
    /* Enable IPT forwarding.
    */
    if(opts->config[CONF_ENABLE_IPT_FORWARDING] == NULL)
        set_config_entry(opts, CONF_ENABLE_IPT_FORWARDING,
            DEF_ENABLE_IPT_FORWARDING);

    /* Enable IPT local NAT.
    */
    if(opts->config[CONF_ENABLE_IPT_LOCAL_NAT] == NULL)
        set_config_entry(opts, CONF_ENABLE_IPT_LOCAL_NAT,
            DEF_ENABLE_IPT_LOCAL_NAT);

    /* Enable IPT SNAT.
    */
    if(opts->config[CONF_ENABLE_IPT_SNAT] == NULL)
        set_config_entry(opts, CONF_ENABLE_IPT_SNAT,
            DEF_ENABLE_IPT_SNAT);

    /* Make sure we have a valid IP if SNAT is enabled
    */
    if(strncasecmp(opts->config[CONF_ENABLE_IPT_SNAT], "Y", 1) == 0)
    {
        /* Note that fw_config_init() will set use_masquerade if necessary
        */
        if(opts->config[CONF_SNAT_TRANSLATE_IP] != NULL)
        {
            if(! is_valid_ipv4_addr(opts->config[CONF_SNAT_TRANSLATE_IP]))
            {
                log_msg(LOG_ERR,
                    "Invalid IPv4 addr for SNAT_TRANSLATE_IP"
                );
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }
    }

    /* Enable IPT OUTPUT.
    */
    if(opts->config[CONF_ENABLE_IPT_OUTPUT] == NULL)
        set_config_entry(opts, CONF_ENABLE_IPT_OUTPUT,
            DEF_ENABLE_IPT_OUTPUT);

    /* Flush IPT at init.
    */
    if(opts->config[CONF_FLUSH_IPT_AT_INIT] == NULL)
        set_config_entry(opts, CONF_FLUSH_IPT_AT_INIT, DEF_FLUSH_IPT_AT_INIT);

    /* Flush IPT at exit.
    */
    if(opts->config[CONF_FLUSH_IPT_AT_EXIT] == NULL)
        set_config_entry(opts, CONF_FLUSH_IPT_AT_EXIT, DEF_FLUSH_IPT_AT_EXIT);

    /* IPT input access.
    */
    if(opts->config[CONF_IPT_INPUT_ACCESS] == NULL)
        set_config_entry(opts, CONF_IPT_INPUT_ACCESS,
            DEF_IPT_INPUT_ACCESS);

    if(validate_ipt_chain_conf(opts->config[CONF_IPT_INPUT_ACCESS]) != 1)
    {
        log_msg(LOG_ERR,
            "Invalid IPT_INPUT_ACCESS specification, see fwknopd.conf comments"
        );
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* IPT output access.
    */
    if(opts->config[CONF_IPT_OUTPUT_ACCESS] == NULL)
        set_config_entry(opts, CONF_IPT_OUTPUT_ACCESS,
            DEF_IPT_OUTPUT_ACCESS);

    if(validate_ipt_chain_conf(opts->config[CONF_IPT_OUTPUT_ACCESS]) != 1)
    {
        log_msg(LOG_ERR,
            "Invalid IPT_OUTPUT_ACCESS specification, see fwknopd.conf comments"
        );
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* IPT forward access.
    */
    if(opts->config[CONF_IPT_FORWARD_ACCESS] == NULL)
        set_config_entry(opts, CONF_IPT_FORWARD_ACCESS,
            DEF_IPT_FORWARD_ACCESS);

    if(validate_ipt_chain_conf(opts->config[CONF_IPT_FORWARD_ACCESS]) != 1)
    {
        log_msg(LOG_ERR,
            "Invalid IPT_FORWARD_ACCESS specification, see fwknopd.conf comments"
        );
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* IPT dnat access.
    */
    if(opts->config[CONF_IPT_DNAT_ACCESS] == NULL)
        set_config_entry(opts, CONF_IPT_DNAT_ACCESS,
            DEF_IPT_DNAT_ACCESS);

    if(validate_ipt_chain_conf(opts->config[CONF_IPT_DNAT_ACCESS]) != 1)
    {
        log_msg(LOG_ERR,
            "Invalid IPT_DNAT_ACCESS specification, see fwknopd.conf comments"
        );
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* IPT snat access.
    */
    if(opts->config[CONF_IPT_SNAT_ACCESS] == NULL)
        set_config_entry(opts, CONF_IPT_SNAT_ACCESS,
            DEF_IPT_SNAT_ACCESS);

    if(validate_ipt_chain_conf(opts->config[CONF_IPT_SNAT_ACCESS]) != 1)
    {
        log_msg(LOG_ERR,
            "Invalid IPT_SNAT_ACCESS specification, see fwknopd.conf comments"
        );
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* IPT masquerade access.
    */
    if(opts->config[CONF_IPT_MASQUERADE_ACCESS] == NULL)
        set_config_entry(opts, CONF_IPT_MASQUERADE_ACCESS,
            DEF_IPT_MASQUERADE_ACCESS);

    if(validate_ipt_chain_conf(opts->config[CONF_IPT_MASQUERADE_ACCESS]) != 1)
    {
        log_msg(LOG_ERR,
            "Invalid IPT_MASQUERADE_ACCESS specification, see fwknopd.conf comments"
        );
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* Check for the iptables 'comment' match at init time
    */
    if(opts->config[CONF_ENABLE_IPT_COMMENT_CHECK] == NULL)
        set_config_entry(opts, CONF_ENABLE_IPT_COMMENT_CHECK,
            DEF_ENABLE_IPT_COMMENT_CHECK);

#elif FIREWALL_IPFW

    /* Flush ipfw rules at init.
    */
    if(opts->config[CONF_FLUSH_IPFW_AT_INIT] == NULL)
        set_config_entry(opts, CONF_FLUSH_IPFW_AT_INIT, DEF_FLUSH_IPFW_AT_INIT);

    /* Flush ipfw rules at exit.
    */
    if(opts->config[CONF_FLUSH_IPFW_AT_EXIT] == NULL)
        set_config_entry(opts, CONF_FLUSH_IPFW_AT_EXIT, DEF_FLUSH_IPFW_AT_EXIT);

    /* Set IPFW start rule number.
    */
    if(opts->config[CONF_IPFW_START_RULE_NUM] == NULL)
        set_config_entry(opts, CONF_IPFW_START_RULE_NUM,
            DEF_IPFW_START_RULE_NUM);

    /* Set IPFW max rules.
    */
    if(opts->config[CONF_IPFW_MAX_RULES] == NULL)
        set_config_entry(opts, CONF_IPFW_MAX_RULES,
            DEF_IPFW_MAX_RULES);

    /* Set IPFW active set number.
    */
    if(opts->config[CONF_IPFW_ACTIVE_SET_NUM] == NULL)
        set_config_entry(opts, CONF_IPFW_ACTIVE_SET_NUM,
            DEF_IPFW_ACTIVE_SET_NUM);

    /* Set IPFW expire set number.
    */
    if(opts->config[CONF_IPFW_EXPIRE_SET_NUM] == NULL)
        set_config_entry(opts, CONF_IPFW_EXPIRE_SET_NUM,
            DEF_IPFW_EXPIRE_SET_NUM);

    /* Set IPFW Dynamic rule expiry interval.
    */
    if(opts->config[CONF_IPFW_EXPIRE_PURGE_INTERVAL] == NULL)
        set_config_entry(opts, CONF_IPFW_EXPIRE_PURGE_INTERVAL,
            DEF_IPFW_EXPIRE_PURGE_INTERVAL);

    /* Set IPFW Dynamic rule expiry interval.
    */
    if(opts->config[CONF_IPFW_ADD_CHECK_STATE] == NULL)
        set_config_entry(opts, CONF_IPFW_ADD_CHECK_STATE,
            DEF_IPFW_ADD_CHECK_STATE);

#elif FIREWALL_PF
    /* Set PF anchor name
    */
    if(opts->config[CONF_PF_ANCHOR_NAME] == NULL)
        set_config_entry(opts, CONF_PF_ANCHOR_NAME,
            DEF_PF_ANCHOR_NAME);

    /* Set PF rule expiry interval.
    */
    if(opts->config[CONF_PF_EXPIRE_INTERVAL] == NULL)
        set_config_entry(opts, CONF_PF_EXPIRE_INTERVAL,
            DEF_PF_EXPIRE_INTERVAL);

#elif FIREWALL_IPF
    /* --DSS Place-holder */

#endif /* FIREWALL type */

    /* GPG Home dir.
    */
    if(opts->config[CONF_GPG_HOME_DIR] == NULL)
        set_config_entry(opts, CONF_GPG_HOME_DIR, DEF_GPG_HOME_DIR);

    /* GPG executable
    */
    if(opts->config[CONF_GPG_EXE] == NULL)
        set_config_entry(opts, CONF_GPG_EXE, DEF_GPG_EXE);

    /* Enable SPA over HTTP.
    */
    if(opts->config[CONF_ENABLE_SPA_OVER_HTTP] == NULL)
        set_config_entry(opts, CONF_ENABLE_SPA_OVER_HTTP,
            DEF_ENABLE_SPA_OVER_HTTP);

    /* Enable TCP server.
    */
    if(opts->config[CONF_ENABLE_TCP_SERVER] == NULL)
        set_config_entry(opts, CONF_ENABLE_TCP_SERVER, DEF_ENABLE_TCP_SERVER);

    /* TCP Server port.
    */
    if(opts->config[CONF_TCPSERV_PORT] == NULL)
        set_config_entry(opts, CONF_TCPSERV_PORT, DEF_TCPSERV_PORT);

    /* Syslog identity.
    */
    if(opts->config[CONF_SYSLOG_IDENTITY] == NULL)
        set_config_entry(opts, CONF_SYSLOG_IDENTITY, DEF_SYSLOG_IDENTITY);

    /* Syslog facility.
    */
    if(opts->config[CONF_SYSLOG_FACILITY] == NULL)
        set_config_entry(opts, CONF_SYSLOG_FACILITY, DEF_SYSLOG_FACILITY);


    /* Validate integer variable ranges
    */
    validate_int_var_ranges(opts);

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
        log_msg(LOG_ERR,
            "The -D, -K, -R, and -S options are mutually exclusive.  Pick only one."
        );
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    if(opts->config[CONF_FIREWALL_EXE] == NULL)
    {
        log_msg(LOG_ERR,
            "[*] No firewall command executable is set. Please check FIREWALL_EXE in fwknopd.conf."
        );
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    return;
}

void
set_preconfig_entries(fko_srv_options_t *opts)
{
    /* First, set any default or otherwise static settings here.  Some may
     * end up being overwritten via config file or command-line.
    */

    /* Setup the firewall executable based on build-time info.
     * --DSS Note: We will want to either force external script mode, or
     *             error out if we do not have a firewall executable defined.
    */
#ifdef FIREWALL_EXE
    set_config_entry(opts, CONF_FIREWALL_EXE, FIREWALL_EXE);
#endif

}

/* Initialize program configuration via config file and/or command-line
 * switches.
*/
void
config_init(fko_srv_options_t *opts, int argc, char **argv)
{
    int             cmd_arg, index, is_err;
    unsigned char   got_conf_file = 0, got_override_config = 0;

    char            override_file[MAX_LINE_LEN] = {0};
    char           *ndx, *cmrk;

    /* Zero out options and opts_track.
    */
    memset(opts, 0x00, sizeof(fko_srv_options_t));

    /* Set some preconfiguration options (i.e. build-time defaults)
    */
    set_preconfig_entries(opts);

    /* In case this is a re-config.
    */
    optind = 0;

    /* First, scan the command-line args for -h/--help or an alternate
     * configuration file. If we find an alternate config file, use it,
     * otherwise use the default.  We also grab any override config files
     * as well.
    */
    while ((cmd_arg = getopt_long(argc, argv,
            GETOPTS_OPTION_STRING, cmd_opts, &index)) != -1) {

        /* If help is wanted, give it and exit.
        */
        switch(cmd_arg) {
            case 'h':
                usage();
                clean_exit(opts, NO_FW_CLEANUP, EXIT_SUCCESS);
                break;

            /* Look for configuration file arg.
            */
            case 'c':
                set_config_entry(opts, CONF_CONFIG_FILE, optarg);
                got_conf_file++;

                /* If we already have the config_override option, we are done.
                */
                if(got_override_config > 0)
                    break;

            /* Look for override configuration file arg.
            */
            case 'O':
                set_config_entry(opts, CONF_OVERRIDE_CONFIG, optarg);
                got_override_config++;

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
        /* Make a copy of the override_config string so we can munge it.
        */
        strlcpy(override_file, opts->config[CONF_OVERRIDE_CONFIG], sizeof(override_file));

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

    /* Set up the verbosity level according to the value found in the
     * config files */
    if (opts->config[CONF_VERBOSE] != NULL)
    {
        opts->verbose = strtol_wrapper(opts->config[CONF_VERBOSE], 0, -1,
                                       NO_EXIT_UPON_ERR, &is_err);
        if(is_err != FKO_SUCCESS)
        {
            log_msg(LOG_ERR, "[*] VERBOSE value '%s' not in the range (>0)",
                opts->config[CONF_VERBOSE]);
            clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
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
            case 'a':
                set_config_entry(opts, CONF_ACCESS_FILE, optarg);
                break;
            case 'c':
                /* This was handled earlier */
                break;
            case 'C':
                opts->packet_ctr_limit = strtol_wrapper(optarg,
                        0, (2 << 30), NO_EXIT_UPON_ERR, &is_err);
                if(is_err != FKO_SUCCESS)
                {
                    log_msg(LOG_ERR,
                        "[*] invalid -C packet count limit '%s'",
                        optarg);
                    clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
                }
                break;
            case 'd':
#if USE_FILE_CACHE
                set_config_entry(opts, CONF_DIGEST_FILE, optarg);
#else
                set_config_entry(opts, CONF_DIGEST_DB_FILE, optarg);
#endif
                break;
            case 'D':
                opts->dump_config = 1;
                break;
            case DUMP_SERVER_ERR_CODES:
                dump_server_errors();
                clean_exit(opts, NO_FW_CLEANUP, EXIT_SUCCESS);
            case 'f':
                opts->foreground = 1;
                break;
            case FW_LIST:
                opts->fw_list = 1;
                break;
            case FW_LIST_ALL:
                opts->fw_list = 1;
                opts->fw_list_all = 1;
                break;
            case FW_FLUSH:
                opts->fw_flush = 1;
                break;
            case GPG_HOME_DIR:
                if (is_valid_dir(optarg))
                {
                    set_config_entry(opts, CONF_GPG_HOME_DIR, optarg);
                }
                else
                {
                    log_msg(LOG_ERR,
                        "[*] Directory '%s' could not stat()/does not exist?",
                        optarg);
                    clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
                }
                break;
            case 'i':
                set_config_entry(opts, CONF_PCAP_INTF, optarg);
                break;
            case IPT_DISABLE_CHECK_SUPPORT:
                opts->ipt_disable_check_support = 1;
                break;
            case 'K':
                opts->kill = 1;
                break;
            case 'l':
                set_config_entry(opts, CONF_LOCALE, optarg);
                break;
            case 'O':
                /* This was handled earlier */
                break;
            case 'p':
                set_config_entry(opts, CONF_FWKNOP_PID_FILE, optarg);
                break;
            case 'P':
                set_config_entry(opts, CONF_PCAP_FILTER, optarg);
                break;
            case PCAP_FILE:
                set_config_entry(opts, CONF_PCAP_FILE, optarg);
                break;
            case ENABLE_PCAP_ANY_DIRECTION:
                opts->pcap_any_direction = 1;
                break;
            case ROTATE_DIGEST_CACHE:
                opts->rotate_digest_cache = 1;
                break;
            case 'R':
                opts->restart = 1;
                break;
            case 'S':
                opts->status = 1;
                break;
            /* Verbosity level */
            case 'v':
                opts->verbose++;
                break;
            case SYSLOG_ENABLE:
                opts->syslog_enable = 1;
                break;
            case 'V':
                fprintf(stdout, "fwknopd server %s\n", MY_VERSION);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_SUCCESS);
                break;
            default:
                usage();
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
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
dump_config(const fko_srv_options_t *opts)
{
    int i;

    fprintf(stdout, "Current fwknopd config settings:\n");

    for(i=0; i<NUMBER_OF_CONFIG_ENTRIES; i++)
        fprintf(stdout, "%3i. %-28s =  '%s'\n",
            i,
            config_map[i],
            (opts->config[i] == NULL) ? "<not set>" : opts->config[i]
        );

    fprintf(stdout, "\n");
    fflush(stdout);
}

/* Print usage message...
*/
void
usage(void)
{
    fprintf(stdout, "\n%s server version %s\n%s - http://www.cipherdyne.org/fwknop/\n\n",
            MY_NAME, MY_VERSION, MY_DESC);
    fprintf(stdout,
      "Usage: fwknopd [options]\n\n"
      " -h, --help              - Print this usage message and exit.\n"
      " -a, --access-file       - Specify an alternate access.conf file.\n"
      " -c, --config-file       - Specify an alternate configuration file.\n"
      " -C, --packet-limit      - Limit the number of candidate SPA packets to\n"
      "                           process and exit when this limit is reached.\n"
      " -d, --digest-file       - Specify an alternate digest.cache file.\n"
      " -D, --dump-config       - Dump the current fwknop configuration values.\n"
      " -f, --foreground        - Run fwknopd in the foreground (do not become\n"
      "                           a background daemon).\n"
      " -i, --interface         - Specify interface to listen for incoming SPA\n"
      "                           packets.\n"
      " -K, --kill              - Kill the currently running fwknopd.\n"
      "     --gpg-home-dir      - Specify the GPG home directory.\n"
      " -l, --locale            - Provide a locale setting other than the system\n"
      "                           default.\n"
      " -O, --override-config   - Specify a file with configuration entries that will\n"
      "                           overide those in fwknopd.conf\n"
      " -p, --pid-file          - Specify an alternate fwknopd.pid file.\n"
      " -P, --pcap-filter       - Specify a Berkeley packet filter statement to\n"
      "                           override the PCAP_FILTER variable in fwknopd.conf.\n"
      " -R, --restart           - Force the currently running fwknopd to restart.\n"
      "     --rotate-digest-cache\n"
      "                         - Rotate the digest cache file by renaming it to\n"
      "                           '<name>-old', and starting a new one.\n"
      " -S, --status            - Display the status of any running fwknopd process.\n"
      " -v, --verbose           - Set verbose mode.\n"
      "     --syslog-enable     - Allow messages to be sent to syslog even if the\n"
      "                           foreground mode is set.\n"
      " -V, --version           - Print version number.\n"
      "     --fw-list           - List all firewall rules that fwknop has created\n"
      "                           and then exit.\n"
      "     --fw-list-all       - List all firewall rules in the complete policy,\n"
      "                           including those that have nothing to do with\n"
      "                           fwknop.\n"
      "     --fw-flush          - Flush all firewall rules created by fwknop.\n"
      "\n"
    );

    return;
}

/***EOF***/
