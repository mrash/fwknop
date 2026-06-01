/**
 * \file server/fw_util_nftables.c
 *
 * \brief Fwknop routines for managing nftables firewall rules.
 */

/*  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
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
 *****************************************************************************
*/

#include "fwknopd_common.h"

#ifdef FIREWALL_NFTABLES

#include "fw_util.h"
#include "utils.h"
#include "log_msg.h"
#include "extcmd.h"
#include "access.h"
#include <jansson.h>
#include "fw_util_nftables_json.h"

#define IPT_ANY_IP              "0.0.0.0/0"

static void
run_nft_cmd_plain(const fko_srv_options_t * const opts, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));
static int
run_nft_cmd(const fko_srv_options_t * const opts, json_t **json, const char *fmt, ...) __attribute__ ((format (printf, 3, 4)));

static struct fw_config fwc;

static const char*
proto_str(int proto)
{
    switch (proto)
    {
        case PROTO_TCP:
            return "tcp";
        case PROTO_UDP:
            return "udp";
        default:
            return "";
    }
}

static inline int
get_fw_chain_conf_bool(const fko_srv_options_t * const opts, int config)
{
    return strncasecmp(opts->config[config], "Y", 1) == 0;
}

static int
set_fw_chain_conf(const int type, const char * const conf_str)
{
    int i, j, is_err;
    char tbuf[MAX_LINE_LEN]  = {0};
    const char *ndx          = conf_str;

    char *chain_fields[FW_NUM_CHAIN_FIELDS];

    struct fw_chain *chain = &(fwc.chain[type]);

    if(conf_str == NULL)
    {
        log_msg(LOG_ERR, "[*] NULL conf_str");
        return 0;
    }

    chain->type = type;

    if(ndx != NULL)
        chain_fields[0] = tbuf;

    i = 0;
    j = 1;
    while(*ndx != '\0')
    {
        if(*ndx != ' ')
        {
            if(*ndx == ',')
            {
                tbuf[i] = '\0';
                chain_fields[j++] = &(tbuf[++i]);
            }
            else
                tbuf[i++] = *ndx;
        }
        if(*ndx != '\0'
                && *ndx != ' '
                && *ndx != ','
                && *ndx != '_'
                && isalnum(*ndx) == 0)
        {
            log_msg(LOG_ERR, "[*] Custom chain config parse error: "
                "invalid character '%c' for chain type %i, "
                "line: %s", *ndx, type, conf_str);
            return 0;
        }
        ndx++;
    }

    /* Sanity check - j should be the number of chain fields
     * (excluding the type).
    */
    if(j != FW_NUM_CHAIN_FIELDS)
    {
        log_msg(LOG_ERR, "[*] Custom chain config parse error: "
            "wrong number of fields for chain type %i, "
            "line: %s", type, conf_str);
        return 0;
    }

    /* Pull and set Target */
    strlcpy(chain->target, chain_fields[0], sizeof(chain->target));

    /* Pull and set Table */
    strlcpy(chain->table, chain_fields[1], sizeof(chain->table));

    /* Pull and set From_chain */
    strlcpy(chain->from_chain, chain_fields[2], sizeof(chain->from_chain));

    /* Pull and set Jump_rule_position */
    chain->jump_rule_pos = strtol_wrapper(chain_fields[3],
            0, RCHK_MAX_IPT_RULE_NUM, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] invalid jump rule position in Line: %s",
            conf_str);
        return 0;
    }

    /* Pull and set To_chain */
    strlcpy(chain->to_chain, chain_fields[4], sizeof(chain->to_chain));

    /* Pull and set to_chain rule position */
    chain->rule_pos = strtol_wrapper(chain_fields[5],
            0, RCHK_MAX_IPT_RULE_NUM, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] invalid to_chain rule position in Line: %s",
            conf_str);
        return 0;
    }
    return 1;
}

void
run_nft_cmd_plain(const fko_srv_options_t * const opts, const char *fmt, ...)
{
    char cmd[512];

    { /* assemble command string */
        char *cmd2 = cmd;
        cmd2 += snprintf(cmd, sizeof(cmd), "%s ", opts->fw_config->fw_command);
        if (cmd2 - cmd >= sizeof(cmd))
            goto err_cmd_too_long;
        va_list args;
        va_start(args, fmt);
        cmd2 += vsnprintf(cmd2, cmd + sizeof(cmd) - cmd2, fmt, args);
        va_end(args);
        if (cmd2 - cmd >= sizeof(cmd))
            goto err_cmd_too_long;
    }

    log_msg(LOG_DEBUG, "cmd: %s", cmd);
    (void)system(cmd);
    return;

err_cmd_too_long:
    log_msg(LOG_ERR, "command too long for buffer (length:%zu): \"%s\" -> \"%.*s\"", sizeof(cmd), fmt, sizeof(cmd), cmd);
}

int
run_nft_cmd(const fko_srv_options_t * const opts, json_t **json, const char *fmt, ...)
{
    char cmd[512];
    json_t *json_tmp;
    json_error_t json_err;
    int rv = 0;

    { /* assemble command string */
        char *cmd2 = cmd;
        cmd2 += snprintf(cmd, sizeof(cmd), "%s -jaes ", opts->fw_config->fw_command);
        if (cmd2 - cmd >= sizeof(cmd))
            goto err_cmd_too_long;
        char *cmd_param_start = cmd2;
        va_list args;
        va_start(args, fmt);
        cmd2 += vsnprintf(cmd2, cmd + sizeof(cmd) - cmd2, fmt, args);
        va_end(args);
        if (cmd2 - cmd >= sizeof(cmd))
            goto err_cmd_too_long;

        { /* add suffix to make command always output a json string --
           * see comment near pclose(p) */
            char ch;
            if (sscanf(cmd_param_start, "delete %c", &ch) == 1 || sscanf(cmd_param_start, "flush %c", &ch) == 1)
            {
                cmd2 += snprintf(cmd2, cmd + sizeof(cmd) - cmd2, "\\; list tables");
                if (cmd2 - cmd >= sizeof(cmd))
                    goto err_cmd_too_long;
            }
        }
    }

    log_msg(LOG_DEBUG, "cmd: %s", cmd);

    { /* run external command */
        FILE *p = popen(cmd, "r");
        if (!p) {
            perror("popen");
            return -1;
        }

        json_tmp = json_loadfd(fileno(p), 0, &json_err);

        /* TODO: our sighandler will wait for chlid processes to finish
        *        (waitpid(-1)). This will result in a race condition due to
        *        which pclose sporadically returns -1. As of now, we cannot rely
        *        on it's return value. Some commands do not return valid JSON
        *        output (eg. deleting chains and rules). To work around this and
        *        make nft print valid JSON output anyway, some commands have
        *        "; list tables" appended. */
        (void)pclose(p);

        if (!json_tmp)
        {
            /* couldn't parse JSON output */
            log_msg(LOG_DEBUG, "%s: command failed: \"%s\"", __func__, cmd);
            rv = -1;
        }
    }

    if (json)
        *json = json_tmp;
    else
        json_decref(json_tmp);
    return rv;
err_cmd_too_long:
    log_msg(LOG_ERR, "command too long for buffer (length:%zu): \"%s\" -> \"%.*s\"", sizeof(cmd), fmt, sizeof(cmd), cmd);
    return -1;
}

static int
get_inserted_rule_handle(json_t *root, json_int_t *handle)
{
    /* json.nftables[0].insert.rule.handle */
    json_t *tmp;
    tmp = json_object_get(root, "nftables");

    if (!json_is_array(tmp)) return -1;
    if (json_array_size(tmp) != 1) return -1;
    tmp = json_array_get(tmp, 0);

    if (!json_is_object(tmp)) return -1;
    tmp= json_object_get(tmp, "insert");

    if (!json_is_object(tmp)) return -1;
    tmp = json_object_get(tmp, "rule");

    if (!json_is_object(tmp)) return -1;
    return json_integer_field_get(tmp, "handle", handle);
}

static int
is_table_used_by_any_chain(const fko_srv_options_t * const opts, const char *table_name)
{
    for(int i=0; i < NUM_FWKNOP_ACCESS_TYPES; i++)
    {
        struct fw_chain *chain = &(opts->fw_config->chain[i]);
        if(chain->table[0] == '\0' || chain->to_chain[i] == '\0')
            continue;
        if (strcmp(chain->table, table_name)==0)
        {
            return 1;
        }
    }
    return 0;
}

/* Print all firewall rules currently instantiated by the running fwknopd
 * daemon to stdout.
*/
int
fw_dump_rules(const fko_srv_options_t * const opts)
{
    if (opts->fw_list_all)
    {
        json_t *j;
        if (run_nft_cmd(opts, &j, "list tables") != 0)
        {
            log_msg(LOG_ERR, "%s: failed to list tables", __func__);
            return -1;
        }

        json_t *arr = json_object_get(j, "nftables"); /* nftables */
        if (!json_is_array(arr))
            goto err;
        size_t index;
        json_t *value;
        json_array_foreach(arr, index, value)
        {
            json_t *table = json_object_get(value, "table");
            if (!json_is_object(table)) continue;

            const char *family;
            if (json_string_field_get(table, "family", &family) != 0)
            {
                log_msg(LOG_ERR, "%s: can't get family of table", __func__);
                continue;
            }
            if (strncmp(family, fwc.ipv4_family, strlen(fwc.ipv4_family)) != 0)
                continue;

            const char *name;
            if (json_string_field_get(table, "name", &name) != 0)
            {
                log_msg(LOG_ERR, "%s: can't get family of table", __func__);
                continue;
            }

            if (is_table_used_by_any_chain(opts, name))
            {
                run_nft_cmd_plain(opts, "list table %s %s", fwc.ipv4_family, name);
            }
        }

    err:
        json_decref(j);
        return 0;
    }
    else if (opts->fw_list)
    {
        int rv = 0;
        int i;
        
        for(i=0; i < NUM_FWKNOP_ACCESS_TYPES; i++)
        {
            struct fw_chain *chain = &fwc.chain[i];
            if(chain->target[0] == '\0')
                continue;
            run_nft_cmd_plain(opts, "list chain %s %s %s", fwc.ipv4_family, chain->table, chain->to_chain);
        }

        return rv;
    }
    return 0;
}

int
fw_config_init(fko_srv_options_t * const opts)
{
    memset(&fwc, 0x0, sizeof(struct fw_config));

    /* Set our firewall exe command path (iptables in most cases).
    */
    strlcpy(fwc.fw_command, opts->config[CONF_FIREWALL_EXE], sizeof(fwc.fw_command));

#if HAVE_LIBFIU
    fiu_return_on("fw_config_init", 0);
#endif

    /* Pull the fwknop chain config info and setup our internal
     * config struct.  The IPT_INPUT is the only one that is
     * required. The rest are optional.
    */
    if(set_fw_chain_conf(IPT_INPUT_ACCESS, opts->config[CONF_IPT_INPUT_ACCESS]) != 1)
        return 0;

    /* The FWKNOP_OUTPUT_ACCESS requires ENABLE_IPT_OUTPUT_ACCESS == Y
    */
    if(get_fw_chain_conf_bool(opts, CONF_ENABLE_IPT_OUTPUT))
        if(set_fw_chain_conf(IPT_OUTPUT_ACCESS, opts->config[CONF_IPT_OUTPUT_ACCESS]) != 1)
            return 0;

#if 0
    /* The remaining access chains require ENABLE_IPT_FORWARDING = Y
    */
    if(get_fw_chain_conf_bool(opts, CONF_ENABLE_IPT_FORWARDING)
            || get_fw_chain_conf_bool(opts, CONF_ENABLE_IPT_LOCAL_NAT))

    {
        if(set_fw_chain_conf(IPT_FORWARD_ACCESS, opts->config[CONF_IPT_FORWARD_ACCESS]) != 1)
            return 0;

        if(set_fw_chain_conf(IPT_DNAT_ACCESS, opts->config[CONF_IPT_DNAT_ACCESS]) != 1)
            return 0;

        /* Requires ENABLE_IPT_SNAT = Y
        */
        if(get_fw_chain_conf_bool(opts, CONF_ENABLE_IPT_SNAT))
        {
            /* Support both SNAT and MASQUERADE - this will be controlled
             * via the access.conf configuration for individual rules
            */
            if(set_fw_chain_conf(IPT_MASQUERADE_ACCESS,
                        opts->config[CONF_IPT_MASQUERADE_ACCESS]) != 1)
                return 0;

            if(set_fw_chain_conf(IPT_SNAT_ACCESS,
                        opts->config[CONF_IPT_SNAT_ACCESS]) != 1)
                return 0;
        }
    }
#endif

    if(get_fw_chain_conf_bool(opts, CONF_ENABLE_DESTINATION_RULE))
    {
        fwc.use_destination = 1;
    }


    if(get_fw_chain_conf_bool(opts, CONF_NFT_IPV4_USE_INET_FAMILY))
    {
        fwc.ipv4_family = "inet";
    }
    else
    {
        fwc.ipv4_family = "ip";
    }

    /* Let us find it via our opts struct as well.
    */
    opts->fw_config = &fwc;

    return 1;
}

static int
chain_create(const fko_srv_options_t * const opts, const char *table, const char *chain)
{
    int rv;
    rv = run_nft_cmd(opts, NULL, "list chain %s %s %s", fwc.ipv4_family, table, chain);
    if (rv == 0) /* chain already exists */
        return 0;
    
    rv = run_nft_cmd(opts, NULL, "create chain %s %s %s", fwc.ipv4_family, table, chain);
    return rv == 0 ? 0 : -1;
}

static void
delete_all_chains(const fko_srv_options_t * const opts)
{
    for(int i=0; i < NUM_FWKNOP_ACCESS_TYPES; i++)
    {
        struct fw_chain *chain = &fwc.chain[i];
        if(chain->target[0] == '\0')
            continue;
        if (chain->handle_jumprule) {
            run_nft_cmd(opts, NULL, "delete rule %s %s %s handle %" JSON_INTEGER_FORMAT,
                fwc.ipv4_family,
                chain->table, chain->from_chain,
                chain->handle_jumprule);
            chain->handle_jumprule = 0;
        }

        run_nft_cmd(opts, NULL, "flush chain %s %s %s", fwc.ipv4_family, chain->table, chain->to_chain);
        run_nft_cmd(opts, NULL, "delete chain %s %s %s", fwc.ipv4_family, chain->table, chain->to_chain);
    }
}

int
fw_initialize(const fko_srv_options_t * const opts)
{
    /* Flush the chains (just in case) so we can start fresh.
    */
    if(strncasecmp(opts->config[CONF_FLUSH_IPT_AT_INIT], "Y", 1) == 0)
        delete_all_chains(opts);

    for(int i=0; i < NUM_FWKNOP_ACCESS_TYPES; i++)
    {
        struct fw_chain *chain = &fwc.chain[i];
        if(chain->target[0] == '\0')
            continue;

        if (chain_create(opts, chain->table, chain->to_chain) != 0)
            return 0;

        json_t *json;
        run_nft_cmd(opts, &json, "insert rule %s %s %s%s counter jump %s",
            fwc.ipv4_family,
            chain->table,
            chain->from_chain,
            get_fw_chain_conf_bool(opts, CONF_NFT_IPV4_USE_INET_FAMILY) ? " meta nfproto ipv4" : "",
            chain->to_chain);

        if (get_inserted_rule_handle(json, &chain->handle_jumprule) == 0)
            log_msg(LOG_DEBUG, "got handle:%" JSON_INTEGER_FORMAT, chain->handle_jumprule);
        else
            log_msg(LOG_ERR, "couldn't get handle for \"jump to chain %s\" rule" JSON_INTEGER_FORMAT, chain->to_chain);
        json_decref(json);
    }

    return 1;
}

int
fw_cleanup(const fko_srv_options_t * const opts)
{
    if(strncasecmp(opts->config[CONF_FLUSH_IPT_AT_EXIT], "N", 1) == 0
            && opts->fw_flush == 0)
        return(0);

    delete_all_chains(opts);

    return(0);
}

static void
chain_rule_added(struct fw_chain *chain, time_t now, time_t exp_ts)
{
    chain->active_rules++;
    if (chain->next_expire < now || exp_ts < chain->next_expire)
        chain->next_expire = exp_ts;
}
static void
chain_rule_removed(struct fw_chain *chain)
{
    if (chain->active_rules > 0)
        chain->active_rules--;
}

static int
rule_exists(const fko_srv_options_t * const opts,
            const char *table, const char *chain,
            const char *saddr, const char *daddr,
            const char *proto, unsigned int dport,
            const char *target_chain)
{
    /* parameter validation */
    if (!table || !chain || !target_chain)
        return -1;
    if (!saddr && !daddr && !proto && !dport)
        return -1;

    /* fetch all rules from chain */
    int rv = 0;
    json_t *json;
    int rc = run_nft_cmd(opts, &json, "list chain %s %s %s", fwc.ipv4_family, table, chain);
    if (rc != 0 || !json)
        return -1;

    json_t *arr = json_object_get(json, "nftables"); /* nftables */
    if (!json_is_array(arr))
        return -1;

    /* iterate over rules */
    size_t index;
    json_t *value;
    json_array_foreach(arr, index, value)
    {
        json_t *rule = json_object_get(value, "rule");
        if (!json_is_object(rule)) continue;

        if (rule_equals(rule, saddr, daddr, proto, dport, target_chain))
        {
            rv = 1;
            break;
        }
    }

    json_decref(json);
    return rv;
}

static void
nft_rule(const fko_srv_options_t * const opts,
         struct fw_chain * const chain,
         int is_prepend,
         spa_data_t * const spadat,
         acc_port_list_t *ple,
         time_t          now, 
         unsigned int    exp_ts)
{
    int rule_already_exists = rule_exists(opts,
                                chain->table, chain->to_chain,
                                spadat->use_src_ip,
                                fwc.use_destination ? spadat->pkt_destination_ip : IPT_ANY_IP,
                                proto_str(ple->proto), ple->port,
                                chain->target);
    if (rule_already_exists)
    {
        log_msg(LOG_DEBUG, "rule already exists in %s -- not adding", chain->to_chain);
        return;
    }

    (void)run_nft_cmd(opts, NULL, "%s rule %s %s %s ip saddr %s ip daddr %s %s dport %i %s %s comment \"%s%u\"",
        is_prepend ? "insert" : "add",
        fwc.ipv4_family,
        chain->table, chain->to_chain,
        spadat->use_src_ip, fwc.use_destination ? spadat->pkt_destination_ip : IPT_ANY_IP,
        proto_str(ple->proto), ple->port,
        strncasecmp(chain->target, "accept", 6) == 0 ? "counter" : "jump",
        chain->target,
        EXPIRE_COMMENT_PREFIX, exp_ts
    );

    chain_rule_added(chain, now, exp_ts);
}

/* Rule Processing - Create an access request...
*/
int
process_spa_request(const fko_srv_options_t * const opts,
        const acc_stanza_t * const acc, spa_data_t * const spadat)
{
    struct fw_chain * const in_chain   = &(opts->fw_config->chain[IPT_INPUT_ACCESS]);

    acc_port_list_t *port_list = NULL;
    acc_port_list_t *ple = NULL;

    int             res = 0;
    time_t          now;
    unsigned int    exp_ts;

    /* Parse and expand our access message.
    */
    if(expand_acc_port_list(&port_list, spadat->spa_message_remain) != 1)
    {
        /* technically we would already have exited with an error if there were
         * any memory allocation errors (see the add_port_list() function), but
         * for completeness...
        */
        free_acc_port_list(port_list);
        return res;
    }

    /* Start at the top of the proto-port list...
    */
    ple = port_list;

    /* Remember the first proto/port combo in case we need them
     * for NAT access requests.
    */
#if 0
    unsigned int    fst_proto = ple->proto;
    unsigned int    fst_port  = ple->port;
#endif

    /* Set our expire time value.
    */
    time(&now);
    exp_ts = now + spadat->fw_access_timeout;

    if(spadat->message_type == FKO_LOCAL_NAT_ACCESS_MSG
      || spadat->message_type == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG
      || spadat->message_type == FKO_NAT_ACCESS_MSG
      || spadat->message_type == FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG
      || acc->force_nat)
    {
#if 0
        char            nat_ip[MAX_IPV4_STR_LEN] = {0};
        char            nat_dst[MAX_HOSTNAME_LEN] = {0};
        struct fw_chain * const fwd_chain  = &(opts->fw_config->chain[IPT_FORWARD_ACCESS]);
        struct fw_chain * const dnat_chain = &(opts->fw_config->chain[IPT_DNAT_ACCESS]);
        unsigned int    nat_port = 0;
#endif
        log_msg(LOG_ERR, "%s: NAT handling not yet implemented!", __func__);
    }
    else /* Non-NAT request - this is the typical case. */
    {
        struct fw_chain * const out_chain  = &(opts->fw_config->chain[IPT_OUTPUT_ACCESS]);
        int is_prepend = (get_fw_chain_conf_bool(opts, CONF_ENABLE_RULE_PREPEND));

        /* Create an access command for each proto/port for the source ip.
        */
        for (; ple != NULL; ple = ple->next)
        {
            nft_rule(opts, in_chain, is_prepend, spadat, ple, now, exp_ts);

            if(strlen(out_chain->to_chain))
            {
                nft_rule(opts, out_chain, is_prepend, spadat, ple, now, exp_ts);
            }
        }
    }

    /* Done with the port list for access rules.
    */
    free_acc_port_list(port_list);

    return 0;
}

static void
rm_expired_rules(const fko_srv_options_t * const opts,
        struct fw_chain *ch, time_t now)
{
    time_t      min_exp = 0;

    json_t *json;
    if (run_nft_cmd(opts, &json, "list chain %s %s %s", fwc.ipv4_family, ch->table, ch->to_chain) != 0)
    {
        log_msg(LOG_ERR, "%s: failed to list rules", __func__);
        return;
    }

    json_t *arr = json_object_get(json, "nftables"); /* nftables */
    if (json_is_array(arr))
    {
        size_t index;
        json_t *value;
        json_array_foreach(arr, index, value)
        {
            json_t *rule = json_object_get(value, "rule");
            if (!json_is_object(rule)) continue;

            json_t *comment_j = json_object_get(rule, "comment");
            if (!json_is_string(comment_j))
                continue;
            const char *comment = json_string_value(comment_j);
            char dummy_ch;
            unsigned int exp_ts;
            if (sscanf(comment, EXPIRE_COMMENT_PREFIX "%u%c", &exp_ts, &dummy_ch) != 1)
            {
                printf("was unable to parse rule\n");
                continue;
            }
            log_msg(LOG_DEBUG, "found exp_ts: %u (now:%lu)", exp_ts, now);
            if (exp_ts <= now)
            {
                json_int_t handle;
                if (json_integer_field_get(rule, "handle", &handle) != 0)
                {
                    log_msg(LOG_ERR, "couldn't get handle for rule");
                    continue;
                }
                if (run_nft_cmd(opts, NULL, "delete rule %s %s %s handle %" JSON_INTEGER_FORMAT, fwc.ipv4_family, ch->table, ch->to_chain, handle) != 0)
                {
                    log_msg(LOG_ERR, "was unable to delete rule -- handle:%" JSON_INTEGER_FORMAT, handle);
                }
                else
                {
                    log_msg(LOG_DEBUG, "deleted rule -- handle:%" JSON_INTEGER_FORMAT, handle);
                    chain_rule_removed(ch);
                }
            }
            else
            {
                if (min_exp == 0 || exp_ts < min_exp)
                    min_exp = exp_ts;
            }
        }
    }

    json_decref(json);

    /* Set the next pending expire time accordingly. 0 if there are no
     * more rules, or whatever the next expected (min_exp) time will be.
    */
    if(ch->active_rules < 1)
        ch->next_expire = 0;
    else if(min_exp)
        ch->next_expire = min_exp;
}

/* Iterate over the configure firewall access chains and purge expired
 * firewall rules.
*/
void
check_firewall_rules(const fko_srv_options_t * const opts,
        const int chk_rm_all)
{
    log_msg(LOG_DEBUG, "%s -- rm_all:%d", __func__, chk_rm_all);

    time_t          now;
    time(&now);
    for(int i=0; i < NUM_FWKNOP_ACCESS_TYPES; i++)
    {
        struct fw_chain *chain = &(opts->fw_config->chain[i]);

        /* If there are no active rules or we have not yet
         * reached our expected next expire time, continue.
        */
        if(!chk_rm_all && (chain->active_rules == 0 || chain->next_expire > now))
            continue;

        if(chain->table[0] == '\0' || chain->to_chain[i] == '\0')
            continue;

        rm_expired_rules(opts, chain, now);
    }

}

int
validate_ipt_chain_conf(const char * const chain_str)
{
    int         j, rv  = 1;
    const char   *ndx  = chain_str;

    j = 1;
    while(*ndx != '\0')
    {
        if(*ndx == ',')
            j++;

        if(*ndx != '\0'
                && *ndx != ' '
                && *ndx != ','
                && *ndx != '_'
                && isalnum(*ndx) == 0)
        {
            rv = 0;
            break;
        }
        ndx++;
    }

    /* Sanity check - j should be the number of chain fields
     * (excluding the type).
    */
    if(j != FW_NUM_CHAIN_FIELDS)
        rv = 0;

    return rv;
}

#endif /* FIREWALL_NFTABLES */

/***EOF***/
