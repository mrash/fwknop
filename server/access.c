/*
 ******************************************************************************
 *
 * File:    access.c
 *
 * Author:  Damien Stuart
 *
 * Purpose: Access.conf file processing for fwknop server.
 *
 * Copyright 2010 Damien Stuart (dstuart@dstuart.org)
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
#include <sys/stat.h>

#if HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
#endif

#include "fwknopd_common.h"
#include <arpa/inet.h>
#include "pwd.h"
#include "access.h"
#include "utils.h"
#include "log_msg.h"

/* Add an access string entry
*/
static void
add_acc_string(char **var, const char *val)
{
    if((*var = strdup(val)) == NULL)
    {
        log_msg(LOG_ERR,
            "Fatal memory allocation error adding access list entry: %s", var
        );
        exit(EXIT_FAILURE);
    }
}

/* Add an access int entry
*/
static int
add_acc_int(int *var, const char *val)
{
    return(*var = atoi(val));
}

/* Add an access bool entry (unsigned char of 1 or 0)
*/
static unsigned char
add_acc_bool(unsigned char *var, const char *val)
{
    return(*var = (strncasecmp(val, "Y", 1) == 0) ? 1 : 0);
}

/* Add expiration time - convert date to epoch seconds
*/
static void
add_acc_expire_time(fko_srv_options_t *opts, time_t *access_expire_time, const char *val)
{
    struct tm tm;

    memset(&tm, 0, sizeof(struct tm));

    if (sscanf(val, "%2d/%2d/%4d", &tm.tm_mon, &tm.tm_mday, &tm.tm_year) != 3)
    {

        log_msg(LOG_ERR,
            "Fatal: invalid date value '%s' (need MM/DD/YYYY) for access stanza expiration time",
            val
        );
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    if(tm.tm_mon > 0)
        tm.tm_mon -= 1;  /* 0-11 */

    /* number of years since 1900
    */
    if(tm.tm_year > 1900)
        tm.tm_year -= 1900;
    else
        if(tm.tm_year < 100)
            tm.tm_year += 100;

    *access_expire_time = mktime(&tm);

    return;
}

/* Add expiration time via epoch seconds defined in access.conf
*/
static void
add_acc_expire_time_epoch(fko_srv_options_t *opts, time_t *access_expire_time, const char *val)
{
    char *endptr;
    unsigned long expire_time = 0;

    errno = 0;

    expire_time = (time_t) strtoul(val, &endptr, 10);

    if (errno == ERANGE || (errno != 0 && expire_time == 0))
    {
        log_msg(LOG_ERR,
            "Fatal: invalid epoch seconds value '%s' for access stanza expiration time",
            val
        );
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    *access_expire_time = (time_t) expire_time;

    return;
}

/* Convert an encryption_mode string to its integer value.
*/
static int
enc_mode_strtoint(const char *enc_mode_str)
{
    if(strcasecmp(enc_mode_str, "cbc") == 0)
        return(FKO_ENC_MODE_CBC);
    else if(strcasecmp(enc_mode_str, "ecb") == 0)
        return(FKO_ENC_MODE_ECB);
    else if(strcasecmp(enc_mode_str, "cfb") == 0)
        return(FKO_ENC_MODE_CFB);
    else if(strcasecmp(enc_mode_str, "pcbc") == 0)
        return(-1);  /* not supported yet */
    else if(strcasecmp(enc_mode_str, "ofb") == 0)
        return(FKO_ENC_MODE_OFB);
    else if(strcasecmp(enc_mode_str, "ctr") == 0)
        return(FKO_ENC_MODE_CTR);
    else
        return(-1);
}

#if FIREWALL_IPTABLES
static void
add_acc_force_nat(fko_srv_options_t *opts, acc_stanza_t *curr_acc, const char *val)
{
    char      ip_str[MAX_IPV4_STR_LEN] = {0};

    if (sscanf(val, "%15s %5u", ip_str, &curr_acc->force_nat_port) != 2)
    {

        log_msg(LOG_ERR,
            "Fatal: invalid FORCE_NAT arg '%s', need <IP> <PORT>",
            val
        );
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    if (curr_acc->force_nat_port > MAX_PORT)
    {
        log_msg(LOG_ERR,
            "Fatal: invalid FORCE_NAT port '%d'", curr_acc->force_nat_port);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    curr_acc->force_nat = 1;
    add_acc_string(&(curr_acc->force_nat_ip), ip_str);

    return;
}
#endif

/* Take an IP or Subnet/Mask and convert it to mask for later
 * comparisons of incoming source IPs against this mask.
*/
static void
add_source_mask(acc_stanza_t *acc, const char *ip)
{
    char                *ndx;
    char                ip_str[MAX_IPV4_STR_LEN] = {0};
    uint32_t            mask;

    struct in_addr      in;

    acc_int_list_t      *last_sle, *new_sle, *tmp_sle;

    if((new_sle = calloc(1, sizeof(acc_int_list_t))) == NULL)
    {
        log_msg(LOG_ERR,
            "Fatal memory allocation error adding stanza source_list entry"
        );
        exit(EXIT_FAILURE);
    }

    /* If this is not the first entry, we walk our pointer to the
     * end of the list.
    */
    if(acc->source_list == NULL)
    {
        acc->source_list = new_sle;
    }
    else
    {
        tmp_sle = acc->source_list;

        do {
            last_sle = tmp_sle;
        } while((tmp_sle = tmp_sle->next));

        last_sle->next = new_sle;
    }

    /* Convert the IP data into the appropriate mask
    */
    if(strcasecmp(ip, "ANY") == 0)
    {
        new_sle->maddr = 0x0;
        new_sle->mask = 0x0;
    }
    else
    {
        /* See if we have a subnet component.  If so pull out the IP and
         * mask values, then create the final mask value.
        */
        if((ndx = strchr(ip, '/')) != NULL)
        {
            mask = atoi(ndx+1);
            strlcpy(ip_str, ip, (ndx-ip)+1);
        }
        else
        {
            mask = 32;
            strlcpy(ip_str, ip, strlen(ip)+1);
        }

        if(inet_aton(ip_str, &in) == 0)
        {
            log_msg(LOG_ERR,
                "Error parsing IP to int for: %s", ip_str
            );

            free(new_sle);
            new_sle = NULL;

            return;
        }

        /* Store our mask converted from CIDR to a 32-bit value.
        */
        new_sle->mask  = (0xFFFFFFFF << (32 - mask));

        /* Store our masked address for comparisons with future incoming
         * packets.
        */
        new_sle->maddr = ntohl(in.s_addr) & new_sle->mask;
    }
}

/* Expand the access SOURCE string to a list of masks.
*/
void
expand_acc_source(acc_stanza_t *acc)
{
    char           *ndx, *start;
    char            buf[32];

    start = acc->source;

    for(ndx = start; *ndx; ndx++)
    {
        if(*ndx == ',')
        {
            /* Skip over any leading whitespace.
            */
            while(isspace(*start))
                start++;

            strlcpy(buf, start, (ndx-start)+1);
            add_source_mask(acc, buf);
            start = ndx+1;
        }
    }

    /* Skip over any leading whitespace (once again for the last in the list).
    */
    while(isspace(*start))
        start++;

    strlcpy(buf, start, (ndx-start)+1);
    add_source_mask(acc, buf);
}

static int
parse_proto_and_port(char *pstr, int *proto, int *port)
{
    char    *ndx;
    char    proto_str[32];

    /* Parse the string into its components.
    */
    if((ndx = strchr(pstr, '/')) == NULL)
    {
        log_msg(LOG_ERR,
            "Parse error on access port entry: %s", pstr);

        return(-1);
    }

    strlcpy(proto_str, pstr,  (ndx - pstr)+1);

    *port = atoi(ndx+1);

    if(strcasecmp(proto_str, "tcp") == 0)
        *proto = PROTO_TCP;
    else if(strcasecmp(proto_str, "udp") == 0)
        *proto = PROTO_UDP;
    else
    {
        log_msg(LOG_ERR,
            "Invalid protocol in access port entry: %s", pstr);

        return(-1);
    }

    return(0);
}

/* Take a proto/port string and convert it to appropriate integer values
 * for comparisons of incoming SPA requests.
*/
static void
add_port_list_ent(acc_port_list_t **plist, char *port_str)
{
    int                 proto_int, port;

    acc_port_list_t     *last_plist, *new_plist, *tmp_plist;

    /* Parse the string into its components and continue only if there
     * are no problems with the incoming string.
    */
    if(parse_proto_and_port(port_str, &proto_int, &port) != 0)
        return;

    if((new_plist = calloc(1, sizeof(acc_port_list_t))) == NULL)
    {
        log_msg(LOG_ERR,
            "Fatal memory allocation error adding stanza source_list entry"
        );
        exit(EXIT_FAILURE);
    }

    /* If this is not the first entry, we walk our pointer to the
     * end of the list.
    */
    if(*plist == NULL)
    {
        *plist = new_plist;
    }
    else
    {
        tmp_plist = *plist;

        do {
            last_plist = tmp_plist;
        } while((tmp_plist = tmp_plist->next));

        last_plist->next = new_plist;
    }

    new_plist->proto = proto_int;
    new_plist->port  = port;
}

/* Add a string list entry to the given acc_string_list.
*/
static void
add_string_list_ent(acc_string_list_t **stlist, const char *str_str)
{
    acc_string_list_t   *last_stlist, *new_stlist, *tmp_stlist;

    if((new_stlist = calloc(1, sizeof(acc_string_list_t))) == NULL)
    {
        log_msg(LOG_ERR,
            "Fatal memory allocation error creating string list entry"
        );
        exit(EXIT_FAILURE);
    }

    /* If this is not the first entry, we walk our pointer to the
     * end of the list.
    */
    if(*stlist == NULL)
    {
        *stlist = new_stlist;
    }
    else
    {
        tmp_stlist = *stlist;

        do {
            last_stlist = tmp_stlist;
        } while((tmp_stlist = tmp_stlist->next));

        last_stlist->next = new_stlist;
    }

    new_stlist->str = strdup(str_str);

    if(new_stlist->str == NULL)
    {
        log_msg(LOG_ERR,
            "Fatal memory allocation error adding string list entry item"
        );
        exit(EXIT_FAILURE);
    }

}

/* Expand a proto/port access string to a list of access proto-port struct.
*/
void
expand_acc_port_list(acc_port_list_t **plist, char *plist_str)
{
    char           *ndx, *start;
    char            buf[32];

    start = plist_str;

    for(ndx = start; *ndx; ndx++)
    {
        if(*ndx == ',')
        {
            /* Skip over any leading whitespace.
            */
            while(isspace(*start))
                start++;

            strlcpy(buf, start, (ndx-start)+1);
            add_port_list_ent(plist, buf);
            start = ndx+1;
        }
    }

    /* Skip over any leading whitespace (once again for the last in the list).
    */
    while(isspace(*start))
        start++;

    strlcpy(buf, start, (ndx-start)+1);

    add_port_list_ent(plist, buf);
}

/* Expand a comma-separated string into a simple acc_string_list.
*/
static void
expand_acc_string_list(acc_string_list_t **stlist, char *stlist_str)
{
    char           *ndx, *start;
    char            buf[1024];

    start = stlist_str;

    for(ndx = start; *ndx; ndx++)
    {
        if(*ndx == ',')
        {
            /* Skip over any leading whitespace.
            */
            while(isspace(*start))
                start++;

            strlcpy(buf, start, (ndx-start)+1);
            add_string_list_ent(stlist, buf);
            start = ndx+1;
        }
    }

    /* Skip over any leading whitespace (once again for the last in the list).
    */
    while(isspace(*start))
        start++;

    strlcpy(buf, start, (ndx-start)+1);

    add_string_list_ent(stlist, buf);
}

/* Free the acc source_list
*/
static void
free_acc_source_list(acc_int_list_t *sle)
{
    acc_int_list_t    *last_sle;

    while(sle != NULL)
    {
        last_sle = sle;
        sle = last_sle->next;

        free(last_sle);
    }
}

/* Free a port_list
*/
void
free_acc_port_list(acc_port_list_t *ple)
{
    acc_port_list_t    *last_ple;

    while(ple != NULL)
    {
        last_ple = ple;
        ple = last_ple->next;

        free(last_ple);
    }
}

/* Free a string_list
*/
static void
free_acc_string_list(acc_string_list_t *stl)
{
    acc_string_list_t    *last_stl;

    while(stl != NULL)
    {
        last_stl = stl;
        stl = last_stl->next;

        free(last_stl->str);
        free(last_stl);
    }
}

/* Free any allocated content of an access stanza.
 *
 * NOTE: If a new access.conf parameter is created, and it is a string
 *       value, it also needs to be added to the list of items to check
 *       and free below.
*/
static void
free_acc_stanza_data(acc_stanza_t *acc)
{

    if(acc->source != NULL)
    {
        free(acc->source);
        free_acc_source_list(acc->source_list);
    }

    if(acc->open_ports != NULL)
    {
        free(acc->open_ports);
        free_acc_port_list(acc->oport_list);
    }

    if(acc->restrict_ports != NULL)
    {
        free(acc->restrict_ports);
        free_acc_port_list(acc->rport_list);
    }

    if(acc->force_nat_ip != NULL)
        free(acc->force_nat_ip);

    if(acc->key != NULL)
        free(acc->key);

    if(acc->cmd_exec_user != NULL)
        free(acc->cmd_exec_user);

    if(acc->require_username != NULL)
        free(acc->require_username);

    if(acc->gpg_home_dir != NULL)
        free(acc->gpg_home_dir);

    if(acc->gpg_decrypt_id != NULL)
        free(acc->gpg_decrypt_id);

    if(acc->gpg_decrypt_pw != NULL)
        free(acc->gpg_decrypt_pw);

    if(acc->gpg_remote_id != NULL)
    {
        free(acc->gpg_remote_id);
        free_acc_string_list(acc->gpg_remote_id_list);
    }
}

/* Expand any access entries that may be multi-value.
*/
static void
expand_acc_ent_lists(fko_srv_options_t *opts)
{
    acc_stanza_t   *acc = opts->acc_stanzas;

    /* We need to do this for each stanza.
    */
    while(acc)
    {
        /* Expand the source string to 32-bit integer masks foreach entry.
        */
        expand_acc_source(acc);

        /* Now expand the open_ports string.
        */
        if(acc->open_ports != NULL && strlen(acc->open_ports))
            expand_acc_port_list(&(acc->oport_list), acc->open_ports);

        if(acc->restrict_ports != NULL && strlen(acc->restrict_ports))
            expand_acc_port_list(&(acc->rport_list), acc->restrict_ports);

        /* Expand the GPG_REMOTE_ID string.
        */
        if(acc->gpg_remote_id != NULL && strlen(acc->gpg_remote_id))
            expand_acc_string_list(&(acc->gpg_remote_id_list), acc->gpg_remote_id);

        acc = acc->next;
    }
}

void
free_acc_stanzas(fko_srv_options_t *opts)
{
    acc_stanza_t    *acc, *last_acc;

    /* Free any resources first (in case of reconfig). Assume non-NULL
     * entry needs to be freed.
    */
    acc = opts->acc_stanzas;

    while(acc != NULL)
    {
        last_acc = acc;
        acc = last_acc->next;

        free_acc_stanza_data(last_acc);
        free(last_acc);
    }

    return;
}

/* Wrapper for free_acc_stanzas(), we may put additional initialization
 * code here.
*/
static void
acc_stanza_init(fko_srv_options_t *opts)
{
    /* Free any resources first (in case of reconfig). Assume non-NULL
     * entry needs to be freed.
    */
    free_acc_stanzas(opts);

    return;
}

/* Add a new stanza bay allocating the required memory at the required
 * location, yada-yada-yada.
*/
static acc_stanza_t*
acc_stanza_add(fko_srv_options_t *opts)
{
    acc_stanza_t    *acc     = opts->acc_stanzas;
    acc_stanza_t    *new_acc = calloc(1, sizeof(acc_stanza_t));
    acc_stanza_t    *last_acc;

    if(new_acc == NULL)
    {
        log_msg(LOG_ERR,
            "Fatal memory allocation error adding access stanza"
        );
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* If this is not the first acc entry, we walk our acc pointer to the
     * end of the existing list.
    */
    if(acc == NULL)
    {
        opts->acc_stanzas = new_acc;
    }
    else
    {
        do {
            last_acc = acc;
        } while((acc = acc->next));

        last_acc->next = new_acc;
    }

    return(new_acc);
}

/* Scan the access options for entries that have not bees set, but need
 * a default value.
*/
static void
set_acc_defaults(fko_srv_options_t *opts)
{
    acc_stanza_t    *acc = opts->acc_stanzas;

    if(!acc)
        return;

    while(acc)
    {
        /* set default fw_access_timeout if necessary
        */
        if(acc->fw_access_timeout < 1)
            acc->fw_access_timeout = DEF_FW_ACCESS_TIMEOUT;

        /* set default gpg keyring path if necessary
        */
        if(acc->gpg_decrypt_pw != NULL)
        {
            acc->encryption_mode = FKO_ENC_MODE_ASYMMETRIC;
            if(acc->gpg_home_dir == NULL)
                add_acc_string(&(acc->gpg_home_dir), opts->config[CONF_GPG_HOME_DIR]);
        }

        if (acc->encryption_mode == FKO_ENC_MODE_UNKNOWN)
            acc->encryption_mode = FKO_DEFAULT_ENC_MODE;

        acc = acc->next;
    }
}

/* Perform some sanity checks on an acc stanza data.
*/
static int
acc_data_is_valid(const acc_stanza_t *acc)
{
    if((acc->key == NULL || !strlen(acc->key))
      && (acc->gpg_decrypt_pw == NULL || !strlen(acc->gpg_decrypt_pw)))
    {
        fprintf(stderr,
            "[*] No keys found for access stanza source: '%s'\n", acc->source
        );
        return(0);
    }

    return(1);
}

/* Read and parse the access file, popluating the access data as we go.
*/
void
parse_access_file(fko_srv_options_t *opts)
{
    FILE           *file_ptr;
    char           *ndx;
    int             got_source = 0;
    unsigned int    num_lines = 0;

    char            access_line_buf[MAX_LINE_LEN] = {0};
    char            var[MAX_LINE_LEN]  = {0};
    char            val[MAX_LINE_LEN]  = {0};

    struct passwd  *pw;
    struct stat     st;

    acc_stanza_t   *curr_acc = NULL;

    /* First see if the access file exists.  If it doesn't, complain
     * and bail.
    */
    if(stat(opts->config[CONF_ACCESS_FILE], &st) != 0)
    {
        fprintf(stderr, "[*] Access file: '%s' was not found.\n",
            opts->config[CONF_ACCESS_FILE]);

        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    if ((file_ptr = fopen(opts->config[CONF_ACCESS_FILE], "r")) == NULL)
    {
        fprintf(stderr, "[*] Could not open access file: %s\n",
            opts->config[CONF_ACCESS_FILE]);
        perror(NULL);

        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* Initialize the access list.
    */
    acc_stanza_init(opts);

    /* Now walk through access file pulling the access entries into the
     * current stanza.
    */
    while ((fgets(access_line_buf, MAX_LINE_LEN, file_ptr)) != NULL)
    {
        num_lines++;
        access_line_buf[MAX_LINE_LEN-1] = '\0';

        /* Get past comments and empty lines (note: we only look at the
         * first character.
        */
        if(IS_EMPTY_LINE(access_line_buf[0]))
            continue;

        if(sscanf(access_line_buf, "%s %[^;\n\r]", var, val) != 2)
        {
            fprintf(stderr,
                "*Invalid access file entry in %s at line %i.\n - '%s'",
                opts->config[CONF_ACCESS_FILE], num_lines, access_line_buf
            );
            continue;
        }

        /* Remove any colon that may be on the end of the var
        */
        if((ndx = strrchr(var, ':')) != NULL)
            *ndx = '\0';

        /*
        */
        if(opts->verbose > 3)
            fprintf(stderr,
                "ACCESS FILE: %s, LINE: %s\tVar: %s, Val: '%s'\n",
                opts->config[CONF_ACCESS_FILE], access_line_buf, var, val
            );

        /* Process the entry.
         *
         * NOTE: If a new access.conf parameter is created.  It also needs
         *       to be accounted for in the following if/if else construct.
        */

        if(CONF_VAR_IS(var, "SOURCE"))
        {
            /* If this is not the first stanza, sanity check the previous
             * stanza for the minimum required data.
            */
            if(curr_acc != NULL) {
                if(!acc_data_is_valid(curr_acc))
                {
                    fprintf(stderr,
                        "[*] Data error in access file: '%s'\n",
                        opts->config[CONF_ACCESS_FILE]);
                    clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
                }
            }

            /* Start new stanza.
            */
            curr_acc = acc_stanza_add(opts);

            add_acc_string(&(curr_acc->source), val);

            got_source++;
        }
        else if (curr_acc == NULL)
        {
            /* The stanza must start with the "SOURCE" variable
            */
            continue;
        }
        else if(CONF_VAR_IS(var, "OPEN_PORTS"))
        {
            add_acc_string(&(curr_acc->open_ports), val);
        }
        else if(CONF_VAR_IS(var, "RESTRICT_PORTS"))
        {
            add_acc_string(&(curr_acc->restrict_ports), val);
        }
        else if(CONF_VAR_IS(var, "KEY"))
        {
            if(strcasecmp(val, "__CHANGEME__") == 0)
            {
                fprintf(stderr,
                    "[*] KEY value is not properly set in stanza source '%s' in access file: '%s'\n",
                    curr_acc->source, opts->config[CONF_ACCESS_FILE]);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
            add_acc_string(&(curr_acc->key), val);
        }
        else if(CONF_VAR_IS(var, "FW_ACCESS_TIMEOUT"))
        {
            add_acc_int(&(curr_acc->fw_access_timeout), val);
        }
        else if(CONF_VAR_IS(var, "ENCRYPTION_MODE"))
        {
            if((curr_acc->encryption_mode = enc_mode_strtoint(val)) < 0)
            {
                fprintf(stderr,
                    "[*] Unrecognized ENCRYPTION_MODE '%s', use {cbc,ecb}\n",
                    val);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }
        else if(CONF_VAR_IS(var, "ENABLE_CMD_EXEC"))
        {
            add_acc_bool(&(curr_acc->enable_cmd_exec), val);
        }
        else if(CONF_VAR_IS(var, "CMD_EXEC_USER"))
        {
            add_acc_string(&(curr_acc->cmd_exec_user), val);

            errno = 0;
            pw = getpwnam(val);

            if(pw == NULL)
            {
                fprintf(stderr, "Unable to determine UID for CMD_EXEC_USER: %s.\n",
                    errno ? strerror(errno) : "Not a user on this system");
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }

            curr_acc->cmd_exec_uid = pw->pw_uid;
        }
        else if(CONF_VAR_IS(var, "REQUIRE_USERNAME"))
        {
            add_acc_string(&(curr_acc->require_username), val);
        }
        else if(CONF_VAR_IS(var, "REQUIRE_SOURCE_ADDRESS"))
        {
            add_acc_bool(&(curr_acc->require_source_address), val);
        }
        else if(CONF_VAR_IS(var, "REQUIRE_SOURCE"))  /* synonym for REQUIRE_SOURCE_ADDRESS */
        {
            add_acc_bool(&(curr_acc->require_source_address), val);
        }
        else if(CONF_VAR_IS(var, "GPG_HOME_DIR"))
        {
            if (is_valid_dir(val))
            {
                add_acc_string(&(curr_acc->gpg_home_dir), val);
            }
            else
            {
                fprintf(stderr,
                    "[*] GPG_HOME_DIR directory '%s' stat()/existence problem in stanza source '%s' in access file: '%s'\n",
                    val, curr_acc->source, opts->config[CONF_ACCESS_FILE]);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }
        else if(CONF_VAR_IS(var, "GPG_DECRYPT_ID"))
        {
            add_acc_string(&(curr_acc->gpg_decrypt_id), val);
        }
        else if(CONF_VAR_IS(var, "GPG_DECRYPT_PW"))
        {
            if(strcasecmp(val, "__CHANGEME__") == 0)
            {
                fprintf(stderr,
                    "[*] GPG_DECRYPT_PW value is not properly set in stanza source '%s' in access file: '%s'\n",
                    curr_acc->source, opts->config[CONF_ACCESS_FILE]);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
            add_acc_string(&(curr_acc->gpg_decrypt_pw), val);
        }
        else if(CONF_VAR_IS(var, "GPG_REQUIRE_SIG"))
        {
            add_acc_bool(&(curr_acc->gpg_require_sig), val);
        }
        else if(CONF_VAR_IS(var, "GPG_IGNORE_SIG_VERIFY_ERROR"))
        {
            add_acc_bool(&(curr_acc->gpg_ignore_sig_error), val);
        }
        else if(CONF_VAR_IS(var, "GPG_REMOTE_ID"))
        {
            add_acc_string(&(curr_acc->gpg_remote_id), val);
        }
        else if(CONF_VAR_IS(var, "ACCESS_EXPIRE"))
        {
            add_acc_expire_time(opts, &(curr_acc->access_expire_time), val);
        }
        else if(CONF_VAR_IS(var, "ACCESS_EXPIRE_EPOCH"))
        {
            add_acc_expire_time_epoch(opts, &(curr_acc->access_expire_time), val);
        }
        else if(CONF_VAR_IS(var, "FORCE_NAT"))
        {
#if FIREWALL_IPTABLES
            if(strncasecmp(opts->config[CONF_ENABLE_IPT_FORWARDING], "Y", 1) !=0 )
            {
                fprintf(stderr,
                    "[*] FORCE_NAT requires ENABLE_IPT_FORWARDING to be enabled in fwknopd.conf\n");
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
            add_acc_force_nat(opts, curr_acc, val);
#else
            fprintf(stderr,
                "[*] FORCE_NAT not supported.\n");
            clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
#endif
        }
        else
        {
            fprintf(stderr,
                "*Ignoring unknown access parameter: '%s' in %s\n",
                var, opts->config[CONF_ACCESS_FILE]
            );
        }
    }

    fclose(file_ptr);

    /* Basic check to ensure that we got at least one SOURCE stanza with
     * a valid KEY defined (valid meaning it has a value that is not
     * "__CHANGEME__".
    */
    if (got_source == 0)
    {
        fprintf(stderr,
            "[*] Could not find valid SOURCE stanza in access file: '%s'\n",
            opts->config[CONF_ACCESS_FILE]);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* Sanity check the last stanza
    */
    if(!acc_data_is_valid(curr_acc))
    {
        fprintf(stderr,
            "[*] Data error in access file: '%s'\n",
            opts->config[CONF_ACCESS_FILE]);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* Expand our the expandable fields into their respective data buckets.
    */

    expand_acc_ent_lists(opts);

    /* Make sure default values are set where needed.
    */
    set_acc_defaults(opts);

    return;
}

int
compare_addr_list(acc_int_list_t *source_list, const uint32_t ip)
{
    int match = 0;

    while(source_list)
    {
        if((ip & source_list->mask) == (source_list->maddr & source_list->mask))
        {
            match = 1;
            break;
        }

        source_list = source_list->next;
    }

    return(match);
}

/* Compare the contents of 2 port lists.  Return true on a match.
 * Match depends on the match_any flag.  if match_any is 1 then any
 * entry in the incoming data need only match one item to return true.
 * Otherwise all entries in the incoming data must have a corresponding
 * match in the access port_list.
*/
static int
compare_port_list(acc_port_list_t *in, acc_port_list_t *ac, const int match_any)
{
    int a_cnt = 0;
    int i_cnt = 0;

    acc_port_list_t *tlist;
    while(in)
    {
        i_cnt++;

        tlist = ac;
        while(tlist)
        {
            if(in->proto == tlist->proto && in->port == tlist->port)
            {
                a_cnt++;
                if(match_any == 1)
                    return(1);
            }
            tlist = tlist->next;
        }
        in = in->next;
    }

    return(i_cnt == a_cnt);
}

/* Take a proto/port string (or mulitple comma-separated strings) and check
 * them against the list for the given access stanza.
 *
 * Return 1 if we are allowed
*/
int
acc_check_port_access(acc_stanza_t *acc, char *port_str)
{
    int             res     = 1;

    char            buf[32];
    char           *ndx, *start;

    acc_port_list_t *o_pl   = acc->oport_list;
    acc_port_list_t *r_pl   = acc->rport_list;

    acc_port_list_t *in_pl  = NULL;

    start = port_str;

    /* Create our own internal port_list from the incoming SPA data
     * for comparison.
    */
    for(ndx = start; *ndx; ndx++)
    {
        if(*ndx == ',')
        {
            strlcpy(buf, start, (ndx-start)+1);
            add_port_list_ent(&in_pl, buf);
            start = ndx+1;
        }
    }
    strlcpy(buf, start, (ndx-start)+1);
    add_port_list_ent(&in_pl, buf);

    if(in_pl == NULL)
    {
        log_msg(LOG_ERR,
            "Unable to create acc_port_list from incoming data: %s", port_str
        );
        return(0);
    }

    /* Start with restricted ports (if any).  Any match (even if only one
     * entry) means not allowed.
    */
    if((acc->rport_list != NULL) && (compare_port_list(in_pl, r_pl, 1)))
    {
        res = 0;
        goto cleanup_and_bail;
    }

    /* For open port list, all must match.
    */
    if((acc->oport_list != NULL) && (!compare_port_list(in_pl, o_pl, 0)))
            res = 0;

cleanup_and_bail:
    free_acc_port_list(in_pl);
    return(res);
}

/* Take a GPG ID string and check it against the list of allowed
 * GPG_REMOTE_ID's.
 *
 * Return 1 if we are allowed
*/
int
acc_check_gpg_remote_id(acc_stanza_t *acc, const char *gpg_id)
{
    acc_string_list_t *ndx;

    for(ndx = acc->gpg_remote_id_list; ndx != NULL; ndx=ndx->next)
        if(strcasecmp(ndx->str, gpg_id) == 0)
            return(1);

    return(0);
}

/* Dump the configuration
*/
void
dump_access_list(const fko_srv_options_t *opts)
{
    int             i = 0;

    acc_stanza_t    *acc = opts->acc_stanzas;

    fprintf(stdout, "Current fwknopd access settings:\n");

    if(!acc)
    {
        fprintf(stderr, "\n    ** No Access Settings Defined **\n\n");
        return;
    }

    while(acc)
    {
        fprintf(stdout,
            "SOURCE (%i):  %s\n"
            "==============================================================\n"
            "                 OPEN_PORTS:  %s\n"
            "             RESTRICT_PORTS:  %s\n"
            "                        KEY:  <see the access.conf file>\n"
            "          FW_ACCESS_TIMEOUT:  %i\n"
            "            ENABLE_CMD_EXEC:  %s\n"
            "              CMD_EXEC_USER:  %s\n"
            "           REQUIRE_USERNAME:  %s\n"
            "     REQUIRE_SOURCE_ADDRESS:  %s\n"
            "              ACCESS_EXPIRE:  %s"  /* asctime() adds a newline */
            "               GPG_HOME_DIR:  %s\n"
            "             GPG_DECRYPT_ID:  %s\n"
            "             GPG_DECRYPT_PW:  <see the access.conf file>\n"
            "            GPG_REQUIRE_SIG:  %s\n"
            "GPG_IGNORE_SIG_VERIFY_ERROR:  %s\n"
            "              GPG_REMOTE_ID:  %s\n",
            ++i,
            acc->source,
            (acc->open_ports == NULL) ? "<not set>" : acc->open_ports,
            (acc->restrict_ports == NULL) ? "<not set>" : acc->restrict_ports,
            //(acc->key == NULL) ? "<not set>" : acc->key,
            acc->fw_access_timeout,
            acc->enable_cmd_exec ? "Yes" : "No",
            (acc->cmd_exec_user == NULL) ? "<not set>" : acc->cmd_exec_user,
            (acc->require_username == NULL) ? "<not set>" : acc->require_username,
            acc->require_source_address ? "Yes" : "No",
            (acc->access_expire_time > 0) ? asctime(localtime(&acc->access_expire_time)) : "<not set>\n",
            (acc->gpg_home_dir == NULL) ? "<not set>" : acc->gpg_home_dir,
            (acc->gpg_decrypt_id == NULL) ? "<not set>" : acc->gpg_decrypt_id,
            //(acc->gpg_decrypt_pw == NULL) ? "<not set>" : acc->gpg_decrypt_pw,
            acc->gpg_require_sig ? "Yes" : "No",
            acc->gpg_ignore_sig_error  ? "Yes" : "No",
            (acc->gpg_remote_id == NULL) ? "<not set>" : acc->gpg_remote_id
        );

        fprintf(stdout, "\n");

        acc = acc->next;
    }

    fprintf(stdout, "\n");
    fflush(stdout);
}

/***EOF***/
