/*
 ******************************************************************************
 *
 * File:    access.c
 *
 * Author:  Damien Stuart
 *
 * Purpose: Access.conf file processing for fwknop server.
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
#include <sys/stat.h>

#if HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
#endif
#include <arpa/inet.h>

#include "fwknopd_common.h"
#include "access.h"
#include "config_init.h"    /* For the convenience macros */
#include "utils.h"
#include "log_msg.h"

/* Add an access string entry
*/
static char *
add_acc_string(char **var, char *val)
{
    if((*var = strdup(val)) == NULL)
    {
        log_msg(LOG_ERR|LOG_STDERR,
            "Fatal memory allocation error adding access list entry: %s", var
        );
        exit(EXIT_FAILURE);
    }            
}

/* Add an access int entry
*/
static int
add_acc_int(int *var, char *val)
{
    return(*var = atoi(val));
}

/* Add an access bool entry (unsigned char of 1 or 0)
*/
static unsigned char
add_acc_bool(unsigned char *var, char *val)
{
    return(*var = (strncasecmp(val, "Y", 1) == 0) ? 1 : 0);
}

/* Take an IP or Subnet/Mask and convert it to mask for later
 * comparisons of incoming source IPs against this mask.
*/
static void
add_source_mask(acc_stanza_t *acc, char *ip)
{
    char                *ndx;
    char                ip_str[16] = {0};
    uint32_t            mask;

    struct in_addr      in;

    acc_int_list_t      *last_sle, *new_sle, *tmp_sle;

    if((new_sle = calloc(1, sizeof(acc_int_list_t))) == NULL)
    {
        log_msg(LOG_ERR|LOG_STDERR,
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
        } while(tmp_sle = tmp_sle->next);

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
            log_msg(LOG_ERR|LOG_STDERR,
                "Error parsing IP to int for: %s", ip_str
            );

            free(new_sle);
            new_sle = NULL;

            return;
        }

        /* Store our mask converted from CIDR to a 32-bit value.
        */
        new_sle->mask  = (0xFFFFFFFF << (32 - mask));

        /* Store our masked address for cpmarisons with future incoming
         * packets.
        */
        new_sle->maddr = ntohl(in.s_addr) & new_sle->mask;
    }
}

/* Expand the access SOURCE string to a list of masks.
*/
static acc_int_list_t*
expand_acc_source(acc_stanza_t *acc)
{
    char           *ndx, *start;
    char            buf[32];

    start = acc->source;

    for(ndx = start; *ndx; ndx++)
    {
        if(*ndx == ',')
        {
            strlcpy(buf, start, (ndx-start)+1);
            add_source_mask(acc, buf);
            start = ndx+1;
        }
    }

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
        log_msg(LOG_ERR|LOG_STDERR,
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
        log_msg(LOG_ERR|LOG_STDERR,
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
    char                *ndx;
    char                proto_str[16];
    int                 proto_int, port;

    acc_port_list_t     *last_plist, *new_plist, *tmp_plist;

    if((new_plist = calloc(1, sizeof(acc_port_list_t))) == NULL)
    {
        log_msg(LOG_ERR|LOG_STDERR,
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
        } while(tmp_plist = tmp_plist->next);

        last_plist->next = new_plist;
    }
    
    /* Parse the string into its components.
    */
    if(parse_proto_and_port(port_str, &proto_int, &port) != 0)
    {
        free(new_plist);
        new_plist = NULL;
        return;
    }

    new_plist->proto = proto_int;
    new_plist->port  = port;
}

/* Add a string list entry to the given acc_string_list.
*/
static void
add_string_list_ent(acc_string_list_t **stlist, char *str_str)
{
    char                *ndx;

    acc_string_list_t   *last_stlist, *new_stlist, *tmp_stlist;

    if((new_stlist = calloc(1, sizeof(acc_string_list_t))) == NULL)
    {
        log_msg(LOG_ERR|LOG_STDERR,
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
        } while(tmp_stlist = tmp_stlist->next);

        last_stlist->next = new_stlist;
    }
    
    new_stlist->str = strdup(str_str);

    if(new_stlist->str == NULL)
    {
        log_msg(LOG_ERR|LOG_STDERR,
            "Fatal memory allocation error adding string list entry item"
        );
        exit(EXIT_FAILURE);
    }

}

/* Expand a proto/port access string to a list of access proto-port struct.
*/
static acc_port_list_t*
expand_acc_port_list(acc_port_list_t **plist, char *plist_str)
{
    char           *ndx, *start;
    char            buf[32];

    start = plist_str;

    for(ndx = start; *ndx; ndx++)
    {
        if(*ndx == ',')
        {
            strlcpy(buf, start, (ndx-start)+1);
            add_port_list_ent(plist, buf);
            start = ndx+1;
        }
    }

    strlcpy(buf, start, (ndx-start)+1);

    add_port_list_ent(plist, buf);
}

/* Expand a comma-separated string into a simple acc_string_list.
*/
static acc_string_list_t*
expand_acc_string_list(acc_string_list_t **stlist, char *stlist_str)
{
    char           *ndx, *start;
    char            buf[1024];

    start = stlist_str;

    for(ndx = start; *ndx; ndx++)
    {
        if(*ndx == ',')
        {
            strlcpy(buf, start, (ndx-start)+1);
            add_string_list_ent(stlist, buf);
            start = ndx+1;
        }
    }

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
static void
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

        free(last_stl);
    }
}

/* Free any allocated content of an access stanza.
 *
 * NOTE: If a new access.conf parameter is created, and it is a string
 *       value, it also needs to be added to the list if items to check
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

    if(acc->key != NULL)
        free(acc->key);

    if(acc->cmd_regex != NULL)
        free(acc->cmd_regex);

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
    char           *ndx, *start, *end;
    char            buf[1024];
    uint32_t        tmpint;


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

/* Take an index and a string value. malloc the space for the value
 * and assign it to the array at the specified index.
*/
static void
acc_stanza_init(fko_srv_options_t *opts)
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
        log_msg(LOG_ERR|LOG_STDERR,
            "Fatal memory allocation error adding access stanza"
        );
        exit(EXIT_FAILURE);
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
        } while(acc = acc->next);
    
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
    int             i = 0;
    char            *var, *val;

    acc_stanza_t    *acc = opts->acc_stanzas;

    if(!acc)
        return;

    while(acc)
    {
        /* fw_access_timeout is the only one that need a default fallback
         * (so far).
        */
        if(acc->fw_access_timeout < 1)
            acc->fw_access_timeout = DEF_FW_ACCESS_TIMEOUT;

        acc = acc->next;
    }
}

/* Read and parse the access file, popluating the access data as we go.
*/
void
parse_access_file(fko_srv_options_t *opts)
{
    FILE           *file_ptr;
    char           *ndx;
    int             got_source = 0, got_open_ports = 0, got_key = 0;
    unsigned int    num_lines = 0;

    char            access_line_buf[MAX_LINE_LEN] = {0};
    char            var[MAX_LINE_LEN]  = {0};
    char            val[MAX_LINE_LEN]  = {0};
    char            tmp1[MAX_LINE_LEN]  = {0};
    char            tmp2[MAX_LINE_LEN]  = {0};

    struct stat     st;

    acc_stanza_t   *curr_acc = NULL;

    /* First see if the access file exists.  If it doesn't, complain
     * and go on with program defaults.
    */
    if(stat(opts->config[CONF_ACCESS_FILE], &st) != 0)
    {
        fprintf(stderr, "[*] Access file: '%s' was not found.\n",
            opts->config[CONF_ACCESS_FILE]);

        exit(EXIT_FAILURE);
    }

    if ((file_ptr = fopen(opts->config[CONF_ACCESS_FILE], "r")) == NULL)
    {
        fprintf(stderr, "[*] Could not open access file: %s\n",
            opts->config[CONF_ACCESS_FILE]);
        perror(NULL);

        exit(EXIT_FAILURE);
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
        fprintf(stderr,
            "ACCESS FILE: %s, LINE: %s\tVar: %s, Val: '%s'\n",
            opts->config[CONF_ACCESS_FILE], access_line_buf, var, val
        );
        */

        /* Process the entry.
         *
         * NOTE: If a new access.conf parameter is created.  It also needs
         *       to be accounted for in the following if/if else construct.
        */

        if(CONF_VAR_IS(var, "SOURCE"))
        {
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
            got_open_ports++;
        }
        else if(CONF_VAR_IS(var, "RESTRICT_PORTS"))
        {
            add_acc_string(&(curr_acc->restrict_ports), val);
        }
        else if(CONF_VAR_IS(var, "KEY"))
        {
            add_acc_string(&(curr_acc->key), val);
            got_key++;
        }
        else if(CONF_VAR_IS(var, "FW_ACCESS_TIMEOUT"))
        {
            add_acc_int(&(curr_acc->fw_access_timeout), val);
        }
        else if(CONF_VAR_IS(var, "ENABLE_CMD_EXEC"))
        {
            add_acc_bool(&(curr_acc->enable_cmd_exec), val);
        }
        else if(CONF_VAR_IS(var, "CMD_REGEX"))
        {
            add_acc_string(&(curr_acc->cmd_regex), val);
        }
        else if(CONF_VAR_IS(var, "REQUIRE_USERNAME"))
        {
            add_acc_bool(&(curr_acc->require_username), val);
        }
        else if(CONF_VAR_IS(var, "REQUIRE_SOURCE_ADDRESS"))
        {
            add_acc_bool(&(curr_acc->require_source_address), val);
        }
        else if(CONF_VAR_IS(var, "GPG_HOME_DIR"))
        {
            add_acc_string(&(curr_acc->gpg_home_dir), val);
        }
        else if(CONF_VAR_IS(var, "GPG_DECRYPT_ID"))
        {
            add_acc_string(&(curr_acc->gpg_decrypt_id), val);
        }
        else if(CONF_VAR_IS(var, "GPG_DECRYPT_PW"))
        {
            add_acc_string(&(curr_acc->gpg_decrypt_pw), val);
        }
        else if(CONF_VAR_IS(var, "GPG_REMOTE_ID"))
        {
            add_acc_string(&(curr_acc->gpg_remote_id), val);
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
     * the OPEN_PORTS and KEY variables defined.
    */
    if (got_source == 0
        || got_open_ports == 0
        || got_key == 0)
    {
        fprintf(stderr,
            "[*] Could not find valid SOURCE stanza in access file: '%s'\n",
            opts->config[CONF_ACCESS_FILE]);
        exit(EXIT_FAILURE);
    }

    /* Expand our the expandable fields into their respective data buckets.
    */
    expand_acc_ent_lists(opts);

    /* Make sure default values are set where needed.
     * a default value.
    */
    set_acc_defaults(opts);

    return;
}

/* Check an IP address against the list of allowed SOURCE stanzas.
 * return the a pointer to the access stanza that matches first or
 * NULL if no match is found.
*/
acc_stanza_t*
acc_check_source(fko_srv_options_t *opts, uint32_t ip)
{
    acc_stanza_t    *acc = opts->acc_stanzas;
    char            *source;

    if(acc == NULL)
    {
        log_msg(LOG_WARNING|LOG_STDERR,
            "Check access source called with no access stanzas defined."
        );
        return(NULL);
    }

    while(acc)
    {
        if((ip && acc->source_list->mask) == acc->source_list->maddr)
            break;

        acc = acc->next;
    }

    return(acc);
}

/* Compare the contents of 2 port lists.  Return true on a match.
 * Match depends on the match_any flag.  if match_any is 1 then any
 * entry in the incoming data need only match one item to return true.
 * Otherwise all entries in the incoming data must have a corresponding
 * match in the access port_list.
*/
static int
compare_port_list(acc_port_list_t *in, acc_port_list_t *ac, int match_any)
{
    int a_cnt = 0;
    int i_cnt = 0;
    int tres  = 0;

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
        log_msg(LOG_ERR|LOG_STDERR,
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

/* Dump the configuration
*/
void
dump_access_list(fko_srv_options_t *opts)
{
    int             i = 0;
    char            *var, *val;

    acc_stanza_t    *acc = opts->acc_stanzas;

    fprintf(stderr, "Current fwknopd access settings:\n");

    if(!acc)
    {
        fprintf(stderr, "\n    ** No Access Settings Defined **\n\n");
        return;
    }

    while(acc)
    {
        fprintf(stderr,
            "SOURCE (%i):  %s\n"
            "==============================================================\n"
            "             OPEN_PORTS:  %s\n"
            "         RESTRICT_PORTS:  %s\n"
            "                    KEY:  %s\n"
            "      FW_ACCESS_TIMEOUT:  %i\n"
            "        ENABLE_CMD_EXEC:  %s\n"
            "              CMD_REGEX:  %s\n"
            "       REQUIRE_USERNAME:  %s\n"
            " REQUIRE_SOURCE_ADDRESS:  %s\n"
            "           GPG_HOME_DIR:  %s\n"
            "         GPG_DECRYPT_ID:  %s\n"
            "         GPG_DECRYPT_PW:  %s\n"
            "          GPG_REMOTE_ID:  %s\n",
            ++i,
            acc->source,
            (acc->open_ports == NULL) ? "<not set>" : acc->open_ports,
            (acc->restrict_ports == NULL) ? "<not set>" : acc->restrict_ports,
            (acc->key == NULL) ? "<not set>" : acc->key,
            acc->fw_access_timeout,
            acc->enable_cmd_exec ? "Yes" : "No",
            (acc->cmd_regex == NULL) ? "<not set>" : acc->cmd_regex,
            acc->require_username ? "Yes" : "No",
            acc->require_source_address ? "Yes" : "No",
            (acc->gpg_home_dir == NULL) ? "<not set>" : acc->gpg_home_dir,
            (acc->gpg_decrypt_id == NULL) ? "<not set>" : acc->gpg_decrypt_id,
            (acc->gpg_decrypt_pw == NULL) ? "<not set>" : acc->gpg_decrypt_pw,
            (acc->gpg_remote_id == NULL) ? "<not set>" : acc->gpg_remote_id
        );

        fprintf(stderr, "\n");

        acc = acc->next;
    }

    fprintf(stderr, "\n");
}

/***EOF***/
