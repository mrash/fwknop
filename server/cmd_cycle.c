/*
 * @file    cmd_cycle.c
 *
 * @brief   Fwknop routines for managing command cycles as defined via
 *          access.conf stanzas (CMD_CYCLE_OPEN and CMD_CYCLE_CLOSE).
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
*/

#include "fwknopd_common.h"
#include "log_msg.h"
#include "extcmd.h"
#include "cmd_cycle.h"
#include "access.h"

static char cmd_buf[CMD_CYCLE_BUFSIZE];
static char err_buf[CMD_CYCLE_BUFSIZE];

static void
zero_cmd_buffers(void)
{
    memset(cmd_buf, 0x0, CMD_CYCLE_BUFSIZE);
    memset(err_buf, 0x0, CMD_CYCLE_BUFSIZE);
    return;
}

static int pid_status = 0;

static int
is_var(const char * const var, const char * const cmd_str)
{
    int i;
    for(i=0; i < strlen(var); i++)
    {
        if(cmd_str[i] != var[i])
            return 0;
    }
    return 1;
}

static int
build_cmd(spa_data_t *spadat, const char * const cmd_cycle_str)
{
    char             port_str[MAX_PORT_STR_LEN+1]   = {0};
    char             proto_str[MAX_PROTO_STR_LEN+1] = {0};
    acc_port_list_t *port_list = NULL;
    int              i=0, buf_idx=0;

    if(expand_acc_port_list(&port_list, spadat->spa_message_remain) != 1)
    {
        free_acc_port_list(port_list);
        return 0;
    }

    /* We only look at the first port/proto combination for command
     * open/close cycles even if the SPA message had multiple ports
     * and protocols set.
    */
    snprintf(port_str, MAX_PORT_STR_LEN+1, "%d", port_list->port);
    snprintf(proto_str, MAX_PROTO_STR_LEN+1, "%d", port_list->proto);

    zero_cmd_buffers();

    /* Look for the following variables for substitution:
     * IP, SRC, PKT_SRC, DST, PORT, and PROTO
    */
    for(i=0; i < strnlen(cmd_cycle_str, CMD_CYCLE_BUFSIZE); i++)
    {
        if(cmd_cycle_str[i] == '$')
        {
            /* Found the start of a variable, now validate it and
             * swap in the IP/port/proto.
            */
            if(is_var("IP", (cmd_cycle_str+i+1)))
            {
                strlcat(cmd_buf, spadat->use_src_ip,
                        CMD_CYCLE_BUFSIZE);
                i += strlen("IP");
                buf_idx += strlen(spadat->use_src_ip);
            }
            /* SRC is a synonym for IP
            */
            else if(is_var("SRC", (cmd_cycle_str+i+1)))
            {
                strlcat(cmd_buf, spadat->use_src_ip,
                        CMD_CYCLE_BUFSIZE);
                i += strlen("SRC");
                buf_idx += strlen(spadat->use_src_ip);
            }
            /* Special case for the SPA packet source IP in
             * the IP header (i.e. not from the decrypted SPA
             * payload) if the user really wants this.
            */
            else if(is_var("PKT_SRC", (cmd_cycle_str+i+1)))
            {
                strlcat(cmd_buf, spadat->pkt_source_ip,
                        CMD_CYCLE_BUFSIZE);
                i += strlen("PKT_SRC");
                buf_idx += strlen(spadat->pkt_source_ip);
            }
            else if(is_var("DST", (cmd_cycle_str+i+1)))
            {
                strlcat(cmd_buf, spadat->pkt_destination_ip,
                        CMD_CYCLE_BUFSIZE);
                i += strlen("DST");
                buf_idx += strlen(spadat->pkt_destination_ip);
            }
            else if (is_var("PORT", (cmd_cycle_str+i+1)))
            {
                strlcat(cmd_buf, port_str, CMD_CYCLE_BUFSIZE);
                i += strlen("PORT");
                buf_idx += strlen(port_str);
            }
            else if (is_var("PROTO", (cmd_cycle_str+i+1)))
            {
                strlcat(cmd_buf, proto_str, CMD_CYCLE_BUFSIZE);
                i += strlen("PROTO");
                buf_idx += strlen(proto_str);
            }
            continue;
        }
        if(cmd_cycle_str[i] != '\0')
            cmd_buf[buf_idx++] = cmd_cycle_str[i];
        if(buf_idx == CMD_CYCLE_BUFSIZE)
        {
            free_acc_port_list(port_list);
            return 0;
        }
    }

    free_acc_port_list(port_list);
    return 1;
}

static int
cmd_open(fko_srv_options_t *opts, acc_stanza_t *acc,
        spa_data_t *spadat, const int stanza_num)
{
    /* CMD_CYCLE_OPEN: Build the open command by taking care of variable
     * substitutions if necessary.
    */
    if(build_cmd(spadat, acc->cmd_cycle_open))
    {
        log_msg(LOG_INFO, "[%s] (stanza #%d) Running CMD_CYCLE_OPEN command: %s",
                spadat->pkt_source_ip, stanza_num, cmd_buf);

        /* Run the open command
        */
        run_extcmd(cmd_buf, err_buf, CMD_CYCLE_BUFSIZE,
                WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    }
    else
    {
        log_msg(LOG_ERR,
            "[%s] (stanza #%d) Could not build CMD_CYCLE_OPEN command.",
            spadat->pkt_source_ip, stanza_num
        );
        return 0;
    }
    return 1;
}

static int
add_cmd_close(fko_srv_options_t *opts, acc_stanza_t *acc,
        spa_data_t *spadat, const int stanza_num)
{
    cmd_cycle_list_t   *last_clist=NULL, *new_clist=NULL, *tmp_clist=NULL;
    time_t              now;
    int                 cmd_close_len = 0;

   /* CMD_CYCLE_CLOSE: Build the close command, but don't execute it until
     * the expiration timer has passed.
    */
    if(build_cmd(spadat, acc->cmd_cycle_close))
    {
        /* Now the corresponding close command is now in cmd_buf
         * for later execution when the timer expires.
        */
        cmd_close_len = strnlen(cmd_buf, CMD_CYCLE_BUFSIZE-1)+1;
        log_msg(LOG_INFO,
                "[%s] (stanza #%d) Running CMD_CYCLE_CLOSE command in %d seconds: %s",
                spadat->pkt_source_ip, stanza_num, acc->cmd_cycle_timer, cmd_buf);
    }
    else
    {
        log_msg(LOG_ERR,
            "[%s] (stanza #%d) Could not build CMD_CYCLE_CLOSE command.",
            spadat->pkt_source_ip, stanza_num
        );
        return 0;
    }

    /* Add the corresponding close command - to be executed after the
     * designated timer has expired.
    */
    if((new_clist = calloc(1, sizeof(cmd_cycle_list_t))) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error creating string list entry"
        );
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }

    if(opts->cmd_cycle_list == NULL)
    {
        opts->cmd_cycle_list = new_clist;
    }
    else
    {
        tmp_clist = opts->cmd_cycle_list;

        do {
            last_clist = tmp_clist;
        } while((tmp_clist = tmp_clist->next));

        last_clist->next = new_clist;
    }

    /* Set the source IP
    */
    strlcpy(new_clist->src_ip, spadat->use_src_ip,
            sizeof(new_clist->src_ip));

    /* Set the expiration timer
    */
    time(&now);
    new_clist->expire = now + acc->cmd_cycle_timer;

    /* Set the close command
    */
    if((new_clist->close_cmd = calloc(1, cmd_close_len)) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error creating command close string"
        );
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }
    strlcpy(new_clist->close_cmd, cmd_buf, cmd_close_len);

    /* Set the access.conf stanza number
    */
    new_clist->stanza_num = stanza_num;

    return 1;
}

/* This is the main driver for open/close command cycles
*/
int
cmd_cycle_open(fko_srv_options_t *opts, acc_stanza_t *acc,
        spa_data_t *spadat, const int stanza_num, int *res)
{
    if(! cmd_open(opts, acc, spadat, stanza_num))
        return 0;

    if(! add_cmd_close(opts, acc, spadat, stanza_num))
        return 0;

     return FKO_SUCCESS;
}

static void
free_cycle_list_node(cmd_cycle_list_t *list_node)
{
    if(list_node != NULL)
    {
        if(list_node->close_cmd != NULL)
            free(list_node->close_cmd);
        free(list_node);
    }
    return;
}

/* Run all close commands based on the expiration timer
*/
void
cmd_cycle_close(fko_srv_options_t *opts)
{
    cmd_cycle_list_t   *curr=NULL, *prev=NULL;
    int                 do_delete=1;
    time_t              now;

    time(&now);

    if(opts->cmd_cycle_list == NULL)
    {
        return; /* No active command cycles */
    }
    else
    {
        while(do_delete)
        {
            do_delete = 0;

            /* Keep going through the command list for as long as
             * there are commands to be executed (and expired).
            */
            for(curr = opts->cmd_cycle_list;
                    curr != NULL;
                    prev = curr, curr=curr->next)
            {
                if(curr->expire <= now)
                {
                    log_msg(LOG_INFO,
                            "[%s] (stanza #%d) Timer expired, running CMD_CYCLE_CLOSE command: %s",
                            curr->src_ip, curr->stanza_num,
                            curr->close_cmd);

                    zero_cmd_buffers();

                    /* Run the close command
                    */
                    run_extcmd(curr->close_cmd, err_buf, CMD_CYCLE_BUFSIZE,
                            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

                    if(prev == NULL)
                        opts->cmd_cycle_list = curr->next;
                    else
                        prev->next = curr->next;

                    free_cycle_list_node(curr);
                    do_delete = 1;
                    break;
                }
            }
        }
    }

    return;
}

void
free_cmd_cycle_list(fko_srv_options_t *opts)
{
    cmd_cycle_list_t   *tmp_clist=NULL, *clist=NULL;

    clist = opts->cmd_cycle_list;

    while(clist != NULL)
    {
        tmp_clist = clist->next;
        free_cycle_list_node(clist);
        clist = tmp_clist;
    }
    return;
}
