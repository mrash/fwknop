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
do_var_subs(const char * const str)
{
    int i;

    /* Look for a '$' char
    */
    if (str != NULL && str[0] != 0x0)
    {
        for (i=0; i<strlen(str); i++)
        {
            if(str[i] == '$')
                return 1;
            i++;
        }
    }
    return 0;
}

int
cmd_cycle_open(fko_srv_options_t *opts, acc_stanza_t *acc,
        spa_data_t *spadat, const int stanza_num, int *res)
{
    cmd_cycle_list_t   *last_clist=NULL, *new_clist=NULL, *tmp_clist=NULL;
    time_t              now;
    char               *open_cmd=NULL, *close_cmd=NULL;

    if(opts->test)
    {
        log_msg(LOG_WARNING,
            "[%s] (stanza #%d) --test mode enabled, skipping CMD_CYCLE_OPEN execution.",
            spadat->pkt_source_ip, stanza_num
        );
        return 0;
    }

    log_msg(LOG_INFO, "[%s] (stanza #%d) CMD_CYCLE_OPEN: %s",
            spadat->pkt_source_ip, stanza_num, acc->cmd_cycle_open);
    log_msg(LOG_INFO, "[%s] (stanza #%d) expected CMD_CYCLE_CLOSE: %s",
            spadat->pkt_source_ip, stanza_num, acc->cmd_cycle_close);

    /* Add the corresponding close command - to be executed after the
     * designated timer has expired.
    */
    if((new_clist = calloc(1, sizeof(cmd_cycle_list_t))) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error creating string list entry"
        );
        return 0; // FIXME: handle this
    }

    if(opts->cmd_cycle_list == NULL)
    {
        opts->cmd_cycle_list = new_clist;
    }
    else
    {
        tmp_clist = new_clist;

        do {
            last_clist = tmp_clist;
        } while((tmp_clist = tmp_clist->next));

        last_clist->next = new_clist;
    }

    /* Set the source IP, expiration timer, and close command
    */
    strlcpy(new_clist->src_ip, spadat->pkt_source_ip,
            sizeof(new_clist->src_ip));

    time(&now);
    new_clist->expire = now + acc->cmd_cycle_timer;

    /* Now, execute the open command
    */
    if(do_var_subs(acc->cmd_cycle_open))
    {
    }
    else
    {
        /* Run the open command as-is
        */
        open_cmd = acc->cmd_cycle_open;
    }

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_CYCLE_BUFSIZE-1, "%s", open_cmd);

    run_extcmd(cmd_buf, err_buf, CMD_CYCLE_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

    return FKO_SUCCESS;
}

void
cmd_cycle_close(fko_srv_options_t *opts)
{
    cmd_cycle_list_t   *tmp_clist = NULL;
    time_t              now;

    time(&now);

    log_msg(LOG_INFO, "cmd_cycle_close() function");

    if(opts->cmd_cycle_list == NULL)
    {
        return; /* No active command cycles */
    }
    else
    {
        tmp_clist = opts->cmd_cycle_list;
        do {
            log_msg(LOG_INFO, "close command for src IP: %s", tmp_clist->src_ip);
            if(tmp_clist->expire <= now)
            {
                // FIXME: must remove this element from the list
                log_msg(LOG_INFO, "EXPIRED!", tmp_clist->src_ip);
            }
        } while((tmp_clist = tmp_clist->next));
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
        free(clist);
        clist = tmp_clist;
    }
    return;
}
