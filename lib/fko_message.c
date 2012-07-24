/*
 *****************************************************************************
 *
 * File:    fko_message.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Set/Get the spa message (access req/command/etc) based
 *          on the current spa data.
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
 *****************************************************************************
*/
#include "fko_common.h"
#include "fko.h"

/* Set the SPA message type.
*/
int
fko_set_spa_message_type(fko_ctx_t ctx, const short msg_type)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    if(msg_type < 0 || msg_type >= FKO_LAST_MSG_TYPE)
        return(FKO_ERROR_INVALID_DATA);

    ctx->message_type = msg_type;

    ctx->state |= FKO_SPA_MSG_TYPE_MODIFIED;

    return(FKO_SUCCESS);
}

/* Return the SPA message type.
*/
int
fko_get_spa_message_type(fko_ctx_t ctx, short *msg_type)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    *msg_type = ctx->message_type;

    return(FKO_SUCCESS);
}

/* Set the SPA MESSAGE data
*/
int
fko_set_spa_message(fko_ctx_t ctx, const char *msg)
{
    int res = FKO_ERROR_UNKNOWN;

    /* Context must be initialized.
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* Gotta have a valid string.
    */
    if(msg == NULL || strnlen(msg, MAX_SPA_MESSAGE_SIZE) == 0)
        return(FKO_ERROR_INVALID_DATA);

    /* --DSS XXX: Bail out for now.  But consider just
     *            truncating in the future...
    */
    if(strnlen(msg, MAX_SPA_MESSAGE_SIZE) == MAX_SPA_MESSAGE_SIZE)
        return(FKO_ERROR_DATA_TOO_LARGE);

    /* Basic message type and format checking...
    */
    switch(ctx->message_type)
    {
        case FKO_COMMAND_MSG:
            res = validate_cmd_msg(msg);
            break;

        case FKO_ACCESS_MSG:
        case FKO_CLIENT_TIMEOUT_ACCESS_MSG:
            res = validate_access_msg(msg);
            break;

        case FKO_NAT_ACCESS_MSG:
        case FKO_LOCAL_NAT_ACCESS_MSG:
        case FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG:
        case FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG:
            res = validate_nat_access_msg(msg);
            break;
    }

    if(res != FKO_SUCCESS)
        return(res);

    /* Just in case this is a subsquent call to this function.  We
     * do not want to be leaking memory.
    */
    if(ctx->message != NULL)
        free(ctx->message);

    ctx->message = strdup(msg);

    ctx->state |= FKO_DATA_MODIFIED;

    if(ctx->message == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    return(FKO_SUCCESS);
}

/* Return the SPA message data.
*/
int
fko_get_spa_message(fko_ctx_t ctx, char **msg)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *msg = ctx->message;

    return(FKO_SUCCESS);
}

/* Validate a command message format.
*/
int
validate_cmd_msg(const char *msg)
{
    const char   *ndx;
    int     res         = FKO_SUCCESS;
    int     startlen    = strnlen(msg, MAX_SPA_CMD_LEN);

    if(startlen == MAX_SPA_CMD_LEN)
        return(FKO_ERROR_INVALID_DATA);

    /* Should have a valid allow IP.
    */
    if((res = got_allow_ip(msg)) != FKO_SUCCESS)
        return(res);

    /* Commands are fairly free-form so all we can really verify is
     * there is something at all. Get past the IP and comma, and make
     * sure we have some string leftover...
    */
    ndx = strchr(msg, ',');
    if(ndx == NULL || (1+(ndx - msg)) >= startlen)
        return(FKO_ERROR_INVALID_SPA_COMMAND_MSG);

    return(FKO_SUCCESS);
}

int
validate_access_msg(const char *msg)
{
    const char   *ndx;
    int     res         = FKO_SUCCESS;
    int     startlen    = strnlen(msg, MAX_SPA_MESSAGE_SIZE);

    if(startlen == MAX_SPA_MESSAGE_SIZE)
        return(FKO_ERROR_INVALID_DATA);

    /* Should have a valid allow IP.
    */
    if((res = got_allow_ip(msg)) != FKO_SUCCESS)
        return(res);

    /* Position ourselves beyond the allow IP and make sure we are
     * still good.
    */
    ndx = strchr(msg, ',');
    if(ndx == NULL || (1+(ndx - msg)) >= startlen)
        return(FKO_ERROR_INVALID_SPA_ACCESS_MSG);

    /* Look for a comma to see if this is a multi-part access request.
    */
    do {
        ndx++;
        res = validate_proto_port_spec(ndx);
    } while((ndx = strchr(ndx, ',')));

    return(res);
}

int
validate_proto_port_spec(const char *msg)
{
    int     startlen    = strnlen(msg, MAX_SPA_MESSAGE_SIZE);
    const char   *ndx   = msg;

    if(startlen == MAX_SPA_MESSAGE_SIZE)
        return(FKO_ERROR_INVALID_DATA);

    /* Now check for proto/port string.  Currenly we only allow protos
     * 'tcp', 'udp', and 'icmp'.
    */
    if(strncmp(ndx, "tcp", 3)
      && strncmp(ndx, "udp", 3)
      && strncmp(ndx, "icmp", 4)
      && strncmp(ndx, "none", 4))
        return(FKO_ERROR_INVALID_SPA_ACCESS_MSG);

    ndx = strchr(ndx, '/');
    if(ndx == NULL || (1+(ndx - msg)) >= startlen)
        return(FKO_ERROR_INVALID_SPA_ACCESS_MSG);

    /* Skip over the ',' and make sure we only have digits.
    */
    ndx++;
    while(*ndx != '\0')
    {
        if(isdigit(*ndx) == 0)
            return(FKO_ERROR_INVALID_SPA_ACCESS_MSG);
        ndx++;
    }

    return(FKO_SUCCESS);
}

int
validate_nat_access_msg(const char *msg)
{
    int res = FKO_SUCCESS;

    /* Should have a valid access message.
    */
    if((res = validate_access_msg(msg)) != FKO_SUCCESS)
        return(res);

    // --DSS TODO: XXX: Put nat_access validation code here

    return(FKO_SUCCESS);
}

int
got_allow_ip(const char *msg)
{
    const char *ndx     = msg;
    int         dot_cnt = 0;
    int         res     = FKO_SUCCESS;

    while(*ndx != ',' && *ndx != '\0')
    {
        if(*ndx == '.')
            dot_cnt++;
        else if(isdigit(*ndx) == 0)
        {
            res = FKO_ERROR_INVALID_ALLOW_IP;
            break;
        }

        ndx++;
    }

    if(dot_cnt != 3)
        res = FKO_ERROR_INVALID_ALLOW_IP;

    return(res);
}

/***EOF***/
