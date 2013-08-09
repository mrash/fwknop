/*
 *****************************************************************************
 *
 * File:    fko_nat_access.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Set/Get the spa nat access request data.
 *
 * Copyright 2009-2013 Damien Stuart (dstuart@dstuart.org)
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
#include "fko_common.h"
#include "fko.h"

/* Set the SPA Nat Access data
*/
int
fko_set_spa_nat_access(fko_ctx_t ctx, const char * const msg)
{
    int res = FKO_SUCCESS;

    /* Context must be initialized.
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* Gotta have a valid string.
    */
    if(msg == NULL || strnlen(msg, MAX_SPA_NAT_ACCESS_SIZE) == 0)
        return(FKO_ERROR_INVALID_DATA_NAT_EMPTY);

    /* --DSS XXX: Bail out for now.  But consider just
     *            truncating in the future...
    */
    if(strnlen(msg, MAX_SPA_NAT_ACCESS_SIZE) == MAX_SPA_NAT_ACCESS_SIZE)
        return(FKO_ERROR_DATA_TOO_LARGE);

    if((res = validate_nat_access_msg(msg)) != FKO_SUCCESS)
        return(res);

    /* Just in case this is a subsquent call to this function.  We
     * do not want to be leaking memory.
    */
    if(ctx->nat_access != NULL)
        free(ctx->nat_access);

    ctx->nat_access = strdup(msg);

    ctx->state |= FKO_DATA_MODIFIED;

    if(ctx->nat_access == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    /* If we set the nat_access message Then we force the message_type
     * as well. Technically, the message type should be set already.
     * This will serve a half-protective measure.
     * --DSS XXX: should do this better.
    */
    if(ctx->client_timeout > 0)
    {
        if(ctx->message_type != FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
            ctx->message_type = FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG;
    }
    else
        if(ctx->message_type != FKO_LOCAL_NAT_ACCESS_MSG)
            ctx->message_type = FKO_NAT_ACCESS_MSG;

    return(FKO_SUCCESS);
}

/* Return the SPA message data.
*/
int
fko_get_spa_nat_access(fko_ctx_t ctx, char **nat_access)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *nat_access = ctx->nat_access;

    return(FKO_SUCCESS);
}

/***EOF***/
