/*
 *****************************************************************************
 *
 * File:    fko_spa_client_timeout.c
 *
 * Purpose: Set/Get the spa client timeout data
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
 *****************************************************************************
*/
#include "fko_common.h"
#include "fko.h"

/* Set the SPA Client Timeout data
*/
int
fko_set_spa_client_timeout(fko_ctx_t ctx, const int timeout)
{
    int     old_msg_type;

    /* Context must be initialized.
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* The timeout should not be negative
    */
    if(timeout < 0)
        return(FKO_ERROR_INVALID_DATA_CLIENT_TIMEOUT_NEGATIVE);

    old_msg_type = ctx->message_type;

    ctx->client_timeout = timeout;

    ctx->state |= FKO_DATA_MODIFIED;

    /* If a timeout is set, then we may need to verify/change message
     * type accordingly.
    */
    if(ctx->client_timeout > 0)
    {
        switch(ctx->message_type)
        {
            case FKO_ACCESS_MSG:
                ctx->message_type = FKO_CLIENT_TIMEOUT_ACCESS_MSG;
                break;

            case FKO_NAT_ACCESS_MSG:
                ctx->message_type = FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG;
                break;

            case FKO_LOCAL_NAT_ACCESS_MSG:
                ctx->message_type = FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG;
                break;
        }
    }
    else  /* Timeout is 0, which means no timeout. */
    {
        switch(ctx->message_type)
        {
            case FKO_CLIENT_TIMEOUT_ACCESS_MSG:
                ctx->message_type = FKO_ACCESS_MSG;
                break;

            case FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG:
                ctx->message_type = FKO_NAT_ACCESS_MSG;
                break;

            case FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG:
                ctx->message_type = FKO_LOCAL_NAT_ACCESS_MSG;
                break;
        }
    }

    if(ctx->message_type != old_msg_type)
        ctx->state |= FKO_SPA_MSG_TYPE_MODIFIED;

    return(FKO_SUCCESS);
}

/* Return the SPA message data.
*/
int
fko_get_spa_client_timeout(fko_ctx_t ctx, int *timeout)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(timeout == NULL)
        return(FKO_ERROR_INVALID_DATA);

    *timeout = ctx->client_timeout;

    return(FKO_SUCCESS);
}

/***EOF***/
