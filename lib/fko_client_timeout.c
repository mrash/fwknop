/* $Id$
 *****************************************************************************
 *
 * File:    fko_spa_client_timeout.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Set/Get the spa client timeout data
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
 *****************************************************************************
*/
#include "fko_common.h"
#include "fko.h"

/* Set the SPA Client Timeout data
*/
int
fko_set_spa_client_timeout(fko_ctx_t ctx, int timeout)
{
    int     old_msg_type = ctx->message_type;

    /* Context must be initialized.
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* Gotta have a valid string.
    */
    if(timeout < 0)
        return(FKO_ERROR_INVALID_DATA);

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

    *timeout = ctx->client_timeout;

    return(FKO_SUCCESS);
}

/***EOF***/
