/* $Id$
 *****************************************************************************
 *
 * File:    fko_spa_client_timeout.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Set/Get the spa client timeout data
 *
 * Copyright (C) 2008 Damien Stuart (dstuart@dstuart.org)
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
int fko_set_spa_client_timeout(fko_ctx_t *ctx, int timeout)
{
    /* Context must be initialized.
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* Gotta have a valid string.
    */
    if(timeout < 0)
        return(FKO_ERROR_INVALID_DATA);

    ctx->client_timeout = timeout;

    ctx->state |= FKO_CLIENT_TIMEOUT_MODIFIED;

    return(FKO_SUCCESS);
} 

/* Return the SPA message data.
*/
int fko_get_spa_client_timeout(fko_ctx_t *ctx)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    return(ctx->client_timeout);
}

/***EOF***/
