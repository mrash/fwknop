/* $Id$
 *****************************************************************************
 *
 * File:    fko_server_auth.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Set/Get the spa server auth data.
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

/* Set the SPA Server Auth data
*/
int
fko_set_spa_server_auth(fko_ctx_t ctx, const char *msg)
{
    /****************************************
     *   --DSS This is not supported yet
     ****************************************
    */
    //return(FKO_ERROR_UNSUPPORTED_FEATURE);


    /* Context must be initialized.
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* Gotta have a valid string.
    */
    if(msg == NULL || strlen(msg) == 0)
        return(FKO_ERROR_INVALID_DATA);

    /* --DSS XXX: Bail out for now.  But consider just
     *            truncating in the future...
    */
    if(strlen(msg) > MAX_SPA_SERVER_AUTH_SIZE)
        return(FKO_ERROR_DATA_TOO_LARGE);

    /* --DSS TODO: ???
     * Do we want to add message type and format checking here
     * or continue to leave it to the implementor?
    */

    /**/

    /* Just in case this is a subsquent call to this function.  We
     * do not want to be leaking memory.
    */
    if(ctx->server_auth != NULL)
        free(ctx->server_auth);

    ctx->server_auth = strdup(msg);

    ctx->state |= FKO_DATA_MODIFIED;

    if(ctx->server_auth == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    return(FKO_SUCCESS);
} 

/* Return the SPA message data.
*/
int
fko_get_spa_server_auth(fko_ctx_t ctx, char **server_auth)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *server_auth = ctx->server_auth;

    return(FKO_SUCCESS);
}

/***EOF***/
