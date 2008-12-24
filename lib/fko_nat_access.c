/* $Id$
 *****************************************************************************
 *
 * File:    fko_nat_access.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Set/Get the spa nat access request data.
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

/* Set the SPA Nat Access data
*/
int fko_set_spa_nat_access(fko_ctx_t *ctx, const char *msg)
{
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
    if(strlen(msg) > MAX_SPA_NAT_ACCESS_SIZE)
        return(FKO_ERROR_DATA_TOO_LARGE);

    /* Just in case this is a subsquent call to this function.  We
     * do not want to be leaking memory.
    */
    if(ctx->nat_access != NULL)
        free(ctx->nat_access);

    ctx->nat_access = strdup(msg);

    if(ctx->nat_access == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    return(FKO_SUCCESS);
} 

/* Return the SPA message data.
*/
char* fko_get_spa_nat_access(fko_ctx_t *ctx)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return NULL;

    return(ctx->nat_access);
}

/***EOF***/
