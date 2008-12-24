/* $Id$
 *****************************************************************************
 *
 * File:    fko_user.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Set/Get the current username.
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

/* Get or Set the username for the fko context spa data.
*/
int fko_set_username(fko_ctx_t *ctx, const char *spoof_user)
{
    char   *username = NULL;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* If spoof_user was not passed in, check for a SPOOF_USER enviroment
     * variable.  If it is set, use its value.
    */
    if(spoof_user != NULL && strlen(spoof_user))
        username = (char*)spoof_user;
    else
        username = getenv("SPOOF_USER");

    /* Try to get the username from the system.
    */
    if(username == NULL)
    {
#ifdef _XOPEN_SOURCE
        /* cuserid will return the effective user (i.e. su or setuid).
        */
        username = cuserid(NULL);
#else
        username = getlogin();
#endif

        /* If we did not get a name using the above methods, try the
         * LOGNAME or USER environment variables. If none of those work,
         * then we bail with an error.
        */
        if(username == NULL)
            if((username = getenv("LOGNAME")) == NULL)
                if((username = getenv("USER")) == NULL)
                    return(FKO_ERROR_USERNAME_UNKNOWN);
    }

    /* --DSS XXX: Bail out for now.  But consider just
     *            truncating in the future...
    */
    if(strlen(username) > MAX_SPA_USERNAME_SIZE)
        return(FKO_ERROR_DATA_TOO_LARGE);

    /* Just in case this is a subsquent call to this function.  We
     * do not want to be leaking memory.
    */
    if(ctx->username != NULL)
        free(ctx->username);

    ctx->username = strdup(username);

    if(ctx->username == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    return(FKO_SUCCESS);
}

/* Return the current username for this fko context.
*/
char* fko_get_username(fko_ctx_t *ctx)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return NULL;

    return(ctx->username);
}


/***EOF***/
