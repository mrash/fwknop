/*
 *****************************************************************************
 *
 * File:    fko_user.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Set/Get the current username.
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

#ifdef WIN32
  #include <getlogin.h>
#endif

/* Get or Set the username for the fko context spa data.
*/
int
fko_set_username(fko_ctx_t ctx, const char *spoof_user)
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
         * then we fallback to NO_USER.
        */
        if(username == NULL)
            if((username = getenv("LOGNAME")) == NULL)
                if((username = getenv("USER")) == NULL)
                    username = strdup("NO_USER");
    }

    /* Truncate the username if it is too long.
    */
    if(strlen(username) > MAX_SPA_USERNAME_SIZE)
        *(username + MAX_SPA_USERNAME_SIZE) = '\0';

    /* Just in case this is a subsquent call to this function.  We
     * do not want to be leaking memory.
    */
    if(ctx->username != NULL)
        free(ctx->username);

    ctx->username = strdup(username);

    ctx->state |= FKO_DATA_MODIFIED;

    if(ctx->username == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    return(FKO_SUCCESS);
}

/* Return the current username for this fko context.
*/
int
fko_get_username(fko_ctx_t ctx, char **username)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *username = ctx->username;

    return(FKO_SUCCESS);
}

/***EOF***/
