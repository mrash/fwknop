/*
 *****************************************************************************
 *
 * File:    fko_user.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Set/Get the current username.
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

#ifdef WIN32
  #include <getlogin.h>
#endif

/* Get or Set the username for the fko context spa data.
*/
int
fko_set_username(fko_ctx_t ctx, const char * const spoof_user)
{
    char   *username = NULL;
    int     res = FKO_SUCCESS, is_user_heap_allocated=0;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* If spoof_user was not passed in, check for a SPOOF_USER enviroment
     * variable.  If it is set, use its value.
    */
    if(spoof_user != NULL && strnlen(spoof_user, MAX_SPA_USERNAME_SIZE))
        username = (char*)spoof_user;
    else
        username = getenv("SPOOF_USER");

    /* Try to get the username from the system.
    */
    if(username == NULL)
    {
        /* Since we've already tried looking at an env variable, try
         * LOGNAME next (and the cuserid() man page recommends this)
        */
        if((username = getenv("LOGNAME")) == NULL)
        {
#ifdef _XOPEN_SOURCE
            /* cuserid will return the effective user (i.e. su or setuid).
            */
            username = cuserid(NULL);
#else
            username = getlogin();
#endif
            /* if we still didn't get a username, continue falling back
            */
            if(username == NULL)
            {
                if((username = getenv("USER")) == NULL)
                {
                    username = strdup("NO_USER");
                    if(username == NULL)
                        return(FKO_ERROR_MEMORY_ALLOCATION);
                    is_user_heap_allocated = 1;
                }
            }
        }
    }

    /* Truncate the username if it is too long.
    */
    if(strnlen(username, MAX_SPA_USERNAME_SIZE) == MAX_SPA_USERNAME_SIZE)
        *(username + MAX_SPA_USERNAME_SIZE - 1) = '\0';

    if((res = validate_username(username)) != FKO_SUCCESS)
    {
        if(is_user_heap_allocated == 1)
            free(username);
        return res;
    }

    /* Just in case this is a subsquent call to this function.  We
     * do not want to be leaking memory.
    */
    if(ctx->username != NULL)
        free(ctx->username);

    ctx->username = strdup(username);

    ctx->state |= FKO_DATA_MODIFIED;

    if(is_user_heap_allocated == 1)
        free(username);

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

int
validate_username(const char *username)
{
    int i;

    if(username == NULL || strnlen(username, MAX_SPA_USERNAME_SIZE) == 0)
        return(FKO_ERROR_INVALID_DATA_USER_MISSING);

    /* Make sure it is just alpha-numeric chars, dashes, dots, and underscores
    */
    if(isalnum(username[0]) == 0)
        return(FKO_ERROR_INVALID_DATA_USER_FIRSTCHAR_VALIDFAIL);

    for (i=1; i < (int)strnlen(username, MAX_SPA_USERNAME_SIZE); i++)
        if((isalnum(username[i]) == 0)
                && username[i] != '-' && username[i] != '_' && username[i] != '.')
            return(FKO_ERROR_INVALID_DATA_USER_REMCHAR_VALIDFAIL);

    return FKO_SUCCESS;
}

/***EOF***/
