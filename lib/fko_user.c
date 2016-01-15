/**
 * \file lib/fko_user.c
 *
 * \brief Set/Get the current username.
 */

/*  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
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

#ifdef __MINGW32__
  #include "../win32/getlogin.h"
#elif WIN32
  #include <getlogin.h>
#endif

/* Get or Set the username for the fko context spa data.
*/
int
fko_set_username(fko_ctx_t ctx, const char * const spoof_user)
{
    char   *username = NULL;
    int     res = FKO_SUCCESS, is_user_heap_allocated=0;

#if HAVE_LIBFIU
    fiu_return_on("fko_set_username_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* If spoof_user was not passed in, check for a SPOOF_USER enviroment
     * variable.  If it is set, use its value.
    */
    if(spoof_user != NULL && spoof_user[0] != '\0')
    {
#if HAVE_LIBFIU
        fiu_return_on("fko_set_username_strdup", FKO_ERROR_MEMORY_ALLOCATION);
#endif
        username = strdup(spoof_user);
        if(username == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);
        is_user_heap_allocated = 1;
    }
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
#if HAVE_LIBFIU
        fiu_return_on("fko_set_username_valuser", FKO_ERROR_INVALID_DATA);
#endif
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

#if HAVE_LIBFIU
    fiu_return_on("fko_get_username_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(username == NULL)
        return(FKO_ERROR_INVALID_DATA);

#if HAVE_LIBFIU
    fiu_return_on("fko_get_username_val", FKO_ERROR_INVALID_DATA);
#endif

    *username = ctx->username;

    return(FKO_SUCCESS);
}

int
validate_username(const char *username)
{
    int i;

    if(username == NULL || strnlen(username, MAX_SPA_USERNAME_SIZE) == 0)
        return(FKO_ERROR_INVALID_DATA_USER_MISSING);

    /* Exclude a few chars - this list is consistent with MS guidance since
     * libfko runs on Windows:
     *      http://technet.microsoft.com/en-us/library/bb726984.aspx
    */
    for (i=0; i < (int)strnlen(username, MAX_SPA_USERNAME_SIZE); i++)
    {
        if((isalnum(username[i]) == 0)
                && ((username[i] < 0x20 || username[i] > 0x7e)
                /* Not allowed chars: " / \ [ ] : ; | = , + * ? < >
                */
                || (username[i] == 0x22
                    || username[i] == 0x2f
                    || username[i] == 0x5c
                    || username[i] == 0x5b
                    || username[i] == 0x5d
                    || username[i] == 0x3a
                    || username[i] == 0x3b
                    || username[i] == 0x7c
                    || username[i] == 0x3d
                    || username[i] == 0x2c
                    || username[i] == 0x2b
                    || username[i] == 0x2a
                    || username[i] == 0x3f
                    || username[i] == 0x3c
                    || username[i] == 0x3e)))
        {
            if(i == 0)
            {
                return(FKO_ERROR_INVALID_DATA_USER_FIRSTCHAR_VALIDFAIL);
            }
            else
            {
                return(FKO_ERROR_INVALID_DATA_USER_REMCHAR_VALIDFAIL);
            }
        }
    }

    return FKO_SUCCESS;
}

/***EOF***/
