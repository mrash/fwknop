/* $Id$
 *****************************************************************************
 *
 * File:    spa_user.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Get the current user
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
#include "fwknop.h"

char* spa_user(spa_message_t *sm, char *spoof_user)
{
    size_t res;

    /* If spoof_user was not passed in, check for a SPOOF_USER enviroment
     * variable.  If it is set, use its value.
    */
    if(spoof_user == NULL)
        spoof_user = getenv("SPOOF_USER");

    if(spoof_user != NULL)
    {
        strlcpy(sm->user, spoof_user, MAX_USER_SIZE+1);
    }
    else
    {
#ifdef _XOPEN_SOURCE
        /* cuserid will return the effective user (i.e. su or setuid).
        */
        res = strlcpy(sm->user, cuserid(NULL), MAX_USER_SIZE);
#else
        res = strlcpy(sm->user, getlogin(), MAX_USER_SIZE);
#endif

        /* If we did not get a name using the above methods, try the
         * LOGNAME or USER environment variables. If none of those work,
         * then we fall back to the DEFAULT_USER.
        */
        if(res < 1)
            if((strlcpy(sm->user, getenv("LOGNAME"), MAX_USER_SIZE)) < 1)
                if((strlcpy(sm->user, getenv("USER"), MAX_USER_SIZE)) < 1)
                    strlcpy(sm->user, DEFAULT_USER, strlen(DEFAULT_USER) + 1);
    }

    return(sm->user);
} 

/***EOF***/
