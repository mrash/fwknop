/* $Id$
 *****************************************************************************
 *
 * File:    spa_digest.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Create the base64-encoded digest for the current spa data. The
 *          digest used is determined by the digest_type setting in the
 *          spa_message struct.
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

int spa_digest(spa_message_t *sm)
{
    if(sm->message[0] == '\0')
        return -1;

    switch(sm->digest_type)
    {
        case MD5_DIGEST:
            md5_base64(sm->digest, (uchar*)sm->message, strlen(sm->message));
            break;    

        case SHA1_DIGEST:
            sha1_base64(sm->digest, (uchar*)sm->message, strlen(sm->message));
            break;    

        case SHA256_DIGEST:
            sha256_base64(sm->digest, (uchar*)sm->message, strlen(sm->message));
            break;    

        default:
            return(-2);
    }

    return(0);
} 

/***EOF***/
