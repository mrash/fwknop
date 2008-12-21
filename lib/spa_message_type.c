/* $Id$
 *****************************************************************************
 *
 * File:    spa_message_type.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Set the current fwknop message type.
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

int spa_message_type(spa_message_t *sm, unsigned short msg_type)
{
    if(msg_type >= LAST_MSG_TYPE)
    {
        fprintf(stderr, "*Invlaid fwknop message type: %u.\n", msg_type);
        return(-1);
    }

    sm->message_type = msg_type;

    return(0);
} 

/***EOF***/
