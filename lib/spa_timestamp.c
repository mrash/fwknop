/* $Id$
 *****************************************************************************
 *
 * File:    spa_timestamp.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Get the current timestamp with optional offset applied.
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
#include <time.h>

unsigned int spa_timestamp(spa_message_t *sm, int offset)
{
    sm->timestamp = time(NULL) + offset;
    return(sm->timestamp);
} 

/***EOF***/
