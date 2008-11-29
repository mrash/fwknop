/* $Id$
 *****************************************************************************
 *
 * File:    fko_test.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Temp test program for libfwknop
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

int main(int argc, char** argv)
{
    spa_message_t    sm;
    //char             test_str[1024] = {0};

    /* Zero our SPA message struct.
    */
    memset(&sm, 0x0, sizeof(spa_message_t));

    /* Get a random 16-byte string of hex values.
    */
    spa_random_number(&sm);

    printf("SPA_RAND_VAL: %s\n", sm.rand_val);

    return(0);
} 

/***EOF***/
