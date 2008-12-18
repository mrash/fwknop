/* $Id$
 *****************************************************************************
 *
 * File:    spa_random_number.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Generate a 16-byte random hex value.
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

char* spa_random_number(spa_message_t *sm)
{
    FILE           *rfd;
    struct timeval  tv;
    unsigned int    seed;
    unsigned long   rnd;
    char            tmp_buf[RAND_VAL_SIZE+1] = {0};

    /* Attempt to read seed data from /dev/urandom.  If that does not
     * work, then fall back to a time-based method (less secure, but
     * probably more portable).
    */
    if((rfd = fopen(RAND_FILE, "r")) != NULL)
    {
        /* Read seed from /dev/urandom
        */
        fread(&seed, 4, 1, rfd);
        fclose(rfd);
#ifdef DEBUG
        fprintf(stderr, "Using /dev/urandom for seed: %u\n", seed);
#endif
    }
    else
    {
        /* Seed based on time (current usecs).
        */
        gettimeofday(&tv, NULL);

        seed = tv.tv_usec;
#ifdef DEBUG
        fprintf(stderr, "Using time and pids for seed: %u\n", seed);
#endif
    }

    srand(seed);

    sprintf(sm->rand_val, "%u", rand());
    
    while(strlen(sm->rand_val) < RAND_VAL_SIZE)
    {
        sprintf(tmp_buf, "%u", rand());
        strlcat(sm->rand_val, tmp_buf, RAND_VAL_SIZE+1);
    }

    return(sm->rand_val);
} 

/***EOF***/
