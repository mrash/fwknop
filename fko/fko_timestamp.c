/* $Id$
 *****************************************************************************
 *
 * File:    fko_timestamp.c
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
#include "fko_common.h"
#include "fko.h"

#ifdef HAVE_SYS_TIME_H
  #include <sys/time.h>
  #ifdef TIME_WITH_SYS_TIME
    #include <time.h>
  #endif
#endif

/* Set the timestamp.
*/
int
fko_set_timestamp(fko_ctx_t ctx, int offset)
{
    unsigned int ts;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    ts = time(NULL) + offset;

    if(ts < 0)
        return(FKO_ERROR_INVALID_DATA);
 
    ctx->timestamp = ts;

    ctx->state |= FKO_DATA_MODIFIED;

    return(FKO_SUCCESS);
} 

/* Return the current timestamp.
*/
unsigned int
fko_get_timestamp(fko_ctx_t ctx)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return 0;

    return(ctx->timestamp);
}

/***EOF***/
