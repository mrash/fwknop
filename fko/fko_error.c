/* $Id$
 *****************************************************************************
 *
 * File:    fko_error.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Error handling functions for libfko
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

/* Note: These messages must matchup with the ERROR_CODES enum
*       defined in fko.h.
*/
static const char *fko_err_msgs[] = {
    "Success",
    "FKO Context is not initialized",
    "Unable to allocate memory",
    "Args contain invalid data",
    "Value or Size of the data exceeded the max allowed",
    "Unable to determine username",
    "Missing or incomplete SPA data",
    "There is no encoded data to process",
    "Invalid digest type",
    "Invalid allow IP address in the SPA mesage data",
    "Invalid SPA command mesage format",
    "Invalid SPA access mesage format",
    "Invalid SPA nat_access mesage format",
    "Invalid encryption type",
    "Unexpected or invalid size for decrypted data",
    "The computed digest did not match the digest in the spa data",
    "Unsupported or unimplemented feature or function",
    "Unknown/Unclassified error",
    0
};

const char*
fko_errstr(int err_code)
{

    if(err_code < 0 || err_code > FKO_ERROR_UNKNOWN)
        return NULL;

    return(fko_err_msgs[err_code]);
}

/***EOF***/
