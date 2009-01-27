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

    /* FKO_SUCCESS */
    "Success",
    /* FKO_ERROR_CTX_NOT_INITIALIZED */
    "FKO Context is not initialized",
    /* FKO_ERROR_MEMORY_ALLOCATION */
    "Unable to allocate memory",
    /* FKO_ERROR_INVALID_DATA */
    "Args contain invalid data",
    /* FKO_ERROR_DATA_TOO_LARGE */
    "Value or Size of the data exceeded the max allowed",
    /* FKO_ERROR_USERNAME_UNKNOWN */
    "Unable to determine username",
    /* FKO_ERROR_INCOMPLETE_SPA_DATA */
    "Missing or incomplete SPA data",
    /* FKO_ERROR_MISSING_ENCODED_DATA */
    "There is no encoded data to process",
    /* FKO_ERROR_INVALID_DIGEST_TYPE */
    "Invalid digest type",
    /* FKO_ERROR_INVALID_ALLOW_IP */
    "Invalid allow IP address in the SPA mesage data",
    /* FKO_ERROR_INVALID_SPA_COMMAND_MSG */
    "Invalid SPA command mesage format",
    /* FKO_ERROR_INVALID_SPA_ACCESS_MSG */
    "Invalid SPA access mesage format",
    /* FKO_ERROR_INVALID_SPA_NAT_ACCESS_MSG */
    "Invalid SPA nat_access mesage format",
    /* FKO_ERROR_INVALID_ENCRYPTION_TYPE */
    "Invalid encryption type",
    /* FKO_ERROR_WRONG_ENCRYPTION_TYPE */
    "Wrong or inappropriate encryption type for this operation",
    /* FKO_ERROR_MISSING_GPG_KEY_DATA */
    "Missing GPG key data (signer or recipient not set)",
    /* FKO_ERROR_DECRYPTION_SIZE */
    "Unexpected or invalid size for decrypted data",
    /* FKO_ERROR_DIGEST_VERIFICATION_FAILED */
    "The computed digest did not match the digest in the spa data",
    /* FKO_ERROR_UNSUPPORTED_FEATURE */
    "Unsupported or unimplemented feature or function",
    /* FKO_ERROR_UNKNOWN */
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
