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

#if HAVE_LIBGPGME
  #include <gpgme.h>
#endif

//extern char *gpg_error_string;
//extern char *gpg_error_source;

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

    /* Start GPGME-related errors */
    NULL,

    /* FKO_ERROR_GPGME_NO_OPENPGP */
    "This GPGME implementation does not support OpenPGP",
    /* FKO_ERROR_GPGME_CONTEXT */
    "Unable to create GPGME context",
    /* FKO_ERROR_GPGME_PLAINTEXT_DATA_OBJ */
    "Error creating the plaintext data object",
    /* FKO_ERROR_GPGME_SET_PROTOCOL */
    "Unable to set GPGME to use OpenPGP protocol",
    /* FKO_ERROR_GPGME_CIPHER_DATA_OBJ */
    "Error creating the encrypted data data object",
    /* FKO_ERROR_GPGME_BAD_SIGNER_PASSPHRASE */
    "Signer passphrase was not valid",
    /* FKO_ERROR_GPGME_ENCRYPT_SIGN */
    "Error during the encrypt and sign operation",
    /* FKO_ERROR_GPGME_CONTEXT_SIGNER_KEY */
    "Unable to create GPGME context for the signer key",
    /* FKO_ERROR_GPGME_SIGNER_KEYLIST_START */
    "Error from signer keylist start operation",
    /*FKO_ERROR_GPGME_SIGNER_KEY_NOT_FOUND */
    "The key for the given signer was not found",
    /* FKO_ERROR_GPGME_SIGNER_KEY_AMBIGUOUS */
    "Ambiguous name/id for the signer key (mulitple matches)",
    /* FKO_ERROR_GPGME_ADD_SIGNER */
    "Error adding the signer key to the gpgme context",
    /* FKO_ERROR_GPGME_CONTEXT_RECIPIENT_KEY */
    "Unable to create GPGME context for the recipient key",
    /* FKO_ERROR_GPGME_RECIPIENT_KEYLIST_START */
    "Error from signer keylist start operation",
    /*FKO_ERROR_GPGME_RECIPIENT_KEY_NOT_FOUND */
    "The key for the given recipient was not found",
    /* FKO_ERROR_GPGME_RECIPIENT_KEY_AMBIGUOUS */
    "Ambiguous name/id for the recipient key (mulitple matches)",
    /* FKO_ERROR_GPGME_DECRYPT_VERIFY */
    "Error during the decrypt and verify operation",

    /* End GPGME-related errors */
    0
};

const char*
fko_errstr(int err_code)
{
    if(err_code < 0 || err_code >= FKO_LAST_ERROR)
        return NULL;

    return(fko_err_msgs[err_code]);
}

/***EOF***/
