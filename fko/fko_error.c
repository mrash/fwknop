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

const char*
fko_errstr(int err_code)
{
    switch (err_code)
    {
        /* Start base FKO errors
        */
        case FKO_SUCCESS:
            return("Success");

        case FKO_ERROR_CTX_NOT_INITIALIZED:
            return("FKO Context is not initialized");

        case FKO_ERROR_MEMORY_ALLOCATION:
            return("Unable to allocate memory");

        case FKO_ERROR_INVALID_DATA:
            return("Args contain invalid data");

        case FKO_ERROR_DATA_TOO_LARGE:
            return("Value or Size of the data exceeded the max allowed");

        case FKO_ERROR_USERNAME_UNKNOWN:
            return("Unable to determine username");

        case FKO_ERROR_INCOMPLETE_SPA_DATA:
            return("Missing or incomplete SPA data");

        case FKO_ERROR_MISSING_ENCODED_DATA:
            return("There is no encoded data to process");

        case FKO_ERROR_INVALID_DIGEST_TYPE:
            return("Invalid digest type");

        case FKO_ERROR_INVALID_ALLOW_IP:
            return("Invalid allow IP address in the SPA mesage data");

        case FKO_ERROR_INVALID_SPA_COMMAND_MSG:
            return("Invalid SPA command mesage format");

        case FKO_ERROR_INVALID_SPA_ACCESS_MSG:
            return("Invalid SPA access mesage format");

        case FKO_ERROR_INVALID_SPA_NAT_ACCESS_MSG:
            return("Invalid SPA nat_access mesage format");

        case FKO_ERROR_INVALID_ENCRYPTION_TYPE:
            return("Invalid encryption type");

        case FKO_ERROR_WRONG_ENCRYPTION_TYPE:
            return("Wrong or inappropriate encryption type for this operation");

        case FKO_ERROR_MISSING_GPG_KEY_DATA:
            return("Missing GPG key data (signer or recipient not set)");

        case FKO_ERROR_DECRYPTION_SIZE:
            return("Unexpected or invalid size for decrypted data");

        case FKO_ERROR_DIGEST_VERIFICATION_FAILED:
            return("The computed digest did not match the digest in the spa data");

        case FKO_ERROR_UNSUPPORTED_FEATURE:
            return("Unsupported or unimplemented feature or function");

        case FKO_ERROR_UNKNOWN:
            return("Unknown/Unclassified error");

#if HAVE_LIBGPGME
        /* Start GPGME-related errors
        */
        case FKO_ERROR_GPGME_NO_OPENPGP:
            return("This GPGME implementation does not support OpenPGP");

        case FKO_ERROR_GPGME_CONTEXT:
            return("Unable to create GPGME context");

        case FKO_ERROR_GPGME_PLAINTEXT_DATA_OBJ:
            return("Error creating the plaintext data object");

        case FKO_ERROR_GPGME_SET_PROTOCOL:
            return("Unable to set GPGME to use OpenPGP protocol");

        case FKO_ERROR_GPGME_CIPHER_DATA_OBJ:
            return("Error creating the encrypted data data object");

        case FKO_ERROR_GPGME_BAD_PASSPHRASE:
            return("The GPG passphrase was not valid");

        case FKO_ERROR_GPGME_ENCRYPT_SIGN:
            return("Error during the encrypt and sign operation");

        case FKO_ERROR_GPGME_CONTEXT_SIGNER_KEY:
            return("Unable to create GPGME context for the signer key");

        case FKO_ERROR_GPGME_SIGNER_KEYLIST_START:
            return("Error from signer keylist start operation");

        case FKO_ERROR_GPGME_SIGNER_KEY_NOT_FOUND:
            return("The key for the given signer was not found");

        case FKO_ERROR_GPGME_SIGNER_KEY_AMBIGUOUS:
            return("Ambiguous name/id for the signer key (mulitple matches)");

        case FKO_ERROR_GPGME_ADD_SIGNER:
            return("Error adding the signer key to the gpgme context");

        case FKO_ERROR_GPGME_CONTEXT_RECIPIENT_KEY:
            return("Unable to create GPGME context for the recipient key");

        case FKO_ERROR_GPGME_RECIPIENT_KEYLIST_START:
            return("Error from signer keylist start operation");

        case FKO_ERROR_GPGME_RECIPIENT_KEY_NOT_FOUND:
            return("The key for the given recipient was not found");

        case FKO_ERROR_GPGME_RECIPIENT_KEY_AMBIGUOUS:
            return("Ambiguous name/id for the recipient key (mulitple matches)");

        case FKO_ERROR_GPGME_DECRYPT_FAILED:
            return("Decryption operation failed");
#endif /* HAVE_LIBGPGME */
    }

#if !HAVE_LIBGPGME
    if(err_code > GPGME_ERR_START && err_code < FKO_LAST_ERROR)
        return("GPG-related error code given, but GPG is not supported");
#endif

    return("Undefined Error");
}

const char*
fko_gpg_errorstr(fko_ctx_t ctx)
{
#if HAVE_LIBGPGME
    if(ctx->gpg_err)
        return(gpgme_strerror(ctx->gpg_err));
#endif /* HAVE_LIBGPGME */

    return("");
}

/***EOF***/
