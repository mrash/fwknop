/* $Id$
 *****************************************************************************
 *
 * File:    fko_encryption.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Set/Get the spa encryption type.
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
#include "cipher_funcs.h"
#include "base64.h"

/* Set the SPA encryption type.
*/
int fko_set_spa_encryption_type(fko_ctx_t *ctx, short encrypt_type)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(encrypt_type < 0 || encrypt_type >= FKO_LAST_ENCRYPTION_TYPE)
        return(FKO_ERROR_INVALID_DATA);

    ctx->encryption_type = encrypt_type;

    ctx->state |= FKO_ENCRYPT_TYPE_MODIFIED;

    return(FKO_SUCCESS);
}

/* Return the SPA encryption type.
*/
short fko_get_spa_encryption_type(fko_ctx_t *ctx)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    return(ctx->encryption_type);
}

/* Encrypt the encoded SPA data.
*/
int fko_encrypt_spa_data(fko_ctx_t *ctx, const char *enc_key)
{
    char           *plain;
    char           *b64cipher;
    unsigned char  *cipher;
    int             cipher_len, res;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    /* If there is no encoded data or the SPA data has been modified,
     * go ahead and re-encode here.
    */
    if(ctx->encoded_msg == NULL || FKO_SPA_DATA_MODIFIED(ctx))
    {
        res = fko_encode_spa_data(ctx);

        if(res != FKO_SUCCESS)
            return(res);
    }

    /* Croak on invalid encoded message as well. At present this is a
     * check for a somewhat arbitrary minimum length for the encoded
     * data.
    */
    if(strlen(ctx->encoded_msg) < MIN_SPA_ENCODED_MSG_SIZE)
        return(FKO_ERROR_MISSING_ENCODED_DATA);

    /* Make a bucket big enough to hold the enc msg + digest (plaintext)
     * and populate it appropriately.
    */
    plain = malloc(strlen(ctx->encoded_msg) + strlen(ctx->digest) + 2);
    if(plain == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    sprintf(plain, "%s:%s", ctx->encoded_msg, ctx->digest);

    /* Make a bucket for the encrypted version and populate it.
    */
    cipher = malloc(strlen(plain) + 32); /* Plus padding for salt and Block */
    if(cipher == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    cipher_len = fko_encrypt(
        (unsigned char*)plain, strlen(plain), (char*)enc_key, cipher
    );

    /* Now make a bucket for the base64-encoded version and populate it.
    */
    b64cipher = malloc(((cipher_len / 3) * 4) + 4);
    if(b64cipher == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    b64_encode(cipher, b64cipher, cipher_len);
    strip_b64_eq(b64cipher);

    ctx->encrypted_msg = strdup(b64cipher);
    
    /* Clean-up
    */
    free(plain);
    free(cipher);
    free(b64cipher);

    return(FKO_SUCCESS);
}

/***EOF***/
