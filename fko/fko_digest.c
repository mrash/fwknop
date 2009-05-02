/* $Id$
 *****************************************************************************
 *
 * File:    fko_digest.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Create the base64-encoded digest for the current spa data. The
 *          digest used is determined by the digest_type setting in the
 *          fko context.
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
#include "digest.h"

/* Set the SPA digest type.
*/
int
fko_set_spa_digest_type(fko_ctx_t ctx, short digest_type)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(digest_type < 1 || digest_type >= FKO_LAST_DIGEST_TYPE)
        return(FKO_ERROR_INVALID_DATA);

    ctx->digest_type = digest_type;

    ctx->state |= FKO_DIGEST_TYPE_MODIFIED;

    return(FKO_SUCCESS);
}

/* Return the SPA digest type.
*/
int
fko_get_spa_digest_type(fko_ctx_t ctx, short *digest_type)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *digest_type = ctx->digest_type;

    return(FKO_SUCCESS);
}

int
fko_set_spa_digest(fko_ctx_t ctx)
{
    char    *md = NULL;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    /* Must have encoded message data to start with.
    */
    if(ctx->encoded_msg == NULL)
        return(FKO_ERROR_MISSING_ENCODED_DATA);

    switch(ctx->digest_type)
    {
        case FKO_DIGEST_MD5:
            md = malloc(MD_HEX_SIZE(MD5_DIGESTSIZE)+1);
            if(md == NULL)
                return(FKO_ERROR_MEMORY_ALLOCATION);
            
            md5_base64(md,
                (unsigned char*)ctx->encoded_msg, strlen(ctx->encoded_msg));
            break;    

        case FKO_DIGEST_SHA1:
            md = malloc(MD_HEX_SIZE(SHA1_DIGESTSIZE)+1);
            if(md == NULL)
                return(FKO_ERROR_MEMORY_ALLOCATION);
            
            sha1_base64(md,
                (unsigned char*)ctx->encoded_msg, strlen(ctx->encoded_msg));
            break;    

        case FKO_DIGEST_SHA256:
            md = malloc(MD_HEX_SIZE(SHA256_DIGESTSIZE)+1);
            if(md == NULL)
                return(FKO_ERROR_MEMORY_ALLOCATION);
            
            sha256_base64(md,
                (unsigned char*)ctx->encoded_msg, strlen(ctx->encoded_msg));
            break;    

        default:
            return(FKO_ERROR_INVALID_DIGEST_TYPE);
    }

    /* Just in case this is a subsquent call to this function.  We
     * do not want to be leaking memory.
    */
    if(ctx->digest != NULL)
        free(ctx->digest);

    ctx->digest = md;

    return(FKO_SUCCESS);
} 

int
fko_get_spa_digest(fko_ctx_t ctx, char **md)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *md = ctx->digest;

    return(FKO_SUCCESS);
}

/***EOF***/
