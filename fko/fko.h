/* $Id$
 *****************************************************************************
 *
 * File:    fko.h
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Header for libfko.
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
#ifndef FKO_H
#define FKO_H 1

/* General params
*/
#define FKO_PROTOCOL_VERSION "1.9.10" /* The fwknop protocol version */

/* Supported FKO Message types...
*/
typedef enum {
    FKO_COMMAND_MSG = 0,
    FKO_ACCESS_MSG,
    FKO_NAT_ACCESS_MSG,
    FKO_CLIENT_TIMEOUT_ACCESS_MSG,
    FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG,
    FKO_LOCAL_NAT_ACCESS_MSG,
    FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG,
    FKO_LAST_MSG_TYPE /* Always leave this as the last one */
} fko_message_type_t;

/* Supported digest types...
*/
typedef enum {
    FKO_DIGEST_MD5 = 0,
    FKO_DIGEST_SHA1,
    FKO_DIGEST_SHA256,
    FKO_LAST_DIGEST_TYPE /* Always leave this as the last one */
} fko_digest_type_t;

/* Supported encryption types...
*/
typedef enum {
    FKO_ENCRYPTION_RIJNDAEL = 0,
    FKO_ENCRYPTION_GPG,
    FKO_LAST_ENCRYPTION_TYPE /* Always leave this as the last one */
} fko_encryption_type_t;

/* FKO ERROR_CODES
 *
 * Note: If you change this list in any way, please be sure to make the
 *       appropriate corresponding change to the error message list in
 *       fko_error.c.
*/
typedef enum {
    FKO_SUCCESS = 0,
    FKO_ERROR_CTX_NOT_INITIALIZED,
    FKO_ERROR_MEMORY_ALLOCATION,
    FKO_ERROR_INVALID_DATA,
    FKO_ERROR_DATA_TOO_LARGE,
    FKO_ERROR_USERNAME_UNKNOWN,
    FKO_ERROR_INCOMPLETE_SPA_DATA,
    FKO_ERROR_MISSING_ENCODED_DATA,
    FKO_ERROR_INVALID_DIGEST_TYPE,
    FKO_ERROR_INVALID_ALLOW_IP,
    FKO_ERROR_INVALID_SPA_COMMAND_MSG,
    FKO_ERROR_INVALID_SPA_ACCESS_MSG,
    FKO_ERROR_INVALID_SPA_NAT_ACCESS_MSG,
    FKO_ERROR_INVALID_ENCRYPTION_TYPE,
    FKO_ERROR_DECRYPTION_SIZE_ERROR,
    FKO_ERROR_DIGEST_VERIFICATION_FAILED,
/* Add more errors above this line */
    FKO_ERROR_UNSUPPORTED_FEATURE,
    FKO_ERROR_UNKNOWN
} fko_error_codes_t;

/* General Defaults
*/
#define FKO_DEFAULT_MSG_TYPE    FKO_ACCESS_MSG
#define FKO_DEFAULT_DIGEST      FKO_DIGEST_SHA256
#define FKO_DEFAULT_ENCRYPTION  FKO_ENCRYPTION_RIJNDAEL

/* The context holds the global state and config options, as
 * well as some intermediate results during processing.
*/
struct fko_context;
typedef struct fko_context *fko_ctx_t;

/* Function prototypes */

/* General api calls */
int fko_new(fko_ctx_t *ctx);
int fko_new_with_data(fko_ctx_t *ctx, char *enc_msg, const char *dec_key);
void fko_destroy(fko_ctx_t ctx);
int fko_spa_data_final(fko_ctx_t ctx, const char *enc_key);

char* fko_get_spa_data(fko_ctx_t ctx);

/* Set context data functions */
int fko_set_rand_value(fko_ctx_t ctx, const char *val);
int fko_set_username(fko_ctx_t ctx, const char *spoof_user);
int fko_set_timestamp(fko_ctx_t ctx, int offset);
int fko_set_spa_message_type(fko_ctx_t ctx, short msg_type);
int fko_set_spa_message(fko_ctx_t ctx, const char *msg_string);
int fko_set_spa_nat_access(fko_ctx_t ctx, const char *nat_access);
int fko_set_spa_server_auth(fko_ctx_t ctx, const char *server_auth);
int fko_set_spa_client_timeout(fko_ctx_t ctx, int timeout);
int fko_set_spa_digest_type(fko_ctx_t ctx, short digest_type);
int fko_set_spa_digest(fko_ctx_t ctx);
int fko_set_spa_encryption_type(fko_ctx_t ctx, short encrypt_type);

/* Data processing and misc utility functions */
const char* fko_errstr(int err_code);

int fko_encode_spa_data(fko_ctx_t ctx);
int fko_decode_spa_data(fko_ctx_t ctx);
int fko_encrypt_spa_data(fko_ctx_t ctx, const char *enc_key);
int fko_decrypt_spa_data(fko_ctx_t ctx, const char *dec_key);
char* fko_get_encoded_data(fko_ctx_t ctx);

/* Get context data functions */
char* fko_get_rand_value(fko_ctx_t ctx);
char* fko_get_username(fko_ctx_t ctx);
unsigned int fko_get_timestamp(fko_ctx_t ctx);
short fko_get_spa_message_type(fko_ctx_t ctx);
char* fko_get_spa_message(fko_ctx_t ctx);
char* fko_get_spa_nat_access(fko_ctx_t ctx);
char* fko_get_spa_server_auth(fko_ctx_t ctx);
int fko_get_spa_client_timeout(fko_ctx_t ctx);
short fko_get_spa_digest_type(fko_ctx_t ctx);
char* fko_get_spa_digest(fko_ctx_t ctx);
short fko_get_spa_encryption_type(fko_ctx_t ctx);

char* fko_version(fko_ctx_t ctx);

#endif /* FKO_H */

/***EOF***/
