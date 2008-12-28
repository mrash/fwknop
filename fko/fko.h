/* $Id$
 *****************************************************************************
 *
 * File:    fko.h
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Header for the fwknop source files
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
enum {
    FKO_COMMAND_MSG = 0,
    FKO_ACCESS_MSG,
    FKO_NAT_ACCESS_MSG,
    FKO_CLIENT_TIMEOUT_ACCESS_MSG,
    FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG,
    FKO_LOCAL_NAT_ACCESS_MSG,
    FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG,
    FKO_LAST_MSG_TYPE /* Always leave this as the last one */
};

/* Supported digest types...
*/
enum {
    FKO_DIGEST_MD5 = 0,
    FKO_DIGEST_SHA1,
    FKO_DIGEST_SHA256,
    FKO_LAST_DIGEST_TYPE /* Always leave this as the last one */
};

/* Supported encryption types...
*/
enum {
    FKO_ENCRYPTION_RIJNDAEL = 0,
    FKO_ENCRYPTION_GPG,
    FKO_LAST_ENCRYPTION_TYPE /* Always leave this as the last one */
};

/* General state flag bit values.
*/
enum {
    FKO_CTX_SET                 = 1,        /* Set when ctx is initialized */
    FKO_RAND_VAL_MODIFIED       = 1 << 1,
    FKO_USERNAME_MODIFIED       = 1 << 2,
    FKO_TIMESTAMP_MODIFIED      = 1 << 3,
    FKO_VERSION_MODIFIED        = 1 << 4,
    FKO_SPA_MSG_TYPE_MODIFIED   = 1 << 6,
    FKO_CTX_SET_2               = 1 << 7,   /* Set when ctx is initialized */
    FKO_SPA_MSG_MODIFIED        = 1 << 8,
    FKO_NAT_ACCESS_MODIFIED     = 1 << 9,
    FKO_SERVER_AUTH_MODIFIED    = 1 << 10,
    FKO_CLIENT_TIMEOUT_MODIFIED = 1 << 11,
    FKO_DIGEST_TYPE_MODIFIED    = 1 << 12,
    FKO_ENCRYPT_TYPE_MODIFIED   = 1 << 13,
    FKO_GPG_SUPPORTED           = 1 << 14,
    FKO_BACKWARD_COMPATIBLE     = 1 << 15
};

/* This is used in conjunction with the ctx->initial value as a means to
 * determine if the ctx has been properly initialized.  However, this
 * may not work 100% of the time as it is possible (though not likely)
 * an ctx may have values that match both the flags and the ctx->initial
 * value.
*/
#define FKO_CTX_INITIALIZED  (FKO_CTX_SET|FKO_CTX_SET_2)

#define FKO_SET_CTX_INITIALIZED(ctx) \
    (ctx->state |= (FKO_CTX_INITIALIZED))

#define FKO_CLEAR_CTX_INITIALIZED(ctx) \
    (ctx->state &= (0xffff & ~FKO_CTX_INITIALIZED))

/* Consolidate all SPA data modified flags.
*/
#define FKO_ANY_SPA_DATA_MODIFIED ( \
    FKO_RAND_VAL_MODIFIED | FKO_USERNAME_MODIFIED | FKO_TIMESTAMP_MODIFIED \
    | FKO_VERSION_MODIFIED | FKO_SPA_MSG_TYPE_MODIFIED | FKO_SPA_MSG_MODIFIED \
    | FKO_NAT_ACCESS_MODIFIED | FKO_SERVER_AUTH_MODIFIED \
    | FKO_CLIENT_TIMEOUT_MODIFIED | FKO_DIGEST_TYPE_MODIFIED \
    | FKO_ENCRYPT_TYPE_MODIFIED )
 
/* This should return true if any SPA data field has been modifed since the
 * last encode/encrypt.
*/
#define FKO_SPA_DATA_MODIFIED(ctx) (ctx->state & FKO_ANY_SPA_DATA_MODIFIED)

/* Clear all SPA data modified flags.  This is normally called after a
 * succesful encode/digest/encryption cycle.
*/
#define FKO_CLEAR_SPA_DATA_MODIFIED(ctx) \
    (ctx->state &= (0xffff & ~FKO_ANY_SPA_DATA_MODIFIED))

/* Macros used for determining ctx initialization state.
*/
#define CTX_INITIALIZED(ctx) (ctx->initval == FKO_CTX_INITIALIZED)

/* FKO ERROR_CODES
 *
 * Note: If you change this list in any way, please be syre to make the
 *       appropriate corresponding change to the error message list in
 *       fko_error.c.
*/
enum {
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
/* Add more errors above this line */
    FKO_ERROR_UNSUPPORTED_FEATURE,
    FKO_ERROR_UNKNOWN
};

/* General Defaults
*/
#define FKO_DEFAULT_MSG_TYPE    FKO_ACCESS_MSG
#define FKO_DEFAULT_DIGEST      FKO_DIGEST_SHA256
#define FKO_DEFAULT_ENCRYPTION  FKO_ENCRYPTION_RIJNDAEL

/* How much space we allow for the fko context error message buffer.
*/
#define MAX_FKO_ERR_MSG_SIZE        128

/* Define some limits (--DSS XXX: These sizes need to be reviewed)
*/
#define MAX_SPA_USERNAME_SIZE        64
#define MAX_SPA_MESSAGE_SIZE        256
#define MAX_SPA_NAT_ACCESS_SIZE     128
#define MAX_SPA_SERVER_AUTH_SIZE     64

#define MIN_SPA_ENCODED_MSG_SIZE     36 /* Somewhat arbitrary */
#define MIN_GNUPG_MSG_SIZE          400

/* Misc.
*/
#define FKO_RAND_VAL_SIZE            16
#define FKO_ENCODE_TMP_BUF_SIZE    1024

/* The pieces we need to make an FKO  SPA data packet.
*/
typedef struct _fko_ctx {
    /* FKO SPA message data (raw and un-encoded) */
    char            rand_val[FKO_RAND_VAL_SIZE+1];
    char           *username;
    unsigned int    timestamp;
    char           *version;
    short           message_type;
    char           *message;
    char           *nat_access;
    char           *server_auth;
    unsigned int    client_timeout;
    char           *digest;

    /* FKO SPA message encoding types */
    short  digest_type;
    short  encryption_type;

    /* Complete processed data (encodings, etc.) */
    char           *encoded_msg;

    char           *encrypted_msg;
    unsigned int    encrypted_msg_size;

    /* State info */
    unsigned short  state;
    unsigned char   initval;

} fko_ctx_t;

/* Function prototypes
*/
int fko_new(fko_ctx_t *ctx);
int fko_new_with_data(fko_ctx_t *ctx, char *enc_data);
void fko_destroy(fko_ctx_t *ctx);

char* fko_version(fko_ctx_t *ctx);
const char* fko_errstr(int err_code);

int fko_set_rand_value(fko_ctx_t *ctx, const char *val);
int fko_set_username(fko_ctx_t *ctx, const char *spoof_user);
int fko_set_timestamp(fko_ctx_t *ctx, int offset);
int fko_set_spa_message_type(fko_ctx_t *ctx, short msg_type);
int fko_set_spa_message(fko_ctx_t *ctx, const char *msg_string);
int fko_set_spa_nat_access(fko_ctx_t *ctx, const char *nat_access);
int fko_set_spa_server_auth(fko_ctx_t *ctx, const char *server_auth);
int fko_set_spa_client_timeout(fko_ctx_t *ctx, int timeout);
int fko_set_spa_digest_type(fko_ctx_t *ctx, short digest_type);
int fko_set_spa_digest(fko_ctx_t *ctx);
int fko_set_spa_encryption_type(fko_ctx_t *ctx, short encrypt_type);

char* fko_get_rand_value(fko_ctx_t *ctx);
char* fko_get_username(fko_ctx_t *ctx);
unsigned int fko_get_timestamp(fko_ctx_t *ctx);
short fko_get_spa_message_type(fko_ctx_t *ctx);
char* fko_get_spa_message(fko_ctx_t *ctx);
char* fko_get_spa_nat_access(fko_ctx_t *ctx);
char* fko_get_spa_server_auth(fko_ctx_t *ctx);
int fko_get_spa_client_timeout(fko_ctx_t *ctx);
short fko_get_spa_digest_type(fko_ctx_t *ctx);
char* fko_get_spa_digest(fko_ctx_t *ctx);
short fko_get_spa_encryption_type(fko_ctx_t *ctx);

int fko_encode_spa_data(fko_ctx_t *ctx);
int fko_decode_spa_data(fko_ctx_t *ctx);

int fko_encrypt_spa_data(fko_ctx_t *ctx, const char *enc_key);
int fko_decrypt_spa_data(fko_ctx_t *ctx, const char *dec_key);


#endif /* FKO_H */

/***EOF***/
