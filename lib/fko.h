/*
 *****************************************************************************
 *
 * File:    fko.h
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Header for libfko.
 *
 * Copyright 2009-2010 Damien Stuart (dstuart@dstuart.org)
 *
 *  License (GNU Public License):
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *****************************************************************************
*/
#ifndef FKO_H
#define FKO_H 1

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
  #ifdef DLL_EXPORTS
    #define DLL_API __declspec(dllexport)
  #else
	#ifdef DLL_IMPORTS
		#define DLL_API __declspec(dllimport)
	#else
		#define DLL_API
	#endif
  #endif
#else
  #define DLL_API
#endif

/* General params
*/
#define FKO_PROTOCOL_VERSION "1.9.12" /* The fwknop protocol version */

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
    FKO_DIGEST_INVALID_DATA = -1,
    FKO_DIGEST_UNKNOWN = 0,
    FKO_DIGEST_MD5,
    FKO_DIGEST_SHA1,
    FKO_DIGEST_SHA256,
    FKO_DIGEST_SHA384,
    FKO_DIGEST_SHA512,
    FKO_LAST_DIGEST_TYPE /* Always leave this as the last one */
} fko_digest_type_t;

/* Supported encryption types...
*/
typedef enum {
    FKO_ENCRYPTION_INVALID_DATA = -1,
    FKO_ENCRYPTION_UNKNOWN = 0,
    FKO_ENCRYPTION_RIJNDAEL,
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
    FKO_ERROR_FILESYSTEM_OPERATION,
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
    FKO_ERROR_WRONG_ENCRYPTION_TYPE,
    FKO_ERROR_DECRYPTION_SIZE,
    FKO_ERROR_DECRYPTION_FAILURE,
    FKO_ERROR_DIGEST_VERIFICATION_FAILED,
    FKO_ERROR_UNSUPPORTED_FEATURE,
    FKO_ERROR_UNKNOWN,

    /* Start GPGME-related errors */
    GPGME_ERR_START,
    FKO_ERROR_MISSING_GPG_KEY_DATA,
    FKO_ERROR_GPGME_NO_OPENPGP,
    FKO_ERROR_GPGME_CONTEXT,
    FKO_ERROR_GPGME_PLAINTEXT_DATA_OBJ,
    FKO_ERROR_GPGME_SET_PROTOCOL,
    FKO_ERROR_GPGME_CIPHER_DATA_OBJ,
    FKO_ERROR_GPGME_BAD_PASSPHRASE,
    FKO_ERROR_GPGME_ENCRYPT_SIGN,
    FKO_ERROR_GPGME_CONTEXT_SIGNER_KEY,
    FKO_ERROR_GPGME_SIGNER_KEYLIST_START,
    FKO_ERROR_GPGME_SIGNER_KEY_NOT_FOUND,
    FKO_ERROR_GPGME_SIGNER_KEY_AMBIGUOUS,
    FKO_ERROR_GPGME_ADD_SIGNER,
    FKO_ERROR_GPGME_CONTEXT_RECIPIENT_KEY,
    FKO_ERROR_GPGME_RECIPIENT_KEYLIST_START,
    FKO_ERROR_GPGME_RECIPIENT_KEY_NOT_FOUND,
    FKO_ERROR_GPGME_RECIPIENT_KEY_AMBIGUOUS,
    FKO_ERROR_GPGME_DECRYPT_FAILED,
    FKO_ERROR_GPGME_DECRYPT_UNSUPPORTED_ALGORITHM,
    FKO_ERROR_GPGME_BAD_GPG_EXE,
    FKO_ERROR_GPGME_BAD_HOME_DIR,
    FKO_ERROR_GPGME_SET_HOME_DIR,
    FKO_ERROR_GPGME_NO_SIGNATURE,
    FKO_ERROR_GPGME_BAD_SIGNATURE,
    FKO_ERROR_GPGME_SIGNATURE_VERIFY_DISABLED,

    FKO_LAST_ERROR
} fko_error_codes_t;

/* Macro that returns true if the given error code is a gpg-related error.
*/
#define IS_GPG_ERROR(x) (x > GPGME_ERR_START && x < FKO_LAST_ERROR)

/* General Defaults
*/
#define FKO_DEFAULT_MSG_TYPE    FKO_ACCESS_MSG
#define FKO_DEFAULT_DIGEST      FKO_DIGEST_SHA256
#define FKO_DEFAULT_ENCRYPTION  FKO_ENCRYPTION_RIJNDAEL

/* The context holds the global state and config options, as
 * well as some intermediate results during processing. This
 * is an opaque pointer.
*/
struct fko_context;
typedef struct fko_context *fko_ctx_t;

/* Some gpg-specifc data types and constants.
*/
#if HAVE_LIBGPGME

enum {
    FKO_GPG_NO_SIG_VERIFY_SIGS  = 0x01,
    FKO_GPG_ALLOW_BAD_SIG       = 0x02,
    FKO_GPG_NO_SIG_INFO         = 0x04,
    FKO_GPG_ALLOW_EXPIRED_SIG   = 0x08,
    FKO_GPG_ALLOW_REVOKED_SIG   = 0x10
};

#define FKO_GPG_GOOD_SIGSUM     3

#endif /* HAVE_LIBGPGME */

/* Function prototypes */

/* General api calls
*/
DLL_API int fko_new(fko_ctx_t *ctx);
DLL_API int fko_new_with_data(fko_ctx_t *ctx, const char *enc_msg, const char *dec_key);
DLL_API void fko_destroy(fko_ctx_t ctx);
DLL_API int fko_spa_data_final(fko_ctx_t ctx, const char *enc_key);


/* Set context data functions
*/
DLL_API int fko_set_rand_value(fko_ctx_t ctx, const char *val);
DLL_API int fko_set_username(fko_ctx_t ctx, const char *spoof_user);
DLL_API int fko_set_timestamp(fko_ctx_t ctx, const int offset);
DLL_API int fko_set_spa_message_type(fko_ctx_t ctx, const short msg_type);
DLL_API int fko_set_spa_message(fko_ctx_t ctx, const char *msg_string);
DLL_API int fko_set_spa_nat_access(fko_ctx_t ctx, const char *nat_access);
DLL_API int fko_set_spa_server_auth(fko_ctx_t ctx, const char *server_auth);
DLL_API int fko_set_spa_client_timeout(fko_ctx_t ctx, const int timeout);
DLL_API int fko_set_spa_digest_type(fko_ctx_t ctx, const short digest_type);
DLL_API int fko_set_spa_digest(fko_ctx_t ctx);
DLL_API int fko_set_spa_encryption_type(fko_ctx_t ctx, const short encrypt_type);
DLL_API int fko_set_spa_data(fko_ctx_t ctx, const char *enc_msg);

/* Data processing and misc utility functions
*/
DLL_API const char* fko_errstr(const int err_code);
DLL_API int fko_encryption_type(const char *enc_data);

DLL_API int fko_encode_spa_data(fko_ctx_t ctx);
DLL_API int fko_decode_spa_data(fko_ctx_t ctx);
DLL_API int fko_encrypt_spa_data(fko_ctx_t ctx, const char *enc_key);
DLL_API int fko_decrypt_spa_data(fko_ctx_t ctx, const char *dec_key);

DLL_API int fko_get_encoded_data(fko_ctx_t ctx, char **enc_data);


/* Get context data functions
*/
DLL_API int fko_get_rand_value(fko_ctx_t ctx, char **rand_val);
DLL_API int fko_get_username(fko_ctx_t ctx, char **username);
DLL_API int fko_get_timestamp(fko_ctx_t ctx, time_t *ts);
DLL_API int fko_get_spa_message_type(fko_ctx_t ctx, short *spa_msg);
DLL_API int fko_get_spa_message(fko_ctx_t ctx, char **spa_message);
DLL_API int fko_get_spa_nat_access(fko_ctx_t ctx, char **nat_access);
DLL_API int fko_get_spa_server_auth(fko_ctx_t ctx, char **server_auth);
DLL_API int fko_get_spa_client_timeout(fko_ctx_t ctx, int *client_timeout);
DLL_API int fko_get_spa_digest_type(fko_ctx_t ctx, short *spa_digest_type);
DLL_API int fko_get_spa_digest(fko_ctx_t ctx, char **spa_digest);
DLL_API int fko_get_spa_encryption_type(fko_ctx_t ctx, short *spa_enc_type);
DLL_API int fko_get_spa_data(fko_ctx_t ctx, char **spa_data);

DLL_API int fko_get_version(fko_ctx_t ctx, char **version);

/* GPG-related functions */
DLL_API int fko_set_gpg_exe(fko_ctx_t ctx, const char *gpg_exe);
DLL_API int fko_get_gpg_exe(fko_ctx_t ctx, char **gpg_exe);

DLL_API int fko_set_gpg_recipient(fko_ctx_t ctx, const char *recip);
DLL_API int fko_get_gpg_recipient(fko_ctx_t ctx, char **recip);
DLL_API int fko_set_gpg_signer(fko_ctx_t ctx, const char *signer);
DLL_API int fko_get_gpg_signer(fko_ctx_t ctx, char **signer);
DLL_API int fko_set_gpg_home_dir(fko_ctx_t ctx, const char *gpg_home_dir);
DLL_API int fko_get_gpg_home_dir(fko_ctx_t ctx, char **gpg_home_dir);

DLL_API const char* fko_gpg_errstr(fko_ctx_t ctx);

DLL_API int fko_set_gpg_signature_verify(fko_ctx_t ctx, const unsigned char val);
DLL_API int fko_get_gpg_signature_verify(fko_ctx_t ctx, unsigned char *val);
DLL_API int fko_set_gpg_ignore_verify_error(fko_ctx_t ctx, const unsigned char val);
DLL_API int fko_get_gpg_ignore_verify_error(fko_ctx_t ctx, unsigned char *val);

DLL_API int fko_get_gpg_signature_id(fko_ctx_t ctx, char **sig_id);
DLL_API int fko_get_gpg_signature_fpr(fko_ctx_t ctx, char **sig_fpr);
DLL_API int fko_get_gpg_signature_summary(fko_ctx_t ctx, int *sigsum);
DLL_API int fko_get_gpg_signature_status(fko_ctx_t ctx, int *sigstat);

DLL_API int fko_gpg_signature_id_match(fko_ctx_t ctx, const char *id, unsigned char *result);
DLL_API int fko_gpg_signature_fpr_match(fko_ctx_t ctx, const char *fpr, unsigned char *result);

#ifdef __cplusplus
}
#endif

#endif /* FKO_H */

/***EOF***/
