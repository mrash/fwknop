/**
 * \file lib/fko.h
 *
 * \brief Header for libfko
 */

/*
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
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
#define FKO_PROTOCOL_VERSION "3.0.0" /**< The fwknop protocol version */

/**
 *
 * \enum fko_message_type_t
 *
 * \brief Supported FKO Message types...
 */

typedef enum {
    FKO_COMMAND_MSG = 0, /**< Command message */
    FKO_ACCESS_MSG, /**< Access message */
    FKO_NAT_ACCESS_MSG,  /**< NAT Access message */
    FKO_CLIENT_TIMEOUT_ACCESS_MSG, /**< Access message with timeout */
    FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG, /**< NAT Access with timeout */
    FKO_LOCAL_NAT_ACCESS_MSG, /**< Local NAT access */
    FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG, /**< Local NAT access with timeout */
    FKO_LAST_MSG_TYPE /**< Always leave this as the last one */
} fko_message_type_t;

/**
 *
 * \enum fko_digest_type_t
 *
 * \brief Supported digest types...
 */
typedef enum {
    FKO_DIGEST_INVALID_DATA = -1, /**< Invalid digest type*/
    FKO_DIGEST_UNKNOWN = 0, /**< Unknown digest type*/
    FKO_DIGEST_MD5, /**< MD5 digest type*/
    FKO_DIGEST_SHA1, /**< SHA1 digest type*/
    FKO_DIGEST_SHA256, /**< SHA256 digest type*/
    FKO_DIGEST_SHA384, /**< SHA384 digest type*/
    FKO_DIGEST_SHA512, /**< SHA512 digest type*/
    FKO_DIGEST_SHA3_256, /**< SHA3 256 digest type*/
    FKO_DIGEST_SHA3_512, /**< SHA3 512 digest type*/
    FKO_LAST_DIGEST_TYPE /**< Always leave this as the last one */
} fko_digest_type_t;

/**
 *
 * \enum fko_hmac_type_t
 *
 * \brief Supported hmac digest types...
*/
typedef enum {
    FKO_HMAC_INVALID_DATA = -1, /**< Invalid HMAC type*/
    FKO_HMAC_UNKNOWN = 0, /**< Unknown HMAC type*/
    FKO_HMAC_MD5, /**< MD5 HMAC type*/
    FKO_HMAC_SHA1, /**< SHA1 HMAC type*/
    FKO_HMAC_SHA256, /**< SHA256 HMAC type*/
    FKO_HMAC_SHA384, /**< SHA384 HMAC type*/
    FKO_HMAC_SHA512, /**< SHA512 HMAC type*/
    FKO_HMAC_SHA3_256, /**< SHA3 256 HMAC type */
    FKO_HMAC_SHA3_512, /**< SHA3 512 HMAC type*/
    FKO_LAST_HMAC_MODE /**< Always leave this as the last one */
} fko_hmac_type_t;

/**
 *
 * \enum fko_encryption_type_t
 *
 * \brief Supported encryption types...
*/
typedef enum {
    FKO_ENCRYPTION_INVALID_DATA = -1, /**< Invalid encryption type*/
    FKO_ENCRYPTION_UNKNOWN = 0, /**< Unknown encryption type*/
    FKO_ENCRYPTION_RIJNDAEL, /**< AES encryption type*/
    FKO_ENCRYPTION_GPG, /**< GPG encryption type*/
    FKO_LAST_ENCRYPTION_TYPE /**< Always leave this as the last one */
} fko_encryption_type_t;

/**
 *
 * \enum fko_encryption_mode_t
 *
 * \brief Symmetric encryption modes to correspond to rijndael.h
*/
typedef enum {
    FKO_ENC_MODE_UNKNOWN = 0, /**< Unknown encryption mode*/
    FKO_ENC_MODE_ECB, /**< Electronic Code Book encryption mode*/
    FKO_ENC_MODE_CBC, /**< Cipher Block Chaining encryption mode*/
    FKO_ENC_MODE_CFB, /**< Cipher Feedback encryption mode*/
    FKO_ENC_MODE_PCBC, /**< Propagating Cipher Block Chaining encryption mode*/
    FKO_ENC_MODE_OFB, /**< Output Feedback encryption mode*/
    FKO_ENC_MODE_CTR, /**< Counter encryption mode*/
    FKO_ENC_MODE_ASYMMETRIC,  /**< placeholder when GPG is used */
    FKO_ENC_MODE_CBC_LEGACY_IV,  /**< for the old zero-padding strategy */
    FKO_LAST_ENC_MODE /**< Always leave this as the last one */
} fko_encryption_mode_t;

/**
 *
 * \enum fko_error_codes_t
 *
 * \brief FKO ERROR_CODES
 *
 * Note: If you change this list in any way, please be sure to make the
 *       appropriate corresponding change to the error message list in
 *       fko_error.c.
*/
typedef enum {
    FKO_SUCCESS = 0, /**< Success*/
    FKO_ERROR_CTX_NOT_INITIALIZED, /**< FKO Context is not initialized*/
    FKO_ERROR_MEMORY_ALLOCATION, /**< Unable to allocate memory*/
    FKO_ERROR_FILESYSTEM_OPERATION, /**< Read/write bytes mismatch*/

    /* Invalid data errors */
    FKO_ERROR_INVALID_DATA, /**< Args contain invalid data*/
    FKO_ERROR_INVALID_DATA_CLIENT_TIMEOUT_NEGATIVE, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_CLIENT_TIMEOUT_NEGATIVE*/
    FKO_ERROR_INVALID_DATA_DECODE_MSGLEN_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_MSGLEN_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_DECODE_NON_ASCII, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_NON_ASCII*/
    FKO_ERROR_INVALID_DATA_DECODE_LT_MIN_FIELDS, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_LT_MIN_FIELDS*/
    FKO_ERROR_INVALID_DATA_DECODE_GT_MAX_FIELDS, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_GT_MAX_FIELDS*/
    FKO_ERROR_INVALID_DATA_DECODE_WRONG_NUM_FIELDS, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_WRONG_NUM_FIELDS*/
    FKO_ERROR_INVALID_DATA_DECODE_ENC_MSG_LEN_MT_T_SIZE, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_ENC_MSG_LEN_MT_T_SIZE*/
    FKO_ERROR_INVALID_DATA_DECODE_RAND_MISSING, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_RAND_MISSING*/
    FKO_ERROR_INVALID_DATA_DECODE_USERNAME_MISSING, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_USERNAME_MISSING*/
    FKO_ERROR_INVALID_DATA_DECODE_USERNAME_TOOBIG, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_USERNAME_TOOBIG*/
    FKO_ERROR_INVALID_DATA_DECODE_USERNAME_DECODEFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_USERNAME_DECODEFAIL*/
    FKO_ERROR_INVALID_DATA_DECODE_USERNAME_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_USERNAME_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_DECODE_TIMESTAMP_MISSING, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_TIMESTAMP_MISSING*/
    FKO_ERROR_INVALID_DATA_DECODE_TIMESTAMP_TOOBIG, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_TIMESTAMP_TOOBIG*/
    FKO_ERROR_INVALID_DATA_DECODE_TIMESTAMP_DECODEFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_TIMESTAMP_DECODEFAIL*/
    FKO_ERROR_INVALID_DATA_DECODE_VERSION_MISSING, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_VERSION_MISSING*/
    FKO_ERROR_INVALID_DATA_DECODE_VERSION_TOOBIG, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_VERSION_TOOBIG*/
    FKO_ERROR_INVALID_DATA_DECODE_MSGTYPE_MISSING, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_MSGTYPE_MISSING*/
    FKO_ERROR_INVALID_DATA_DECODE_MSGTYPE_TOOBIG, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_MSGTYPE_TOOBIG*/
    FKO_ERROR_INVALID_DATA_DECODE_MSGTYPE_DECODEFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_MSGTYPE_DECODEFAIL*/
    FKO_ERROR_INVALID_DATA_DECODE_MESSAGE_MISSING, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_MESSAGE_MISSING*/
    FKO_ERROR_INVALID_DATA_DECODE_MESSAGE_TOOBIG, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_MESSAGE_TOOBIG*/
    FKO_ERROR_INVALID_DATA_DECODE_MESSAGE_DECODEFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_MESSAGE_DECODEFAIL*/
    FKO_ERROR_INVALID_DATA_DECODE_MESSAGE_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_MESSAGE_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_DECODE_ACCESS_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_ACCESS_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_DECODE_NATACCESS_MISSING, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_NATACCESS_MISSING*/
    FKO_ERROR_INVALID_DATA_DECODE_NATACCESS_TOOBIG, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_NATACCESS_TOOBIG*/
    FKO_ERROR_INVALID_DATA_DECODE_NATACCESS_DECODEFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_NATACCESS_DECODEFAIL*/
    FKO_ERROR_INVALID_DATA_DECODE_NATACCESS_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_NATACCESS_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_DECODE_SRVAUTH_MISSING, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_SRVAUTH_MISSING*/
    FKO_ERROR_INVALID_DATA_DECODE_SRVAUTH_DECODEFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_SRVAUTH_DECODEFAIL*/
    FKO_ERROR_INVALID_DATA_DECODE_SPA_EXTRA_TOOBIG, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_SPA_EXTRA_TOOBIG*/
    FKO_ERROR_INVALID_DATA_DECODE_EXTRA_TOOBIG, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_EXTRA_TOOBIG*/
    FKO_ERROR_INVALID_DATA_DECODE_EXTRA_DECODEFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_EXTRA_DECODEFAIL*/
    FKO_ERROR_INVALID_DATA_DECODE_TIMEOUT_MISSING, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_TIMEOUT_MISSING*/
    FKO_ERROR_INVALID_DATA_DECODE_TIMEOUT_TOOBIG, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_TIMEOUT_TOOBIG*/
    FKO_ERROR_INVALID_DATA_DECODE_TIMEOUT_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_TIMEOUT_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_DECODE_TIMEOUT_DECODEFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_DECODE_TIMEOUT_DECODEFAIL*/
    FKO_ERROR_INVALID_DATA_ENCODE_MESSAGE_TOOBIG, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCODE_MESSAGE_TOOBIG*/
    FKO_ERROR_INVALID_DATA_ENCODE_MSGLEN_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCODE_MSGLEN_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_ENCODE_DIGEST_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCODE_DIGEST_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_ENCODE_DIGEST_TOOBIG, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCODE_DIGEST_TOOBIG*/
    FKO_ERROR_INVALID_DATA_ENCODE_NOTBASE64, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCODE_NOTBASE64*/
    FKO_ERROR_INVALID_DATA_ENCRYPT_MSGLEN_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCRYPT_MSGLEN_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_ENCRYPT_DIGESTLEN_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCRYPT_DIGESTLEN_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_ENCRYPT_PTLEN_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCRYPT_PTLEN_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_ENCRYPT_RESULT_MSGLEN_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCRYPT_RESULT_MSGLEN_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_ENCRYPT_CIPHERLEN_DECODEFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCRYPT_CIPHERLEN_DECODEFAIL*/
    FKO_ERROR_INVALID_DATA_ENCRYPT_CIPHERLEN_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCRYPT_CIPHERLEN_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_ENCRYPT_DECRYPTED_MESSAGE_MISSING, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCRYPT_DECRYPTED_MESSAGE_MISSING*/
    FKO_ERROR_INVALID_DATA_ENCRYPT_DECRYPTED_MSGLEN_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCRYPT_DECRYPTED_MSGLEN_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_MESSAGE_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_MESSAGE_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_DIGEST_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_DIGEST_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_MSGLEN_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_MSGLEN_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_RESULT_MSGLEN_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_RESULT_MSGLEN_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_CIPHER_DECODEFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_CIPHER_DECODEFAIL*/
    FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_ENCODEDMSG_NULL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_ENCODEDMSG_NULL*/
    FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_ENCODEDMSGLEN_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCRYPT_GPG_ENCODEDMSGLEN_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_ENCRYPT_TYPE_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCRYPT_TYPE_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_ENCRYPT_MODE_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCRYPT_MODE_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_ENCRYPT_TYPE_UNKNOWN, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_ENCRYPT_TYPE_UNKNOWN*/
    FKO_ERROR_INVALID_DATA_FUNCS_NEW_ENCMSG_MISSING, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_FUNCS_NEW_ENCMSG_MISSING*/
    FKO_ERROR_INVALID_DATA_FUNCS_NEW_MSGLEN_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_FUNCS_NEW_MSGLEN_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_FUNCS_GEN_KEYLEN_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_FUNCS_GEN_KEYLEN_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_FUNCS_GEN_HMACLEN_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_FUNCS_GEN_HMACLEN_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_FUNCS_GEN_KEY_ENCODEFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_FUNCS_GEN_KEY_ENCODEFAIL*/
    FKO_ERROR_INVALID_DATA_FUNCS_GEN_HMAC_ENCODEFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_FUNCS_GEN_HMAC_ENCODEFAIL*/
    FKO_ERROR_INVALID_DATA_FUNCS_SET_MSGLEN_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_FUNCS_SET_MSGLEN_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_HMAC_MSGLEN_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_HMAC_MSGLEN_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_HMAC_ENCMSGLEN_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_HMAC_ENCMSGLEN_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_HMAC_COMPAREFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_HMAC_COMPAREFAIL*/
    FKO_ERROR_INVALID_DATA_HMAC_TYPE_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_HMAC_TYPE_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_HMAC_LEN_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_HMAC_LEN_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_MESSAGE_PORT_MISSING, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_MESSAGE_PORT_MISSING*/
    FKO_ERROR_INVALID_DATA_MESSAGE_TYPE_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_MESSAGE_TYPE_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_MESSAGE_EMPTY, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_MESSAGE_EMPTY*/
    FKO_ERROR_INVALID_DATA_MESSAGE_CMD_MISSING, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_MESSAGE_CMD_MISSING*/
    FKO_ERROR_INVALID_DATA_MESSAGE_ACCESS_MISSING, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_MESSAGE_ACCESS_MISSING*/
    FKO_ERROR_INVALID_DATA_MESSAGE_NAT_MISSING, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_MESSAGE_NAT_MISSING*/
    FKO_ERROR_INVALID_DATA_MESSAGE_PORTPROTO_MISSING, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_MESSAGE_PORTPROTO_MISSING*/
    FKO_ERROR_INVALID_DATA_NAT_EMPTY, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_NAT_EMPTY*/
    FKO_ERROR_INVALID_DATA_RAND_LEN_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_RAND_LEN_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_SRVAUTH_MISSING, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_SRVAUTH_MISSING*/
    FKO_ERROR_INVALID_DATA_TIMESTAMP_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_TIMESTAMP_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_USER_MISSING, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_USER_MISSING*/
    FKO_ERROR_INVALID_DATA_USER_FIRSTCHAR_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_USER_FIRSTCHAR_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_USER_REMCHAR_VALIDFAIL, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_USER_REMCHAR_VALIDFAIL*/
    FKO_ERROR_INVALID_DATA_UTIL_STRTOL_LT_MIN, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_UTIL_STRTOL_LT_MIN*/
    FKO_ERROR_INVALID_DATA_UTIL_STRTOL_GT_MAX, /**< Args contain invalid data: FKO_ERROR_INVALID_DATA_UTIL_STRTOL_GT_MAX*/

    FKO_ERROR_DATA_TOO_LARGE, /**< Value or Size of the data exceeded the max allowed*/
    FKO_ERROR_INVALID_KEY_LEN, /**< Invalid key length*/
    FKO_ERROR_USERNAME_UNKNOWN, /**< Unable to determine username*/
    FKO_ERROR_INCOMPLETE_SPA_DATA, /**< Missing or incomplete SPA data*/
    FKO_ERROR_MISSING_ENCODED_DATA, /**< There is no encoded data to process*/
    FKO_ERROR_INVALID_DIGEST_TYPE, /**< Invalid digest type*/
    FKO_ERROR_INVALID_ALLOW_IP, /**< Invalid allow IP address in the SPA message data*/
    FKO_ERROR_INVALID_SPA_COMMAND_MSG, /**< Invalid SPA command message format*/
    FKO_ERROR_INVALID_SPA_ACCESS_MSG, /**< Invalid SPA access message format*/
    FKO_ERROR_INVALID_SPA_NAT_ACCESS_MSG, /**< Invalid SPA nat_access message format*/
    FKO_ERROR_INVALID_ENCRYPTION_TYPE, /**< Invalid encryption type*/
    FKO_ERROR_WRONG_ENCRYPTION_TYPE, /**< Wrong or inappropriate encryption type for this operation*/
    FKO_ERROR_DECRYPTION_SIZE, /**< Unexpected or invalid size for decrypted data*/
    FKO_ERROR_DECRYPTION_FAILURE, /**< Decryption failed or decrypted data is invalid*/
    FKO_ERROR_DIGEST_VERIFICATION_FAILED, /**< The computed digest did not match the digest in the spa data*/
    FKO_ERROR_INVALID_HMAC_KEY_LEN, /**< Invalid HMAC key length*/
    FKO_ERROR_UNSUPPORTED_HMAC_MODE, /**< Unsupported HMAC mode (default: SHA256)*/
    FKO_ERROR_UNSUPPORTED_FEATURE, /**< Unsupported or unimplemented feature or function*/
    FKO_ERROR_ZERO_OUT_DATA, /**< Could not zero out sensitive data*/
    FKO_ERROR_UNKNOWN, /**< Unknown/Unclassified error*/

    /* Start GPGME-related errors (NOTE: Do not put non-GPG-related error
     * below this point).
    */
    GPGME_ERR_START, /**< Not a real error, marker for start of GPG errors*/
    FKO_ERROR_MISSING_GPG_KEY_DATA, /**< Missing GPG key data (signer or recipient not set)*/
    FKO_ERROR_GPGME_NO_OPENPGP, /**< This GPGME implementation does not support OpenPGP*/
    FKO_ERROR_GPGME_CONTEXT, /**< Unable to create GPGME context*/
    FKO_ERROR_GPGME_PLAINTEXT_DATA_OBJ, /**< Error creating the plaintext data object*/
    FKO_ERROR_GPGME_SET_PROTOCOL, /**< Unable to set GPGME to use OpenPGP protocol*/
    FKO_ERROR_GPGME_CIPHER_DATA_OBJ, /**< Error creating the encrypted data data object*/
    FKO_ERROR_GPGME_BAD_PASSPHRASE, /**< The GPG passphrase was not valid*/
    FKO_ERROR_GPGME_ENCRYPT_SIGN, /**< Error during the encrypt and sign operation*/
    FKO_ERROR_GPGME_CONTEXT_SIGNER_KEY, /**< Unable to create GPGME context for the signer key*/
    FKO_ERROR_GPGME_SIGNER_KEYLIST_START, /**< Error from signer keylist start operation*/
    FKO_ERROR_GPGME_SIGNER_KEY_NOT_FOUND, /**< The key for the given signer was not found*/
    FKO_ERROR_GPGME_SIGNER_KEY_AMBIGUOUS, /**< Ambiguous name/id for the signer key (multiple matches)*/
    FKO_ERROR_GPGME_ADD_SIGNER, /**< Error adding the signer key to the gpgme context*/
    FKO_ERROR_GPGME_CONTEXT_RECIPIENT_KEY, /**< Unable to create GPGME context for the recipient key*/
    FKO_ERROR_GPGME_RECIPIENT_KEYLIST_START, /**< Error from signer keylist start operation*/
    FKO_ERROR_GPGME_RECIPIENT_KEY_NOT_FOUND, /**< The key for the given recipient was not found*/
    FKO_ERROR_GPGME_RECIPIENT_KEY_AMBIGUOUS, /**< Ambiguous name/id for the recipient key (multiple matches)*/
    FKO_ERROR_GPGME_DECRYPT_FAILED, /**< Decryption operation failed*/
    FKO_ERROR_GPGME_DECRYPT_UNSUPPORTED_ALGORITHM, /**< Decryption operation failed due to unsupported algorithm*/
    FKO_ERROR_GPGME_BAD_GPG_EXE, /**< Unable to stat the given GPG executable*/
    FKO_ERROR_GPGME_BAD_HOME_DIR, /**< Unable to stat the given GPG home directory*/
    FKO_ERROR_GPGME_SET_HOME_DIR, /**< Unable to set the given GPG home directory*/
    FKO_ERROR_GPGME_NO_SIGNATURE, /**< Missing GPG signature*/
    FKO_ERROR_GPGME_BAD_SIGNATURE, /**< Bad GPG signature*/
    FKO_ERROR_GPGME_SIGNATURE_VERIFY_DISABLED, /**< Trying to check signature with verification disabled*/

    FKO_LAST_ERROR /**< Not a real error, must be last of enum*/
} fko_error_codes_t;

/** Macro that returns true if the given error code is a gpg-related error.
*/
#define IS_GPG_ERROR(x) (x > GPGME_ERR_START && x < FKO_LAST_ERROR)

/* General Defaults
*/
#define FKO_DEFAULT_MSG_TYPE     FKO_ACCESS_MSG
#define FKO_DEFAULT_DIGEST       FKO_DIGEST_SHA256
#define FKO_DEFAULT_ENCRYPTION   FKO_ENCRYPTION_RIJNDAEL
#define FKO_DEFAULT_ENC_MODE     FKO_ENC_MODE_CBC
#define FKO_DEFAULT_KEY_LEN      0
#define FKO_DEFAULT_HMAC_KEY_LEN 0
#define FKO_DEFAULT_HMAC_MODE    FKO_HMAC_SHA256

/* Define the consistent prefixes or salt on some encryption schemes.
*/
#define B64_RIJNDAEL_SALT "U2FsdGVkX1"
#define B64_RIJNDAEL_SALT_STR_LEN 10

#define B64_GPG_PREFIX "hQ"
#define B64_GPG_PREFIX_STR_LEN 2

/* Specify whether libfko is allowed to call exit()
*/
#define EXIT_UPON_ERR 1
#define NO_EXIT_UPON_ERR 0

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

/* General API calls
*/

/**
 * \brief Initialize a new FKO context
 *
 * This function initializes an FKO context, and sets some default values.
 * The FKO context must first be declared, ex: fko_ctx_t   ctx;
 * The pointer to the context should then be passed into fko_new.
 *
 * \param ctx Pointer to the FKO context to be initialized
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise.
 */
DLL_API int fko_new(fko_ctx_t *ctx);


/**
 * \brief Initialize a new FKO context with data
 *
 * The function 'fko_new_with_data' sets up and initializes a new
 * 'fko_ctx_t' context, but instead of initializing default values, it
 * stores the encrypted message data and makes it ready for parsing.
 * This can be done in one of two ways.  One is to pass 'NULL' for the
 * third argument.  The context will be created and the data will be
 * stored, but no decryption or decoding takes place.  In this case,
 * you will need to call 'fko_decrypt_spa_data' at a later time.  The
 * other way to do it is to supply the KEY value (decryption
 * passphrase) and assocated length.  In this case, the context is
 * created, the SPA data is decrypted, decoded, parsed, and stored in
 * the context ready for retrieval.  If an HMAC is also desired or
 * required, then the HMAC_KEY and associated length can be passed in.
 * This will cause libfko to authenticate the SPA data before
 * decryption is attempted, and this is strongly recommended to do.
 *
 * \param ctx Pointer to the FKO context to be initialized
 * \param enc_msg Pointer to the message to be decoded, should be null terminated
 * \param dec_key Pointer to the decryption key.  Expects either text or unsigned char.
 * \param dec_key_len Size of the decryption key.
 * \param encryption_mode Describes the mode of encryption used.  Most common is FKO_ENC_MODE_CBC, which is AES in CBC mode.
 * \param hmac_key This is the pointer to the HMAC key.  Expected to be either text or unsigned char.
 * \param hmac_key_len Size of the HMAC key
 * \param hmac_type Describes which hash function to use for the HMAC.
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise.
 */
DLL_API int fko_new_with_data(fko_ctx_t *ctx, const char * const enc_msg,
    const char * const dec_key, const int dec_key_len, int encryption_mode,
    const char * const hmac_key, const int hmac_key_len, const int hmac_type);

/**
 * \brief Clean up the fko context
 *
 * The function 'fko_destroy' destroys the context with the handle CTX
 * and releases all associated resources.
 *
 * \param Pointer to the context to destroy.
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise.
 */
DLL_API int fko_destroy(fko_ctx_t ctx);

/**
 * \brief Final encoding of SPA data
 *
 * This function is the final step in creating a complete encrypted
 * SPA data string suitable for transmission to an fwknop server.  It
 * does require all of the requisite SPA data fields be set, otherwise
 * it will fail with an appropriate error code.
 *
 * \param ctx The fko context containing the fields to be encoded and encrypted
 * \param enc_key The encryption key to be used
 * \param enc_key_len The size of the encryption key
 * \param hmac_key The HMAC key to be used
 * \param hmac_key_len The size of the HMAC key
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise.
 */
DLL_API int fko_spa_data_final(fko_ctx_t ctx, const char * const enc_key,
    const int enc_key_len, const char * const hmac_key, const int hmac_key_len);

/* Set context data functions
*/

/**
 * \brief Set or Generate random nonce
 *
 * Set the random value portion of the spa data to the given value
 * (VAL).  The given value must be a pointer to a 16-character decimal
 * numeric string or NULL. If the value is NULL, the function generate
 * a new random value.  If a string value is provided, it must be a
 * 16-character decimal string.  Otherwise, the function will return
 * 'FKO_ERROR_INVALID_DATA'.
 *
 * \param ctx The FKO context to modify
 * \param val The 16 digits of random value, may be null
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise.
 */
DLL_API int fko_set_rand_value(fko_ctx_t ctx, const char * const val);

/**
 * \brief Set FKO username
 *
 * Set the username field of the SPA data.  If USERNAME is NULL,
 * libfko will first look for the environment variable 'SPOOF_USER'
 * and use its value if found.  Otherwise, it will try to determine
 * the username itself using various methods starting with 'cuser' or
 * 'getlogin', then fallback to the environment variables 'LOGNAME' or
 * 'USER'.  If none of those work, the function will return
 * 'FKO_ERROR_USERNAME_UNKNOWN'.
 *
 * \param ctx the FKO context to modify
 * \param spoof_user The username to set in the FKO context
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise.
 */
DLL_API int fko_set_username(fko_ctx_t ctx, const char * const spoof_user);

/**
 * \brief Sets the SPA timestamp value.
 *
 * Sets the timestamp value of the SPA data to the current time plus
 * the offset value.  The time is measured in seconds.
 *
 * \param ctx The FKO context to modify
 * \param offset The time offset in seconds.  This value may be negative.
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise.
 */
DLL_API int fko_set_timestamp(fko_ctx_t ctx, const int offset);

/**
 * \brief Sets the message type for the SPA data.
 *
 * \param ctx The FKO context to modify
 * \param ctx msg_type The message type to be set, one of [these options](@ref fko_message_type_t)
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise.
 */
DLL_API int fko_set_spa_message_type(fko_ctx_t ctx, const short msg_type);

/**
 * \brief Set the SPA message string to the given value.
 *
 * If this string does not conform to the required 'spa_nat_access' format, the function
 * will return 'FKO_ERROR_INVALID_DATA'.
 *
 * \param ctx The FKO context to modify
 * \param msg_string The null terminated string to be pushed into the context
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise.
 */
DLL_API int fko_set_spa_message(fko_ctx_t ctx, const char * const msg_string);

/**
 * \brief Set the optional SPA nat access string to the given value.
 *
 * If this string does not conform to the required 'spa_nat_access' format,
 * the function will return 'FKO_ERROR_INVALID_DATA'.
 *
 * \param ctx The FKO context to modify
 * \param nat_access The null terminated string to be pushed into the context
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise.
 */
DLL_API int fko_set_spa_nat_access(fko_ctx_t ctx, const char * const nat_access);

/**
 * \brief Set the optional SPA server auth feature to the given value.
 *
 * This parameter is very seldom used and may become deprecated.
 *
 * \todo finish the function's description
 *
 * \param ctx The FKO context to modify
 * \param server_auth
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise.
 */
DLL_API int fko_set_spa_server_auth(fko_ctx_t ctx, const char * const server_auth);

/**
 * \brief Sets the SPA client timeout value.
 *
 * If the timeout is set to a value greater than 0, it is assumed the
 * 'spa_message_type' setting should be one of the "TIMEOUT" variants.
 * This function will change the 'message_type' to the appropriate setting if necessary.
 * However, it is recommended you set the correct 'message_type' ahead of time.
 *
 * \param ctx The FKO context to modify
 * \param timeout The timeout value in seconds to be pushed into the FKO context
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_set_spa_client_timeout(fko_ctx_t ctx, const int timeout);

/**
 * \brief Set the message digest type.
 *
 *If a value other than the those that are supported is given,
 * the function will return 'FKO_ERROR_INVALID_DATA'.
 *
 * \param ctx The FKO context to modify
 * \param digest_type a message type as defined in [fko_digest_type](@ref fko_digest_type_t).
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_set_spa_digest_type(fko_ctx_t ctx, const short digest_type);

/**
 * \brief Trigger calculation of message digest
 *
 * Initiates a calculation (or recalculation) of the message digest hash for the current
 * SPA data.  If the required data fields are not set this function will return
 * 'FKO_ERROR_MISSING_ENCODED_DATA'.
 * *Note*: It should not be necessary to call this function directly
 * as it will be called automatically by other functions during
 * normal processing (most notably '[fko_spa_data_final](\ref fko_spa_data_final)').
 *
 * \param ctx The FKO context to modify
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_set_spa_digest(fko_ctx_t ctx);

/**
 * \brief set the raw digest type
 *
 * \todo complete documentation for this function
 *
 * \param ctx The FKO context to modify
 * \param raw_digest_type
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_set_raw_spa_digest_type(fko_ctx_t ctx, const short raw_digest_type);

/**
 * \brief set the raw digest
 *
 * \todo complete documentation for this function
 *
 * \param ctx The FKO context to modify
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_set_raw_spa_digest(fko_ctx_t ctx);

/**
 * \brief Set the encrytion algorithm
 *
 * Set the encrytion algorithm to use when ecrypting the final SPA
 * data.  Valid values can be found in [FKO_ENCRYPTION_TYPE_T](\ref FKO_ENCRYPTION_TYPE_T)
 * of this manual.  For example:
 *
 * rc = fko_set_spa_encryption_type(ctx, FKO_ENCRYPTION_RIJNDAEL);
 *
 * \param ctx The FKO context to modify
 * \param the encryption type to use
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_set_spa_encryption_type(fko_ctx_t ctx, const short encrypt_type);

/**
 * \brief Set encryption mode
 *
 * \param ctx The FKO context to modify
 * \param encryption mode, must be one of [fko_encryption_mode_t](\ref fko_encryption_mode_t)
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_set_spa_encryption_mode(fko_ctx_t ctx, const int encrypt_mode);

/**
 * \brief place encrypted SPA data into a newly created empty context
 *
 * This function is used to place encrypted SPA data into a newly
 * created empty context (i.e.  with 'fko_new').  In most cases, you
 * would use 'fko_new_with_data' so you wouldn't have to take the
 * extra step to use this function.  However, some may find a reason
 * to do it in this way.
 *
 * \param ctx The FKO context to modify
 * \param enc_msg The encrypted message to push into the fko context
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_set_spa_data(fko_ctx_t ctx, const char * const enc_msg);

#if AFL_FUZZING
DLL_API int fko_afl_set_spa_data(fko_ctx_t ctx, const char * const enc_msg,
        const int enc_msg_len);
#endif

/**
 * \brief Set the message hmac type.
 *
 * \param ctx The FKO context to modify
 * \param The hmac_type, must be one of [fko_hmac_type_t](\ref fko_hmac_type_t)
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_set_spa_hmac_type(fko_ctx_t ctx, const short hmac_type);

/* Data processing and misc utility functions
*/

/**
 * \brief Return error in string form
 *
 * The function 'fko_errstr' returns a pointer to a statically
 * allocated string containing the description of the error.
 *
 * \param err_code The error code to convert
 *
 * \return Returns a pointer to the error string
 */
DLL_API const char* fko_errstr(const int err_code);

/**
 * \brief Return the assumed encryption type based on the raw encrypted data.
 *
 * \param The encrypted data to process
 *
 * \return Returns a value from [fko_encryption_type_t](\ref fko_encryption_type_t)
 */
DLL_API int fko_encryption_type(const char * const enc_data);

/**
 * \brief generates random keys
 *
 * \param key_base64 pass a pointer into the function to be filled with the generated key
 * \param key_len Length of key to generate, use FKO_DEFAULT_KEY_LEN for default length
 * \param hmac_key_base64 pass a pointer into the function to be filled with the generated hmac key
 * \param hmac_key_len Length of hmac key to generate, use FKO_DEFAULT_HMAC_KEY_LEN for default length
 * \param hmac_type used to determine the default HMAC length, must be one of [fko_hmac_type_t](\ref fko_hmac_type_t)
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_key_gen(char * const key_base64, const int key_len,
        char * const hmac_key_base64, const int hmac_key_len,
        const int hmac_type);

/**
 * \brief Encodes text or binary data into base64
 *
 * Function takes text or binary data and returns a base64 encoded string.
 * This implements base64 encoding as per rfc 4648.
 * (This is not the url safe encoding scheme)
 *
 * \param in Pointer to input data.  May be text or binary data
 * \param out Pointer to the base64 encoded data
 * \param in_length Size in bytes of the input
 *
 * \return Returns length of base64 encoded output
 * \todo add CUnit test of base64 encoding: https://tools.ietf.org/html/rfc4648
 */
DLL_API int fko_base64_encode(unsigned char * const in, char * const out, int in_len);

/**
 * \brief Decodes base64 into text or binary data
 *
 * Function takes a base64 encoded string and returns the resulting text or binary data
 * This implements base64 decoding as per rfc 4648.
 * (This is not the url safe encoding scheme)
 *
 * \param in Pointer to input data.  Must be Base64 encoded
 * \param out Pointer to the resulting data
 *
 * \return Returns length in bytes of decoded output
 * \todo add CUnit test of base64 decoding: https://tools.ietf.org/html/rfc4648
 */
DLL_API int fko_base64_decode(const char * const in, unsigned char *out);


/**
 * \brief Encodes data in SPA context
 *
 * Performs the base64 encoding of those SPA data fields that need to be encoded,
 * performs some data validation, and calls 'fkp_set_spa_digest' to recompute
 * the SPA message digest.  It is normally not called directly as it is called
 * from 'fko_encrypt_spa_data' (which is in turn called from 'fko_spa_data_final').
 *
 * \param ctx The FKO context to process
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_encode_spa_data(fko_ctx_t ctx);

/**
 * \brief Decodes data in an SPA context
 *
 * This function performs the decoding, parsing, validation of the SPA
 * data that was just decrypted.  It is normally not called directly
 * as it is called from 'fko_decrypt_spa_data' (which is in turn
 * called from 'fko_new_with_data' if a password is supplied to it).
 *
 * \param ctx The FKO context to decode
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_decode_spa_data(fko_ctx_t ctx);

/**
 * \brief encrypt the date in the FKO context
 *
 * Encrypts the intermediate encoded SPA data stored in the context.
 * This function will call 'fko_encode' if necessary.  It is normally
 * not called directly as it is called from 'fko_spa_data_final'.
 *
 * \param ctx The FKO context to encrypt
 * \param enc_key The encryption key to use
 * \param enc_key_len the length of the encryption key
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_encrypt_spa_data(fko_ctx_t ctx, const char * const enc_key,
    const int enc_key_len);

/**
 * \brief decrypts and decodes the SPA message
 *
 * When given the correct KEY (password), this function decrypts,
 * decodes, and parses the encrypted SPA data that was supplied to the
 * context via the 'fko_new_with_data' function that was also called
 * without the KEY value.  Once the data is decrypted, this function
 * will also call 'fko_decode_spa_data' to decode, parse, validate,
 * and store the data fields in the context for later retrieval.
 *
 * \param ctx The FKO context to decrypt
 * \param dec_key the key to use when decrypting
 * \param dec_key_len the size of kec_key
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_decrypt_spa_data(fko_ctx_t ctx, const char * const dec_key,
    const int dec_key_len);

/**
 * \brief verifies the HMAC signature for a received message
 *
 * \param ctx The FKO context that has the message loaded
 * \param hmac_key The expected HMAC key to verify
 * \param hmac_key_len The size of hmac_key
 *
 * \return FKO_SUCCESS if the message verifies, returns an error code otherwise
 */
DLL_API int fko_verify_hmac(fko_ctx_t ctx, const char * const hmac_key,
    const int hmac_key_len);

/**
 * \brief Set and calculate the HMAC
 *
 * Initiates a calculation (or recalculation) of the message HMAC for
 * the current SPA data.  *Note*: It should not be necessary to call
 * this function directly as it will be called automatically by other
 * functions during normal processing (most notably 'fko_spa_data_final').
 *
 * \param ctx The FKO context to modify
 * \param hmac_key the HMAC key to use
 * \param hmac_key_len the size of hmac_key
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_set_spa_hmac(fko_ctx_t ctx, const char * const hmac_key,
    const int hmac_key_len);

/**
 * \brief get a pointer to the HMAC value from FKO context
 *
 * Assigns the pointer to the string holding the the fko SPA HMAC value
 * associated with the current context to the address SPA_HMAC is pointing to.
 *
 * \param ctx The FKO context to use
 * \param enc_data Pointer to the pointer to be assigned
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_spa_hmac(fko_ctx_t ctx, char **enc_data);


/**
 * \brief get a pointer to the SPA data
 *
 * Assigns the pointer to the string holding the the encoded SPA data
 * (before encryption) associated with the current context to the
 * address ENC_MSG is pointing to.  This is intermediate data that
 * would not normally be of use unless debugging the library.
 *
 * \param ctx The FKO context to use
 * \param enc_data Pointer to the pointer to be assigned
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_encoded_data(fko_ctx_t ctx, char **enc_data);

#if FUZZING_INTERFACES
DLL_API int fko_set_encoded_data(fko_ctx_t ctx, const char * const encoded_msg,
        const int msg_len, const int do_digest, const int digest_type);
#endif

/* Get context data functions
*/

/**
 * \brief get nonce from FKO context
 *
 * Assigns the pointer to the string holding the random 16-character
 * decimal number ('rand_val') associated with the current context to
 * the address RAND_VAL is pointing to.
 *
 * \param ctx The FKO context to access
 * \param rand_val Pointer to the pointer to be assigned
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_rand_value(fko_ctx_t ctx, char **rand_val);

/**
 * \brief get username from FKO context
 *
 * Assigns the pointer to the string holding the username associated
 * with the current context to the address RAND_VAL is pointing to.
 *
 * \param ctx The FKO context to access
 * \param Pointer to the pointer to be assigned
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_username(fko_ctx_t ctx, char **username);

/**
 * \brief get timestamp from FKO context
 *
 * Sets the value of the TIMESTAMP variable to the timestamp value
 * associated with the current context.
 *
 * \param ctx The FKO context to access
 * \param ts Pointer to variable that will be set to the timestamp
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_timestamp(fko_ctx_t ctx, time_t *ts);

/**
 * \brief get message type from FKO context
 *
 * Sets the value of the MSG_TYPE variable to the SPA message type
 * value associated with the current context.  This value can be
 * checked against the list of valid message_types listed in [fko_message_type_t](\ref fko_message_type_t)
 * For example:
 *
~~~
              short msg_type;

              rc = fko_get_spa_message_type(ctx, &msg_type);

              switch(msg_type)
              {
                  case FKO_ACCESS_MSG:
                      process_access_msg(...);
                      break;
                  case FKO_NAT_ACCESS_MSG:
                      process_nat_access_msg(...);
                      break;
              //...and so on...
              }
~~~
 *
 * \param ctx The FKO context to access
 * \param spa_msg pointer to variable that will be set with the message type value
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_spa_message_type(fko_ctx_t ctx, short *spa_msg);

/**
 * \brief get spa message from FKO context
 *
 * Assigns the pointer to the string holding the the fko SPA request message
 * associated with the current context to the address SPA_MSG is pointing to.
 *
 * \param ctx The FKO context to access
 * \param spa_message Pointer to the pointer to be assigned
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_spa_message(fko_ctx_t ctx, char **spa_message);

/**
 * \brief get nat access string from FKO context
 *
 * Assigns the pointer to the string holding the the fko SPA nat
 * access message associated with the current context to the address
 * NAT_ACCESS is pointing to.
 *
 * \param ctx The FKO context to access
 * \param nat_access Pointer to the pointer to be assigned
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_spa_nat_access(fko_ctx_t ctx, char **nat_access);

/**
 * \brief get server auth string from FKO context
 *
 * Assigns the pointer to the string holding the the fko SPA server
 * auth message associated with the current context to the address
 * SERVER_AUTH is pointing to.
 *
 * \param ctx The FKO context to access
 * \param server_auth Pointer to the pointer to be assigned
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_spa_server_auth(fko_ctx_t ctx, char **server_auth);

/**
 * \brief get client timeout from FKO context
 *
 * Sets the value of the CLIENT_TIMEOUT variable to the client_timeout
 * value associated with the current context.
 *
 * \param ctx The FKO context to access
 * \param client_timeout Pointer to the pointer to be assigned
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_spa_client_timeout(fko_ctx_t ctx, int *client_timeout);

/**
 * \brief get digest type from the FKO context
 *
 * Sets the value of the DIGEST_TYPE variable to the digest type value
 * associated with the current context.  This value can be checked
 * against the list of valid digest_types listed in [fko_digest_type_t] (\ref fko_digest_type_t)
 *
 * \param ctx The FKO context to access
 * \param spa_digest_type pointer to the variable to fill with the digest type
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_spa_digest_type(fko_ctx_t ctx, short *spa_digest_type);

/**
 * \brief get the raw digest type
 *
 * \param ctx The FKO context to access
 * \param raw_spa_digest_type
 *
 * \todo finish documentation for this function
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_raw_spa_digest_type(fko_ctx_t ctx, short *raw_spa_digest_type);

/**
 * \brief get the hmac type from the FKO context
 *
 * Sets the value of the HMAC_TYPE variable to the HMAC type value
 * associated with the current context.  This value can be checked
 * against the list of valid hmac_types listed in [fko_hmac_type_t](\ref fko_hmac_type_t)
 *
 * \param ctx The FKO context to access
 * \param spa_hmac_type pointer to the variable to fill with the hmac type
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_spa_hmac_type(fko_ctx_t ctx, short *spa_hmac_type);

/**
 * \brief get the digest value from the FKO context
 *
 * Assigns the pointer to the string holding the the fko SPA digest
 * value associated with the current context to the address SPA_DIGEST
 * is pointing to.
 *
 * \param ctx The FKO context to access
 * \param spa_digest Pointer to the pointer to be assigned
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_spa_digest(fko_ctx_t ctx, char **spa_digest);

/**
 * \brief get raw spa digest
 *
 * \todo Finish the documentation for this function
 *
 * \param ctx The FKO context to access
 * \param raw_spa_digest Pointer to the pointer to be assigned
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_raw_spa_digest(fko_ctx_t ctx, char **raw_spa_digest);

/**
 * \brief get the encryption type from the SPA context
 *
 * Sets the value of the ENC_TYPE variable to the encryption type
 * value associated with the current context.  This value can be
 * checked against the list of valid encryption types listed in [fko_encryption_type_t](\ref fko_encryption_type_t)
 *
 * \param ctx The FKO context to access
 * \param spa_enc_type pointer to the variable to fill with the encryption type
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_spa_encryption_type(fko_ctx_t ctx, short *spa_enc_type);

/**
 * \brief get the encryption mode from the FKO context
 *
 * Sets the value of the ENC_MODE variable to the encryption mode associated
 * with the current context. This value can be checked against the list of
 * valid encryption modes listed in [fko_encryption_mode_t](\ref fko_encryption_mode_t)
 *
 * \param ctx The FKO context to access
 * \param spa_enc_mode pointer to the variable to fill with the encryption mode
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_spa_encryption_mode(fko_ctx_t ctx, int *spa_enc_mode);

/**
 * \brief get the encrypted SPA data from the SPA context
 *
 * Assigns the pointer to the string holding the final encrypted SPA
 * data to the address SPA_DATA is pointing to.  This is the data that
 * would be packaged into a packet and sent to an fwknop server.
 *
 * \param ctx The FKO context to access
 * \param spa_data Pointer to the pointer to be assigned
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_spa_data(fko_ctx_t ctx, char **spa_data);


/**
 * \brief get SPA version from SPA context
 *
 * Assigns the pointer to the string holding the the SPA version value
 * associated with the current context to the address FKO_VERSION is
 * pointing to.  This is a static value for SPA data that is being
 * created in a new context.  For data parsed from an external source,
 * the version string will be whatever version the sending client used.
 *
 * \param ctx The FKO context to access
 * \param version Pointer to the pointer to be assigned
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_version(fko_ctx_t ctx, char **version);

/* GPG-related functions
*/

/**
 * \brief set the GPG executable
 *
 * Sets the path to the GPG executable that _gpgme_ will use.  By
 * default, _libfko_ forces _gpgme_ to use 'gpg' in case _gpgme_ was
 * compiled to use 'gpg2' as its default engine.  You can use this
 * function to override and set what GPG executable _gpgme_ will use.
 *
 * \param ctx The FKO context to modify
 * \param The path to the GPG executable
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_set_gpg_exe(fko_ctx_t ctx, const char * const gpg_exe);

/**
 * \brief gets the GPG executable from the FKO context
 *
 * Assigns the pointer to the string holding the the GPG executable
 * path associated with the current context to the address GPG_EXE is
 * pointing to.
 *
 * \param ctx The FKO context to access
 * \param gpg_exe Pointer to the pointer to assign to the executable name
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_gpg_exe(fko_ctx_t ctx, char **gpg_exe);


/**
 * \brief set the recipient GPG key
 *
 * Sets the GPG key for the recipient.  This would be the recipient's
 * public key used to encyrpt the SPA data.  You can use the user name
 * ("recip@the.dest.com") or the key ID ("5EXXXXCC"). At present,
 * multiple recipients are not supported.
 *
 * \param ctx The FKO context to modify
 * \param recip The key to set
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_set_gpg_recipient(fko_ctx_t ctx, const char * const recip);

/**
 * \brief get the GPG recipient ID from the FKO context
 *
 * Assigns the pointer to the string holding the the GPG recipient ID
 * associated with the current context to the address RECIPIENT is
 * pointing to.
 *
 * \param  ctx The FKO context to access
 * \param Pointer to the pointer to assign the value
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_gpg_recipient(fko_ctx_t ctx, char **recip);

/**
 * \brief Set the GPG signing key
 *
 * Sets the GPG key for signing the data.  This would be the sender's
 * key used to sign the SPA data.  You can use the user name or key
 * ID.
 *
 * \param ctx The FKO context to modify
 * \param The GPG key to use for signing
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_set_gpg_signer(fko_ctx_t ctx, const char * const signer);

/**
 * \brief Get the GPG signing key
 *
 * Assigns the pointer to the string holding the the GPG signer ID
 * associated with the current context to the address SIGNER is
 * pointing to.
 *
 * \param ctx The FKO context to access
 * \param signer pointer to the pointer to assign the value
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_gpg_signer(fko_ctx_t ctx, char **signer);

/**
 * \brief set the GPG home directory
 *
 * Sets the GPG home directory for the current gpgme context.  This
 * allows for using alternate keyrings, gpg configurations, etc.
 *
 * \param ctx The FKO context to modify
 * \param gpg_home_dir The path to set
 *
 * \return
 */
DLL_API int fko_set_gpg_home_dir(fko_ctx_t ctx, const char * const gpg_home_dir);

/**
 * \brief get the GPG home directory from the FKO context
 *
 * Assigns the pointer to the string holding the the GPG home
 * directory associated with the current context to the address
 * GPG_DIR is pointing to.
 *
 * \param ctx The FKO context to access
 * \param gpg_home_dir Pointer to the pointer to assign the value
 *
 * \return
 */
DLL_API int fko_get_gpg_home_dir(fko_ctx_t ctx, char **gpg_home_dir);


/**
 * \brief gets the text value of the current gpg error
 *
 * \param ctx The FKO context to access
 *
 * \return Returns the gpg error string
 */
DLL_API const char* fko_gpg_errstr(fko_ctx_t ctx);


/**
 * \brief Set the GPG verify signature flag
 *
 * Sets the verify GPG signature flag.  When set to a true value, the
 * GPG signature is extracted and checked for validity during the
 * decryption/decoding phase.  When set to false, no attempt is made
 * to access or check the signature.  This flag is set to true by default.
 *
 * \param ctx The FKO context to modify
 * \param val Set TRUE or FALSE to set flag
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_set_gpg_signature_verify(fko_ctx_t ctx,
    const unsigned char val);

/**
 * \brief Get the value of the GPG signature verify flag
 *
 * Sets the value of the VAL variable to the current
 * gpg_signature_verify flag value associated with the current
 * context.
 *
 * \param ctx The FKO context to access
 * \param Pointer where flag value will be set
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_gpg_signature_verify(fko_ctx_t ctx,
    unsigned char * const val);

/**
 * \brief set ignore signature verify error flag
 *
 * Sets the ignore signature verify error flag.  When set to a true
 * value.  Any signature verification errors are ignored (but still
 * captured) and the decoding process will continue.  The default
 * value of this flag is false.
 *
 * \param ctx The FKO context to modify
 * \param val Set TRUE or FALSE to set the flag
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_set_gpg_ignore_verify_error(fko_ctx_t ctx,
    const unsigned char val);

/**
 * \brief get the ignore_verify_error flag
 *
 * Sets the value of the VAL variable to the current
 * ignore_verify_error flag value associated with the current context.
 *
 * \param ctx The FKO context to access
 * \param val Pointer where the flag value will be set
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_gpg_ignore_verify_error(fko_ctx_t ctx,
    unsigned char * const val);


/**
 * \brief get GPG signature id
 *
 * Assigns the pointer to the string holding the the GPG signature ID
 * associated with the current context to the address SIG_ID is
 * pointing to.
 *
 * \param ctx The FKO context to access
 * \param Pointer to the pointer where to set the value
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_gpg_signature_id(fko_ctx_t ctx, char **sig_id);

/**
 * \brief get GPG signature fingerprint
 *
 * Assigns the pointer to the string holding the the GPG signature
 * fingerprint associated with the current context to the address
 * SIG_FPR is pointing to.
 *
 * \param ctx The FKO context to access
 * \param sig_fpr Pointer to the pointer where to set the value
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_gpg_signature_fpr(fko_ctx_t ctx, char **sig_fpr);

/**
 * \brief get GPG signature summary
 *
 * Sets the value of the SIG_SUM variable to the GPG signature summary
 * value associated with the current context.
 *
 * \param ctx The FKO context to access
 * \param sigsum Pointer where to set the summary
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_gpg_signature_summary(fko_ctx_t ctx, int *sigsum);

/**
 * \brief get the SIG_STAT
 *
 * Sets the value of the SIG_STAT variable to the GPG signature error
 * status value associated with the current context.
 *
 * \param ctx The FKO context to access
 * \param sigstat The pointer where to set the status
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_get_gpg_signature_status(fko_ctx_t ctx, int *sigstat);


/**
 * \brief Query whether IDs match
 *
 * Sets the value of the ID_MATCH variable to true (1) if the value of
 * ID matches the ID of the GPG signature associated with the current
 * context.  Otherwise, ID_MATCH is set to false (0).
 *
 * \param ctx The FKO context to access
 * \param id The id to compare
 * \param result Pointer where the result is stored
 *
 * \return  FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_gpg_signature_id_match(fko_ctx_t ctx, const char * const id,
    unsigned char * const result);

/**
 * \brief Compare GPG fingerprints
 *
 * Sets the value of the FPR_MATCH variable to true (1) if the value
 * of FPR matches the fingerprint of the GPG signature associated with
 * the current context.  Otherwise, FPR_MATCH is set to false (0).
 *
 * \param ctx The FKO context to access
 * \param fpr The fingerprint to compare
 * \param result Pointer where the result is stored
 *
 * \return FKO_SUCCESS if successful, returns an error code otherwise
 */
DLL_API int fko_gpg_signature_fpr_match(fko_ctx_t ctx, const char * const fpr,
    unsigned char * const result);

#ifdef __cplusplus
}
#endif

#ifdef HAVE_C_UNIT_TESTS
int register_ts_fko_decode(void);
int register_ts_hmac_test(void);
int register_ts_digest_test(void);
int register_ts_aes_test(void);
int register_utils_test(void);
int register_base64_test(void);
#endif

#endif /* FKO_H */

/***EOF***/
