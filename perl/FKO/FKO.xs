#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <fko.h>

/* Global FKO error code var
*/
int g_ec;

MODULE = FKO		PACKAGE = FKO		

PROTOTYPES: DISABLE

# This call is used only for the global g_ec error value
# during initialization (in case object instantiation fails).
#
char*
error_str()
    CODE:
    RETVAL = (char*)fko_errstr(g_ec);
    OUTPUT:
    RETVAL

# 
# All of the remaining functions are wrappers for the
# libfko calls.  These are, in turn, wrapped/called from
# the FKO.pm module methods.
#

fko_ctx_t
_init_ctx()
    INIT:
    fko_ctx_t ctx;
    CODE:
    g_ec = fko_new(&ctx);
    if(g_ec == 0)
        RETVAL = ctx;
    else
        RETVAL = NULL;
    OUTPUT:
    RETVAL

fko_ctx_t
_init_ctx_with_data(enc_msg, dec_key, dec_key_len, enc_mode, hmac_key, hmac_key_len)
    INPUT:
    char*   enc_msg;
    char*   dec_key;
    int     dec_key_len;
    int     enc_mode;
    char*   hmac_key;
    int     hmac_key_len;
    INIT:
    fko_ctx_t ctx;
    CODE:
    g_ec = fko_new_with_data(&ctx, enc_msg, dec_key, dec_key_len, enc_mode, hmac_key, hmac_key_len);
    if(g_ec == 0)
        RETVAL = ctx;
    else
        RETVAL = NULL;
    OUTPUT:
    RETVAL

fko_ctx_t
_init_ctx_with_data_only(data)
    INPUT:
    char*   data;
    INIT:
    fko_ctx_t ctx;
    CODE:
    g_ec = fko_new_with_data(&ctx, data, NULL, 0, FKO_ENCRYPTION_RIJNDAEL, NULL, 0);
    if(g_ec == 0)
        RETVAL = ctx;
    else
        RETVAL = NULL;
    OUTPUT:
    RETVAL

void
_destroy_ctx(ctx)
    INPUT:
    fko_ctx_t ctx;
    CODE:
    fko_destroy(ctx);

int
_version(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    char *val;
    CODE:
    val = NULL;
    RETVAL = fko_get_version(ctx, &val);
    OUTPUT:
    val
    RETVAL

const char*
_error_str(err_code)
    INPUT:
    int     err_code;
    CODE:
    RETVAL = fko_errstr(err_code);
    OUTPUT:
    RETVAL

const char*
_gpg_error_str(ctx)
    INPUT:
    fko_ctx_t ctx;
    CODE:
    RETVAL = fko_gpg_errstr(ctx);
    OUTPUT:
    RETVAL

int
_set_digest_type(ctx, digest_type)
    INPUT:
    fko_ctx_t ctx;
    short    digest_type;
    CODE:
    RETVAL = fko_set_spa_digest_type(ctx, digest_type);
    OUTPUT:
    RETVAL

int
_get_digest_type(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    short val
    CODE:
    RETVAL = fko_get_spa_digest_type(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_set_encryption_type(ctx, encryption_type)
    INPUT:
    fko_ctx_t ctx;
    short    encryption_type;
    CODE:
    RETVAL = fko_set_spa_encryption_type(ctx, encryption_type);
    OUTPUT:
    RETVAL

int
_get_encryption_type(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    short val
    CODE:
    RETVAL = fko_get_spa_encryption_type(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_set_hmac_mode(ctx, hmac_mode)
    INPUT:
    fko_ctx_t ctx;
    short    hmac_mode;
    CODE:
    RETVAL = fko_set_hmac_mode(ctx, hmac_mode);
    OUTPUT:
    RETVAL

int
_set_rand_value(ctx, rand_val)
    INPUT:
    fko_ctx_t ctx;
    char*   rand_val;
    CODE:
    RETVAL = fko_set_rand_value(ctx, rand_val);
    OUTPUT:
    RETVAL

int
_get_rand_value(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    char *val;
    CODE:
    RETVAL = fko_get_rand_value(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_set_username(ctx, username)
    INPUT:
    fko_ctx_t   ctx;
    char*       username;
    CODE:
    RETVAL = fko_set_username(ctx, username);
    OUTPUT:
    RETVAL

int
_get_username(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    char *val;
    CODE:
    RETVAL = fko_get_username(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_set_spa_message_type(ctx, spa_message_type)
    INPUT:
    fko_ctx_t ctx;
    int     spa_message_type;
    CODE:
    RETVAL = fko_set_spa_message_type(ctx, spa_message_type);
    OUTPUT:
    RETVAL

int
_get_spa_message_type(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    short val;
    CODE:
    RETVAL = fko_get_spa_message_type(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_set_timestamp(ctx, offset)
    INPUT:
    fko_ctx_t ctx;
    int offset;
    CODE:
    RETVAL = fko_set_timestamp(ctx, offset);
    OUTPUT:
    RETVAL

int
_get_timestamp(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    time_t val;
    CODE:
    RETVAL = fko_get_timestamp(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_set_spa_message(ctx, spa_message)
    INPUT:
    fko_ctx_t ctx;
    char*   spa_message;
    CODE:
    RETVAL = fko_set_spa_message(ctx, spa_message);
    OUTPUT:
    RETVAL

int
_get_spa_message(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    char *val;
    CODE:
    RETVAL = fko_get_spa_message(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_set_spa_nat_access(ctx, spa_nat_access)
    INPUT:
    fko_ctx_t ctx;
    char*   spa_nat_access;
    CODE:
    RETVAL = fko_set_spa_nat_access(ctx, spa_nat_access);
    OUTPUT:
    RETVAL

int
_get_spa_nat_access(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    char *val;
    CODE:
    RETVAL = fko_get_spa_nat_access(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_set_spa_server_auth(ctx, spa_server_auth)
    INPUT:
    fko_ctx_t ctx;
    char*   spa_server_auth;
    CODE:
    RETVAL = fko_set_spa_server_auth(ctx, spa_server_auth);
    OUTPUT:
    RETVAL

int
_get_spa_server_auth(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    char *val;
    CODE:
    RETVAL = fko_get_spa_server_auth(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_set_spa_client_timeout(ctx, spa_client_timeout)
    INPUT:
    fko_ctx_t ctx;
    int   spa_client_timeout;
    CODE:
    RETVAL = fko_set_spa_client_timeout(ctx, spa_client_timeout);
    OUTPUT:
    RETVAL

int
_get_spa_client_timeout(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    int val;
    CODE:
    RETVAL = fko_get_spa_client_timeout(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_set_spa_digest(ctx)
    INPUT:
    fko_ctx_t ctx;
    CODE:
    RETVAL = fko_set_spa_digest(ctx);
    OUTPUT:
    RETVAL

int
_get_spa_digest(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    char *val;
    CODE:
    RETVAL = fko_get_spa_digest(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_set_spa_data(ctx, spa_data)
    INPUT:
    fko_ctx_t ctx;
    char*   spa_data;
    CODE:
    RETVAL = fko_set_spa_data(ctx, spa_data);
    OUTPUT:
    RETVAL

int
_get_spa_data(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    char *val;
    CODE:
    RETVAL = fko_get_spa_data(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_set_gpg_recipient(ctx, gpg_recipient)
    INPUT:
    fko_ctx_t ctx;
    char*   gpg_recipient;
    CODE:
    RETVAL = fko_set_gpg_recipient(ctx, gpg_recipient);
    OUTPUT:
    RETVAL

int
_get_gpg_recipient(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    char *val;
    CODE:
    RETVAL = fko_get_gpg_recipient(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_set_gpg_signer(ctx, gpg_signer)
    INPUT:
    fko_ctx_t ctx;
    char*   gpg_signer;
    CODE:
    RETVAL = fko_set_gpg_signer(ctx, gpg_signer);
    OUTPUT:
    RETVAL

int
_get_gpg_signer(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    char *val;
    CODE:
    RETVAL = fko_get_gpg_signer(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_set_gpg_home_dir(ctx, gpg_home_dir)
    INPUT:
    fko_ctx_t ctx;
    char*   gpg_home_dir;
    CODE:
    RETVAL = fko_set_gpg_home_dir(ctx, gpg_home_dir);
    OUTPUT:
    RETVAL

int
_get_gpg_home_dir(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    char *val;
    CODE:
    RETVAL = fko_get_gpg_home_dir(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_set_gpg_signature_verify(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    unsigned char val;
    CODE:
    RETVAL = fko_set_gpg_signature_verify(ctx, val);
    OUTPUT:
    RETVAL

int
_get_gpg_signature_verify(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    unsigned char val;
    CODE:
    RETVAL = fko_get_gpg_signature_verify(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_set_gpg_ignore_verify_error(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    unsigned char val;
    CODE:
    RETVAL = fko_set_gpg_ignore_verify_error(ctx, val);
    OUTPUT:
    RETVAL

int
_get_gpg_ignore_verify_error(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    unsigned char val;
    CODE:
    RETVAL = fko_get_gpg_ignore_verify_error(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_get_gpg_signature_id(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    char *val;
    CODE:
    RETVAL = fko_get_gpg_signature_id(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_get_gpg_signature_fpr(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    char *val;
    CODE:
    RETVAL = fko_get_gpg_signature_fpr(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_get_gpg_signature_summary(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    int val;
    CODE:
    RETVAL = fko_get_gpg_signature_summary(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_get_gpg_signature_status(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    int val;
    CODE:
    RETVAL = fko_get_gpg_signature_status(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_gpg_signature_id_match(ctx, id, val)
    INPUT:
    fko_ctx_t ctx;
    char *id;
    unsigned char val;
    CODE:
    RETVAL = fko_gpg_signature_id_match(ctx, id, &val);
    OUTPUT:
    val
    RETVAL

int
_gpg_signature_fpr_match(ctx, fpr, val)
    INPUT:
    fko_ctx_t ctx;
    char *fpr;
    unsigned char val;
    CODE:
    RETVAL = fko_gpg_signature_fpr_match(ctx, fpr, &val);
    OUTPUT:
    val
    RETVAL

int
_get_encoded_data(ctx, val)
    INPUT:
    fko_ctx_t ctx;
    char *val;
    CODE:
    RETVAL = fko_get_encoded_data(ctx, &val);
    OUTPUT:
    val
    RETVAL

int
_spa_data_final(ctx, enc_key, enc_key_len, hmac_key, hmac_key_len)
    INPUT:
    fko_ctx_t ctx;
    char*   enc_key;
    int     enc_key_len;
    char*   hmac_key;
    int     hmac_key_len;
    CODE:
    RETVAL = fko_spa_data_final(ctx, enc_key, enc_key_len, hmac_key, hmac_key_len);
    OUTPUT:
    RETVAL

int
_decrypt_spa_data(ctx, dec_key, dec_key_len)
    INPUT:
    fko_ctx_t ctx;
    char*   dec_key;
    int     dec_key_len;
    CODE:
    RETVAL = fko_decrypt_spa_data(ctx, dec_key, dec_key_len);
    OUTPUT:
    RETVAL

int
_encrypt_spa_data(ctx, enc_key, enc_key_len)
    INPUT:
    fko_ctx_t ctx;
    char*   enc_key;
    int     enc_key_len;
    CODE:
    RETVAL = fko_encrypt_spa_data(ctx, enc_key, enc_key_len);
    OUTPUT:
    RETVAL

int
_decode_spa_data(ctx)
    INPUT:
    fko_ctx_t ctx;
    CODE:
    RETVAL = fko_decode_spa_data(ctx);
    OUTPUT:
    RETVAL

int
_encode_spa_data(ctx)
    INPUT:
    fko_ctx_t ctx;
    CODE:
    RETVAL = fko_encode_spa_data(ctx);
    OUTPUT:
    RETVAL

###EOF###
