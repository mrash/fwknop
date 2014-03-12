/*
 *****************************************************************************
 *
 * File:    fkomodule.c
 *
 * Purpose: Python wrapper module for the fwknop library (libfko).
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2014 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *****************************************************************************
*/
#include <Python.h>
#include <fko.h>

/* A lot to figure out yet... */

/* This will be our Error object.
*/
static PyObject *FKOError;

/* FKO context functions.
*/
static PyObject * init_ctx(PyObject *self, PyObject *args);
static PyObject * init_ctx_with_data(PyObject *self, PyObject *args);
static PyObject * destroy_ctx(PyObject *self, PyObject *args);

/* FKO SPA data functions.
*/
static PyObject * get_version(PyObject *self, PyObject *args);
static PyObject * get_rand_value(PyObject *self, PyObject *args);
static PyObject * set_rand_value(PyObject *self, PyObject *args);
static PyObject * get_username(PyObject *self, PyObject *args);
static PyObject * set_username(PyObject *self, PyObject *args);
static PyObject * get_timestamp(PyObject *self, PyObject *args);
static PyObject * set_timestamp(PyObject *self, PyObject *args);
static PyObject * get_spa_digest_type(PyObject *self, PyObject *args);
static PyObject * set_spa_digest_type(PyObject *self, PyObject *args);
static PyObject * get_spa_encryption_type(PyObject *self, PyObject *args);
static PyObject * set_spa_encryption_type(PyObject *self, PyObject *args);
static PyObject * get_spa_message_type(PyObject *self, PyObject *args);
static PyObject * set_spa_message_type(PyObject *self, PyObject *args);

static PyObject * get_spa_message(PyObject *self, PyObject *args);
static PyObject * set_spa_message(PyObject *self, PyObject *args);
static PyObject * get_spa_nat_access(PyObject *self, PyObject *args);
static PyObject * set_spa_nat_access(PyObject *self, PyObject *args);
static PyObject * get_spa_server_auth(PyObject *self, PyObject *args);
static PyObject * set_spa_server_auth(PyObject *self, PyObject *args);
static PyObject * get_spa_client_timeout(PyObject *self, PyObject *args);
static PyObject * set_spa_client_timeout(PyObject *self, PyObject *args);
static PyObject * get_spa_digest(PyObject *self, PyObject *args);
static PyObject * set_spa_digest(PyObject *self, PyObject *args);
static PyObject * get_spa_data(PyObject *self, PyObject *args);
static PyObject * set_spa_data(PyObject *self, PyObject *args);
static PyObject * get_encoded_data(PyObject *self, PyObject *args);

static PyObject * get_raw_spa_digest_type(PyObject *self, PyObject *args);
static PyObject * set_raw_spa_digest_type(PyObject *self, PyObject *args);
static PyObject * get_raw_spa_digest(PyObject *self, PyObject *args);
static PyObject * set_raw_spa_digest(PyObject *self, PyObject *args);
static PyObject * get_spa_encryption_mode(PyObject *self, PyObject *args);
static PyObject * set_spa_encryption_mode(PyObject *self, PyObject *args);
static PyObject * get_spa_hmac_type(PyObject *self, PyObject *args);
static PyObject * set_spa_hmac_type(PyObject *self, PyObject *args);

/* FKO other utility Functions.
*/
static PyObject * spa_data_final(PyObject *self, PyObject *args);
static PyObject * decrypt_spa_data(PyObject *self, PyObject *args);
static PyObject * encrypt_spa_data(PyObject *self, PyObject *args);
static PyObject * decode_spa_data(PyObject *self, PyObject *args);
static PyObject * encode_spa_data(PyObject *self, PyObject *args);

static PyObject * encryption_type(PyObject *self, PyObject *args);
static PyObject * key_gen(PyObject *self, PyObject *args);
static PyObject * base64_encode(PyObject *self, PyObject *args);
static PyObject * base64_decode(PyObject *self, PyObject *args);
static PyObject * verify_hmac(PyObject *self, PyObject *args);
static PyObject * set_spa_hmac(PyObject *self, PyObject *args);
static PyObject * get_spa_hmac(PyObject *self, PyObject *args);

/* FKO GPG-related Functions.
*/
static PyObject * get_gpg_recipient(PyObject *self, PyObject *args);
static PyObject * set_gpg_recipient(PyObject *self, PyObject *args);
static PyObject * get_gpg_signer(PyObject *self, PyObject *args);
static PyObject * set_gpg_signer(PyObject *self, PyObject *args);
static PyObject * get_gpg_home_dir(PyObject *self, PyObject *args);
static PyObject * set_gpg_home_dir(PyObject *self, PyObject *args);
static PyObject * get_gpg_signature_verify(PyObject *self, PyObject *args);
static PyObject * set_gpg_signature_verify(PyObject *self, PyObject *args);
static PyObject * get_gpg_ignore_verify_error(PyObject *self, PyObject *args);
static PyObject * set_gpg_ignore_verify_error(PyObject *self, PyObject *args);
static PyObject * get_gpg_exe(PyObject *self, PyObject *args);
static PyObject * set_gpg_exe(PyObject *self, PyObject *args);
static PyObject * get_gpg_signature_id(PyObject *self, PyObject *args);
static PyObject * get_gpg_signature_fpr(PyObject *self, PyObject *args);
static PyObject * get_gpg_signature_summary(PyObject *self, PyObject *args);
static PyObject * get_gpg_signature_status(PyObject *self, PyObject *args);
static PyObject * gpg_signature_id_match(PyObject *self, PyObject *args);
static PyObject * gpg_signature_fpr_match(PyObject *self, PyObject *args);

/* FKO error message functions.
*/
static PyObject * errstr(PyObject *self, PyObject *args);
static PyObject * gpg_errstr(PyObject *self, PyObject *args);

static PyMethodDef FKOMethods[] = {
    {"init_ctx",  init_ctx, METH_VARARGS,
     "Initialize a new FKO context."},
    {"init_ctx_with_data",  init_ctx_with_data, METH_VARARGS,
     "Initialize a new FKO context with encoded SPA data and optional key."},
    {"destroy_ctx",  destroy_ctx, METH_VARARGS,
     "Destroy an FKO context and release resources it was using."},

    {"get_version",  get_version, METH_VARARGS,
     "Returns the SPA protocol version string"},
    {"get_rand_value",  get_rand_value, METH_VARARGS,
     "Returns the random value string for this context"},
    {"set_rand_value",  set_rand_value, METH_VARARGS,
     "Sets or generates the random value string for this context"},
    {"get_username",  get_username, METH_VARARGS,
     "Returns the username string for this context"},
    {"set_username",  set_username, METH_VARARGS,
     "Sets the username string for this context"},
    {"get_timestamp",  get_timestamp, METH_VARARGS,
     "Returns the timestamp value for this context"},
    {"set_timestamp",  set_timestamp, METH_VARARGS,
     "Sets the timestamp value with optional offset for this context"},
    {"get_spa_digest_type",  get_spa_digest_type, METH_VARARGS,
     "Returns the spa_digest_type value for this context"},
    {"set_spa_digest_type",  set_spa_digest_type, METH_VARARGS,
     "Sets the spa_digest_type value for this context"},
    {"get_spa_encryption_type",  get_spa_encryption_type, METH_VARARGS,
     "Returns the spa_encryption_type value for this context"},
    {"set_spa_encryption_type",  set_spa_encryption_type, METH_VARARGS,
     "Sets the spa_encryption_type value for this context"},
    {"get_spa_message_type",  get_spa_message_type, METH_VARARGS,
     "Returns the spa_message_type value for this context"},
    {"set_spa_message_type",  set_spa_message_type, METH_VARARGS,
     "Sets the spa_message_type data for this context"},
    {"get_spa_message",  get_spa_message, METH_VARARGS,
     "Returns the spa_message data for this context"},
    {"set_spa_message",  set_spa_message, METH_VARARGS,
     "Sets the spa_message data for this context"},
    {"get_spa_nat_access",  get_spa_nat_access, METH_VARARGS,
     "Returns the spa_nat_access string for this context"},
    {"set_spa_nat_access",  set_spa_nat_access, METH_VARARGS,
     "Sets the spa_nat_access string for this context"},
    {"get_spa_server_auth",  get_spa_server_auth, METH_VARARGS,
     "Returns the spa_server_auth string for this context"},
    {"set_spa_server_auth",  set_spa_server_auth, METH_VARARGS,
     "Sets the spa_server_auth string for this context"},
    {"get_spa_client_timeout",  get_spa_client_timeout, METH_VARARGS,
     "Returns the spa_client_timeout value for this context"},
    {"set_spa_client_timeout",  set_spa_client_timeout, METH_VARARGS,
     "Sets the spa_client_timeout value for this context"},
    {"get_spa_digest",  get_spa_digest, METH_VARARGS,
     "Returns the spa_digest data for this context"},
    {"set_spa_digest",  set_spa_digest, METH_VARARGS,
     "Sets the spa_digest data for this context"},
    {"get_spa_data",  get_spa_data, METH_VARARGS,
     "Returns the spa_data string for this context"},
    {"set_spa_data",  set_spa_data, METH_VARARGS,
     "Sets the spa_data string for this context"},
    {"get_encoded_data",  get_encoded_data, METH_VARARGS,
     "Returns the encoded_data string for this context"},

//--DSS
    {"get_raw_spa_digest_type", get_raw_spa_digest_type, METH_VARARGS,
     "Returns the raw spa_digest_type value for this context"},
    {"set_raw_spa_digest_type", set_raw_spa_digest_type, METH_VARARGS,
     "Sets the raw_spa_digest_type string for this context"},
    {"get_raw_spa_digest", get_raw_spa_digest, METH_VARARGS,
     "Returns the raw spa_digest value for this context"},
    {"set_raw_spa_digest", set_raw_spa_digest, METH_VARARGS,
     "Sets the raw_spa_digest string for this context"},
    {"get_spa_encryption_mode", get_spa_encryption_mode, METH_VARARGS,
     "Returns the raw spa_encryption_mode value for this context"},
    {"set_spa_encryption_mode", set_spa_encryption_mode, METH_VARARGS,
     "Sets the set_spa_encryption_mode string for this context"},
    {"get_spa_hmac_type", get_spa_hmac_type, METH_VARARGS,
     "Returns the raw spa_hmac_type value for this context"},
    {"set_spa_hmac_type", set_spa_hmac_type, METH_VARARGS,
     "Sets the spa_hmac_type string for this context"},

    {"spa_data_final",  spa_data_final, METH_VARARGS,
     "Recalculate and recreate the SPA data for the current context"},
    {"decrypt_spa_data",  decrypt_spa_data, METH_VARARGS,
     "Decrypt and parse the current context SPA data"},
    {"encrypt_spa_data",  encrypt_spa_data, METH_VARARGS,
     "Encrypt the current context raw data into a SPA data message"},
    {"decode_spa_data",  decode_spa_data, METH_VARARGS,
     "Decode and parse the decrypted current context SPA data"},
    {"encode_spa_data",  encode_spa_data, METH_VARARGS,
     "Encode the current context raw data to prepare for encryption"},

//--DSS
    {"encryption_type", encryption_type, METH_VARARGS,
     "Return the assumed encryption type based on the encryptped data"},
    {"key_gen", key_gen, METH_VARARGS,
     "Generate Rijndael and HMAC keys and base64 encode them"},
    {"base64_encode", base64_encode, METH_VARARGS,
     "Base64 encode function"},
    {"base64_decode", base64_decode, METH_VARARGS,
     "Base64 decode function"},
    {"verify_hmac", verify_hmac, METH_VARARGS,
     "Generate HMAC for the data and verify it against the HMAC included with the data"},
    {"set_spa_hmac", set_spa_hmac, METH_VARARGS,
     "Calculate the HMAC for the given data"},
    {"get_spa_hmac", get_spa_hmac, METH_VARARGS,
     "Return the HMAC for the data in the current context"},

    {"get_gpg_recipient",  get_gpg_recipient, METH_VARARGS,
     "Returns the gpg_recipient string for this context"},
    {"set_gpg_recipient",  set_gpg_recipient, METH_VARARGS,
     "Sets the gpg_recipient string for this context"},
    {"get_gpg_signer",  get_gpg_signer, METH_VARARGS,
     "Returns the gpg_signer string for this context"},
    {"set_gpg_signer",  set_gpg_signer, METH_VARARGS,
     "Sets the gpg_signer string for this context"},
    {"get_gpg_home_dir",  get_gpg_home_dir, METH_VARARGS,
     "Returns the gpg_home_dir string for this context"},
    {"set_gpg_home_dir",  set_gpg_home_dir, METH_VARARGS,
     "Sets the gpg_home_dir string for this context"},
    {"get_gpg_signature_verify",  get_gpg_signature_verify, METH_VARARGS,
     "Returns the gpg_signature_verify flag value for this context"},
    {"set_gpg_signature_verify",  set_gpg_signature_verify, METH_VARARGS,
     "Sets the gpg_signature_verify flag value for this context"},
    {"get_gpg_ignore_verify_error",  get_gpg_ignore_verify_error, METH_VARARGS,
     "Returns the gpg_ignore_verify_error flag value for this context"},
    {"set_gpg_ignore_verify_error",  set_gpg_ignore_verify_error, METH_VARARGS,
     "Sets the gpg_ignore_verify_error flag value for this context"},
    {"get_gpg_exe",  get_gpg_exe, METH_VARARGS,
     "Returns the path to the gpg executable used by this context"},
    {"set_gpg_exe",  set_gpg_exe, METH_VARARGS,
     "Sets the path to the gpg executable to use for this context"},
    {"get_gpg_signature_id",  get_gpg_signature_id, METH_VARARGS,
     "Returns the gpg_signature_id string for recently decoded GPG-encoded message"},
    {"get_gpg_signature_fpr",  get_gpg_signature_fpr, METH_VARARGS,
     "Returns the gpg_signature_fpr (fingerprint) string for recently decoded GPG-encoded message"},
    {"get_gpg_signature_summary",  get_gpg_signature_summary, METH_VARARGS,
     "Returns the gpg_signature_summary value for recently decoded GPG-encoded message"},
    {"get_gpg_signature_status",  get_gpg_signature_status, METH_VARARGS,
     "Returns the gpg_signature_status value for recently decoded GPG-encoded message"},
    {"gpg_signature_id_match",  gpg_signature_id_match, METH_VARARGS,
     "Returns a true value if the GPG signature of GPG-encoded message matches the given id string"},
    {"gpg_signature_fpr_match",  gpg_signature_fpr_match, METH_VARARGS,
     "Returns a true value if the GPG fingerprint of GPG-encoded message matches the given fingerprint string"},


    {"errstr",  errstr, METH_VARARGS,
     "Returns the error message for the given error code"},
    {"gpg_errstr", gpg_errstr, METH_VARARGS,
     "Returns the GPG error message for the given error code"},
    {NULL, NULL, 0, NULL}
};


/*****************************************************************************
 * Module init
*/
PyMODINIT_FUNC
init_fko(void)
{
    PyObject *m;

    m = Py_InitModule("_fko", FKOMethods);
    if (m == NULL)
        return;

    FKOError = PyErr_NewException("fko.error", NULL, NULL);
    Py_INCREF(FKOError);
    PyModule_AddObject(m, "error", FKOError);
}


/*****************************************************************************
 * FKO context functions.
*/
/* init_ctx
*/
static PyObject *
init_ctx(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    int res;

    res = fko_new(&ctx);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("k", ctx);
}


/* init_ctx_with_data
*/
static PyObject *
init_ctx_with_data(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *spa_data;
    char *dec_key;
    int dec_key_len;
    int enc_mode;
    char *hmac_key;
    int hmac_key_len;
    int hmac_type;
    int res;

    if(!PyArg_ParseTuple(args, "ss#is#", &spa_data, &dec_key, &dec_key_len,
                         &enc_mode, &hmac_key, &hmac_key_len, &hmac_type))
        return NULL;

    res = fko_new_with_data(&ctx, spa_data, dec_key, dec_key_len, enc_mode,
                            hmac_key, hmac_key_len, hmac_type);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("k", ctx);
}

/* destroy_ctx
*/
static PyObject *
destroy_ctx(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    fko_destroy(ctx);

    return Py_BuildValue("", NULL);
}


/*****************************************************************************
 * FKO SPA data functions.
*/
/* get_version
*/
static PyObject *
get_version(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *ver_str;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_version(ctx, &ver_str);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("s", ver_str);
}

/* get_rand_value
*/
static PyObject *
get_rand_value(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *rand_value;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_rand_value(ctx, &rand_value);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("s", rand_value);
}

/* set_rand_value
*/
static PyObject *
set_rand_value(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *rand_value;
    int res;

    if(!PyArg_ParseTuple(args, "kz", &ctx, &rand_value))
        return NULL;

    res = fko_set_rand_value(ctx, rand_value);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* get_username
*/
static PyObject *
get_username(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *username;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_username(ctx, &username);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("s", username);
}

/* set_username
*/
static PyObject *
set_username(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *username;
    int res;

    if(!PyArg_ParseTuple(args, "kz", &ctx, &username))
        return NULL;

    res = fko_set_username(ctx, username);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* get_timestamp
*/
static PyObject *
get_timestamp(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    time_t timestamp;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_timestamp(ctx, &timestamp);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("k", timestamp);
}

/* set_timestamp
*/
static PyObject *
set_timestamp(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    int res, offset;

    if(!PyArg_ParseTuple(args, "kk", &ctx, &offset))
        return NULL;

    res = fko_set_timestamp(ctx, offset);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* get_spa_digest_type
*/
static PyObject *
get_spa_digest_type(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    short digest_type;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_spa_digest_type(ctx, &digest_type);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("h", digest_type);
}

/* set_spa_digest_type
*/
static PyObject *
set_spa_digest_type(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    short digest_type;
    int res;

    if(!PyArg_ParseTuple(args, "kh", &ctx, &digest_type))
        return NULL;

    res = fko_set_spa_digest_type(ctx, digest_type);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* get_spa_encryption_type
*/
static PyObject *
get_spa_encryption_type(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    short encryption_type;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_spa_encryption_type(ctx, &encryption_type);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("h", encryption_type);
}

/* set_spa_encryption_type
*/
static PyObject *
set_spa_encryption_type(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    short encryption_type;
    int res;

    if(!PyArg_ParseTuple(args, "kh", &ctx, &encryption_type))
        return NULL;

    res = fko_set_spa_encryption_type(ctx, encryption_type);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* get_spa_message_type
*/
static PyObject *
get_spa_message_type(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    short message_type;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_spa_message_type(ctx, &message_type);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("h", message_type);
}

/* set_spa_message_type
*/
static PyObject *
set_spa_message_type(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    short message_type;
    int res;

    if(!PyArg_ParseTuple(args, "kh", &ctx, &message_type))
        return NULL;

    res = fko_set_spa_message_type(ctx, message_type);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* get_spa_message
*/
static PyObject *
get_spa_message(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *spa_message;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_spa_message(ctx, &spa_message);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("s", spa_message);
}

/* set_spa_message
*/
static PyObject *
set_spa_message(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *spa_message;
    int res;

    if(!PyArg_ParseTuple(args, "ks", &ctx, &spa_message))
        return NULL;

    res = fko_set_spa_message(ctx, spa_message);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* get_spa_nat_access
*/
static PyObject *
get_spa_nat_access(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *spa_nat_access;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_spa_nat_access(ctx, &spa_nat_access);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("s", spa_nat_access);
}

/* set_spa_nat_access
*/
static PyObject *
set_spa_nat_access(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *spa_nat_access;
    int res;

    if(!PyArg_ParseTuple(args, "ks", &ctx, &spa_nat_access))
        return NULL;

    res = fko_set_spa_nat_access(ctx, spa_nat_access);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* get_spa_server_auth
*/
static PyObject *
get_spa_server_auth(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *spa_server_auth;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_spa_server_auth(ctx, &spa_server_auth);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("s", spa_server_auth);
}

/* set_spa_server_auth
*/
static PyObject *
set_spa_server_auth(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *spa_server_auth;
    int res;

    if(!PyArg_ParseTuple(args, "ks", &ctx, &spa_server_auth))
        return NULL;

    res = fko_set_spa_server_auth(ctx, spa_server_auth);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* get_spa_client_timeout
*/
static PyObject *
get_spa_client_timeout(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    int client_timeout;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_spa_client_timeout(ctx, &client_timeout);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("i", client_timeout);
}

/* set_spa_client_timeout
*/
static PyObject *
set_spa_client_timeout(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    int client_timeout;
    int res;

    if(!PyArg_ParseTuple(args, "ki", &ctx, &client_timeout))
        return NULL;

    res = fko_set_spa_client_timeout(ctx, client_timeout);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* get_spa_digest
*/
static PyObject *
get_spa_digest(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *spa_digest;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_spa_digest(ctx, &spa_digest);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("s", spa_digest);
}

/* set_spa_digest
*/
static PyObject *
set_spa_digest(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_set_spa_digest(ctx);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* get_spa_data
*/
static PyObject *
get_spa_data(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *spa_data;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_spa_data(ctx, &spa_data);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("s", spa_data);
}

/* set_spa_data
*/
static PyObject *
set_spa_data(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *spa_data;
    int res;

    if(!PyArg_ParseTuple(args, "ks", &ctx, &spa_data))
        return NULL;

    res = fko_set_spa_data(ctx, spa_data);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* get_encoded_data
*/
static PyObject *
get_encoded_data(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *encoded_data;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_encoded_data(ctx, &encoded_data);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("s", encoded_data);
}

static PyObject *
get_raw_spa_digest_type(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    short raw_digest_type;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_raw_spa_digest_type(ctx, &raw_digest_type);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("h", raw_digest_type);
}

static PyObject *
set_raw_spa_digest_type(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    short raw_digest_type;
    int res;

    if(!PyArg_ParseTuple(args, "kh", &ctx, &raw_digest_type))
        return NULL;

    res = fko_set_raw_spa_digest_type(ctx, raw_digest_type);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

static PyObject *
get_raw_spa_digest(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *raw_spa_digest;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_raw_spa_digest(ctx, &raw_spa_digest);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("s", raw_spa_digest);
}

static PyObject *
set_raw_spa_digest(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_set_raw_spa_digest(ctx);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

static PyObject *
get_spa_encryption_mode(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    int encryption_mode;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_spa_encryption_mode(ctx, &encryption_mode);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("h", encryption_mode);
}

static PyObject *
set_spa_encryption_mode(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    int encryption_mode;
    int res;

    if(!PyArg_ParseTuple(args, "kh", &ctx, &encryption_mode))
        return NULL;

    res = fko_set_spa_encryption_mode(ctx, encryption_mode);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

static PyObject *
get_spa_hmac_type(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    short hmac_type;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_spa_hmac_type(ctx, &hmac_type);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("h", hmac_type);
}

static PyObject *
set_spa_hmac_type(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    short hmac_type;
    int res;

    if(!PyArg_ParseTuple(args, "kh", &ctx, &hmac_type))
        return NULL;

    res = fko_set_spa_hmac_type(ctx, hmac_type);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/*****************************************************************************
 * FKO other utility functions.
*/
/* spa_data_final
*/
static PyObject *
spa_data_final(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *enc_key;
    int enc_key_len;
    char *hmac_key;
    int hmac_key_len;
    int res;

    if(!PyArg_ParseTuple(args, "ks#s#", &ctx, &enc_key, &enc_key_len,
                         &hmac_key, &hmac_key_len))
        return NULL;

    res = fko_spa_data_final(ctx, enc_key, enc_key_len,
                             hmac_key, hmac_key_len);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* decrypt_spa_data
*/
static PyObject *
decrypt_spa_data(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *key;
    int key_len;
    int res;

    if(!PyArg_ParseTuple(args, "ks#", &ctx, &key, &key_len))
        return NULL;

    res = fko_decrypt_spa_data(ctx, key, key_len);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* encrypt_spa_data
*/
static PyObject *
encrypt_spa_data(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *key;
    int key_len;
    int res;

    if(!PyArg_ParseTuple(args, "ks#", &ctx, &key, &key_len))
        return NULL;

    res = fko_encrypt_spa_data(ctx, key, key_len);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* decode_spa_data
*/
static PyObject *
decode_spa_data(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_decode_spa_data(ctx);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* encode_spa_data
*/
static PyObject *
encode_spa_data(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_encode_spa_data(ctx);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

static PyObject *
encryption_type(PyObject *self, PyObject *args)
{
    char *spa_data;
    int enc_type;

    if(!PyArg_ParseTuple(args, "s", &spa_data))
        return NULL;

    enc_type = fko_encryption_type(spa_data);

    return Py_BuildValue("i", enc_type);
}

static PyObject *
key_gen(PyObject *self, PyObject *args)
{
    char *key_b64;
    int key_b64_len;
    char *hmac_key_b64;
    int hmac_key_b64_len;
    int hmac_type;
    int res;

    if(!PyArg_ParseTuple(args, "s#s#ih", &key_b64, &key_b64_len,
                         &hmac_key_b64, &hmac_key_b64_len, &hmac_type))
        return NULL;

    res = fko_key_gen(key_b64, key_b64_len, hmac_key_b64, hmac_key_b64_len,
                      hmac_type);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

static PyObject *
base64_encode(PyObject *self, PyObject *args)
{
    unsigned char *in;
    int in_len;
    char *out;
    int res;

    /* --DSS Note the order of args is different than the libfko call.
             We need to do this for the following parse call. */
    if(!PyArg_ParseTuple(args, "s#s", &in, &in_len, &out))
        return NULL;

    res = fko_base64_encode(in, out, in_len);

    return Py_BuildValue("s", out);
}

static PyObject *
base64_decode(PyObject *self, PyObject *args)
{
    char *in;
    unsigned char *out;
    int res;

    if(!PyArg_ParseTuple(args, "ss", &in, &out))
        return NULL;

    res = fko_base64_decode(in, out);

    return Py_BuildValue("s#", out, res);
}

static PyObject *
verify_hmac(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *hmac_key;
    int hmac_key_len;
    int res;

    if(!PyArg_ParseTuple(args, "ks#", &ctx, &hmac_key, &hmac_key_len))
        return NULL;

    res = fko_verify_hmac(ctx, hmac_key, hmac_key_len);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

static PyObject *
set_spa_hmac(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *hmac_key;
    int hmac_key_len;
    int res;

    if(!PyArg_ParseTuple(args, "ks#", &ctx, &hmac_key, &hmac_key_len))
        return NULL;

    res = fko_set_spa_hmac(ctx, hmac_key, hmac_key_len);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

static PyObject *
get_spa_hmac(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *enc_data;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_spa_hmac(ctx, &enc_data);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("s", enc_data);
}

/*****************************************************************************
 * FKO GPG-related functions.
*/
/* get_gpg_recipient
*/
static PyObject *
get_gpg_recipient(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *gpg_recipient;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_gpg_recipient(ctx, &gpg_recipient);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("s", gpg_recipient);
}

/* set_gpg_recipient
*/
static PyObject *
set_gpg_recipient(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *gpg_recipient;
    int res;

    if(!PyArg_ParseTuple(args, "ks", &ctx, &gpg_recipient))
        return NULL;

    res = fko_set_gpg_recipient(ctx, gpg_recipient);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* get_gpg_signer
*/
static PyObject *
get_gpg_signer(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *gpg_signer;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_gpg_signer(ctx, &gpg_signer);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("s", gpg_signer);
}

/* set_gpg_signer
*/
static PyObject *
set_gpg_signer(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *gpg_signer;
    int res;

    if(!PyArg_ParseTuple(args, "ks", &ctx, &gpg_signer))
        return NULL;

    res = fko_set_gpg_signer(ctx, gpg_signer);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* get_gpg_home_dir
*/
static PyObject *
get_gpg_home_dir(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *gpg_home_dir;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_gpg_home_dir(ctx, &gpg_home_dir);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("s", gpg_home_dir);
}

/* set_gpg_home_dir
*/
static PyObject *
set_gpg_home_dir(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *gpg_home_dir;
    int res;

    if(!PyArg_ParseTuple(args, "ks", &ctx, &gpg_home_dir))
        return NULL;

    res = fko_set_gpg_home_dir(ctx, gpg_home_dir);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* get_gpg_signature_verify
*/
static PyObject *
get_gpg_signature_verify(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    unsigned char gpg_signature_verify;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_gpg_signature_verify(ctx, &gpg_signature_verify);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("b", gpg_signature_verify);
}

/* set_gpg_signature_verify
*/
static PyObject *
set_gpg_signature_verify(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    unsigned char gpg_signature_verify;
    int res;

    if(!PyArg_ParseTuple(args, "kb", &ctx, &gpg_signature_verify))
        return NULL;

    res = fko_set_gpg_signature_verify(ctx, gpg_signature_verify);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* get_gpg_ignore_verify_error
*/
static PyObject *
get_gpg_ignore_verify_error(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    unsigned char gpg_ignore_verify_error;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_gpg_ignore_verify_error(ctx, &gpg_ignore_verify_error);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("b", gpg_ignore_verify_error);
}

/* set_gpg_ignore_verify_error
*/
static PyObject *
set_gpg_ignore_verify_error(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    unsigned char gpg_ignore_verify_error;
    int res;

    if(!PyArg_ParseTuple(args, "kb", &ctx, &gpg_ignore_verify_error))
        return NULL;

    res = fko_set_gpg_ignore_verify_error(ctx, gpg_ignore_verify_error);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* get_gpg_exe
*/
static PyObject *
get_gpg_exe(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *gpg_exe;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_gpg_exe(ctx, &gpg_exe);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("s", gpg_exe);
}

/* set_gpg_exe
*/
static PyObject *
set_gpg_exe(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *gpg_exe;
    int res;

    if(!PyArg_ParseTuple(args, "ks", &ctx, &gpg_exe))
        return NULL;

    res = fko_set_gpg_exe(ctx, gpg_exe);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("", NULL);
}

/* get_gpg_signature_id
*/
static PyObject *
get_gpg_signature_id(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *gpg_signature_id;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_gpg_signature_id(ctx, &gpg_signature_id);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("s", gpg_signature_id);
}

/* get_gpg_signature_fpr
*/
static PyObject *
get_gpg_signature_fpr(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    char *gpg_signature_fpr;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_gpg_signature_fpr(ctx, &gpg_signature_fpr);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("s", gpg_signature_fpr);
}

/* get_gpg_signature_summary
*/
static PyObject *
get_gpg_signature_summary(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    int gpg_signature_summary;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_gpg_signature_summary(ctx, &gpg_signature_summary);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("i", gpg_signature_summary);
}

/* get_gpg_signature_status
*/
static PyObject *
get_gpg_signature_status(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    int gpg_signature_status;
    int res;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    res = fko_get_gpg_signature_status(ctx, &gpg_signature_status);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("i", gpg_signature_status);
}

/* gpg_signature_id_match
*/
static PyObject *
gpg_signature_id_match(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    const char *gpg_signature_id;
    unsigned char gpg_signature_id_match;
    int res;

    if(!PyArg_ParseTuple(args, "ks", &ctx, &gpg_signature_id))
        return NULL;

    res = fko_gpg_signature_id_match(ctx, gpg_signature_id, &gpg_signature_id_match);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("b", gpg_signature_id_match);
}

/* gpg_signature_fpr_match
*/
static PyObject *
gpg_signature_fpr_match(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    const char *gpg_signature_fpr;
    unsigned char gpg_signature_fpr_match;
    int res;

    if(!PyArg_ParseTuple(args, "ks", &ctx, &gpg_signature_fpr))
        return NULL;

    res = fko_gpg_signature_id_match(ctx, gpg_signature_fpr, &gpg_signature_fpr_match);

    if(res != FKO_SUCCESS)
    {
        PyErr_SetString(FKOError, fko_errstr(res));
        return NULL;
    }

    return Py_BuildValue("b", gpg_signature_fpr_match);
}


/*****************************************************************************
 * FKO error message function.
*/
/* errstr
*/
static PyObject *
errstr(PyObject *self, PyObject *args)
{
    const char *errmsg;
    int res;

    if(!PyArg_ParseTuple(args, "i", &res))
        return NULL;

    errmsg = fko_errstr(res);

    return Py_BuildValue("s", errmsg);
}

/* gpg_errstr
*/
static PyObject *
gpg_errstr(PyObject *self, PyObject *args)
{
    fko_ctx_t ctx;
    const char *errmsg;

    if(!PyArg_ParseTuple(args, "k", &ctx))
        return NULL;

    errmsg = fko_gpg_errstr(ctx);

    return Py_BuildValue("s", errmsg);
}

/***EOF***/
