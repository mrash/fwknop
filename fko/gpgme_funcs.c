/* $Id$
 *****************************************************************************
 *
 * File:    gpgme_funcs.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: gpgme-related functions for GPG encryptions support in libfko.
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

#if HAVE_LIBGPGME

//#include <locale.h>
#include <gpgme.h>
#include "gpgme_funcs.h"

/* Callback function that supplies the password when gpgme needs it.
*/
gpgme_error_t
passphrase_cb(
  void *hook, const char *uid_hint, const char *passphrase_info,
  int prev_was_bad, int fd)
{
    /* We only need to try once as it is fed by the program
     * (for now --DSS).
    */
    if(prev_was_bad)
        return(GPG_ERR_CANCELED);

    write(fd, (const char*)hook, strlen((const char*)hook));
    write(fd, "\n", 1);

    return 0;
}

/* Get the key for the designated signer and add it to the main gpgme context.
*/
int
set_signer(gpgme_ctx_t ctx, const char *signer)
{
    gpgme_error_t err;
    gpgme_ctx_t list_ctx;
    gpgme_key_t key, key2;

    /* Create a gpgme context for the list
    */
    err = gpgme_new(&list_ctx);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        return(gpg_err_code(err));
    }

    err = gpgme_op_keylist_start(list_ctx, signer, 1);

    if (!err)
        err = gpgme_op_keylist_next(list_ctx, &key);

    if (err)
    {
        gpgme_release(list_ctx);
        //secret key not found
        return(gpg_err_code(err));
    }

    err = gpgme_op_keylist_next(list_ctx, &key2);

    if (!err)
    {
        gpgme_key_release(key);
        gpgme_key_release(key2);
        gpgme_release(list_ctx);
        //ambiguous specfication of secret key
        return(gpg_err_code(err));
    }

    gpgme_op_keylist_end(list_ctx);
    gpgme_release(list_ctx);

    gpgme_signers_clear(ctx);

    err = gpgme_signers_add(ctx, key);

    gpgme_key_release(key);

    if (err)
    {
        //error setting secret key
        return(gpg_err_code(err));
    }

    return 0;
}

int
get_recip_key(gpgme_key_t *mykey, const char *recip)
{
    gpgme_error_t err;
    gpgme_ctx_t list_ctx;
    gpgme_key_t key, key2;

    /* Create a gpgme context for the list
    */
    err = gpgme_new(&list_ctx);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        return(gpg_err_code(err));
    }

    err = gpgme_op_keylist_start(list_ctx, recip, 0);

    /* Grab the first key in the list (we hope it is the only one).
    */
    err = gpgme_op_keylist_next(list_ctx, &key);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        gpgme_release(list_ctx);
        return(gpg_err_code(err));
    }

    /* We try to get the next key match. If we do, then the name is
     * ambiguous, so we return an error.
    */
    err = gpgme_op_keylist_next(list_ctx, &key2);
    if(gpg_err_code(err) == GPG_ERR_NO_ERROR) /* Note: look for NO error */
    {
        gpgme_key_release(key);
        gpgme_key_release(key2);
        gpgme_release(list_ctx);
        //ambiguous specfication of secret key
        return(gpg_err_code(err));
    }

    gpgme_op_keylist_end(list_ctx);

    //printf("Got Key:\n%s: %s <%s>\n",
    //        key->subkeys->keyid, key->uids->name, key->uids->email);

    /* Make our key the first entry in the array (just more gpgme funkyness).
    */
    *mykey = key;

    return(0);
}

/* The main GPG encryption routine for libfko.
*/
int
gpgme_encrypt(
  unsigned char *indata, size_t in_len, const char *signer, const char *recip,
  const char *pw, unsigned char **out, size_t *out_len)
{
    char               *tmp_buf;
    int                 res;

    gpgme_ctx_t         gpg_ctx;
    gpgme_error_t       err;
    gpgme_key_t         key[2] = {0};
    gpgme_data_t        data;
    gpgme_data_t        plaintext;

    /* Because the gpgme manual says you should.
    */
    gpgme_check_version(NULL);

    /* Check for OpenPGP support
    */
    err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        /* GPG engine is not available. */
        return(gpg_err_code(err));
    }

    /* Create our gpgme context
    */
    err = gpgme_new(&gpg_ctx);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        return(gpg_err_code(err));
    }

    /* Initialize the plaintext data (place into gpgme_data object)
    */
    err = gpgme_data_new_from_mem(&plaintext, (char*)indata, in_len, 1);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        gpgme_release(gpg_ctx);
        return(gpg_err_code(err));
    }

    /* Set protocol
    */
    err = gpgme_set_protocol(gpg_ctx, GPGME_PROTOCOL_OpenPGP);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        gpgme_release(gpg_ctx);
        return(gpg_err_code(err));
    }

    /* Set ascii-armor off (we will be base64-encoding the encrypted data
     * ourselves.
    */
    gpgme_set_armor(gpg_ctx, 0);

    /* Get the signer gpg key
    */
    err = set_signer(gpg_ctx, signer);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        gpgme_release(gpg_ctx);
        return(gpg_err_code(err));
    }

    /* Get the recipient gpg key
    */
    err = get_recip_key((gpgme_key_t*)&key, recip);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        gpgme_release(gpg_ctx);
        return(gpg_err_code(err));
    }

    /* Create the buffer for our encrypted data.
    */
    err = gpgme_data_new(&data);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        gpgme_release(gpg_ctx);

        return(gpg_err_code(err));
    }

    /* Set the passphrase callback.
    */
    gpgme_set_passphrase_cb(gpg_ctx, passphrase_cb, (void*)pw);

    err = gpgme_op_encrypt_sign(gpg_ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, plaintext, data);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        //fprintf(stderr, "*Ecrypt&Sign Error: %s\n", gpgme_strerror(err));
        gpgme_release(gpg_ctx);

        return(gpg_err_code(err));
    }

    gpgme_data_release(plaintext);

    /* Get the encrypted data and its length from the gpgme data object.
    */
    tmp_buf = gpgme_data_release_and_get_mem(data, out_len);

    *out = malloc(*out_len); /* Note: this is freed when the context is destroyed */
    if(*out == NULL)
    {
        res = -2;
    }
    else
    {
        res = 0;
        memcpy(*out, tmp_buf, *out_len);
    }

    gpgme_free(tmp_buf);
    gpgme_release(gpg_ctx);

    return(res);
}

/* The main GPG encryption routine for libfko.
*/
int
gpgme_decrypt(
  unsigned char *indata, size_t in_len, const char *signer, const char *recip,
  const char *pw, unsigned char **out, size_t *out_len)
{
    char                   *tmp_buf;
    int                     res;

    gpgme_ctx_t             gpg_ctx;
    gpgme_error_t           err;
    gpgme_data_t            cipher, plaintext;
    gpgme_decrypt_result_t  decrypt_result;
    gpgme_verify_result_t   verify_result;

    /* Because the gpgme manual says you should.
    */
    gpgme_check_version(NULL);
    //setlocale(LC_ALL, "");
    //gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));

    /* Check for OpenPGP support
    */
    err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        /* GPG engine is not available. */
        return(gpg_err_code(err));
    }

    /* Create our gpgme context
    */
    err = gpgme_new(&gpg_ctx);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        return(gpg_err_code(err));
    }

    //gpgme_set_armor(gpg_ctx, 0);

    err = gpgme_data_new(&plaintext);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        gpgme_release(gpg_ctx);
        return(gpg_err_code(err));
    }

    
    /* Initialize the cipher data (place into gpgme_data object)
    */
    err = gpgme_data_new_from_mem(&cipher, (char*)indata, in_len, 0);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        gpgme_release(gpg_ctx);
        return(gpg_err_code(err));
    }

    /* Set the passphrase callback.
    */
    gpgme_set_passphrase_cb(gpg_ctx, passphrase_cb, (void*)pw);

    /* Now decrypt and verify.
    */
    err = gpgme_op_decrypt_verify(gpg_ctx, cipher, plaintext);
    if(gpg_err_code(err) != GPG_ERR_NO_ERROR)
    {
        gpgme_release(gpg_ctx);
        return(gpg_err_code(err));
    }

    gpgme_data_release(cipher);

    decrypt_result = gpgme_op_decrypt_result (gpg_ctx);

    /* TODO: Do something with this (like the sample below)
    if (decrypt_result->unsupported_algorithm)
    {
        fprintf (stderr, "%s:%i: unsupported algorithm: %s\n",
	        __FILE__, __LINE__, decrypt_result->unsupported_algorithm);
    }    
    */

    verify_result = gpgme_op_verify_result (gpg_ctx);
    //TODO: Do something with this too (or not)

    /* Get the encrypted data and its length from the gpgme data object.
    */
    tmp_buf = gpgme_data_release_and_get_mem(plaintext, out_len);

    *out = malloc(*out_len); /* Note: this is freed when the context is destroyed */
    if(*out == NULL)
    {
        res = -2;
    }
    else
    {
        res = 0;
        memcpy(*out, tmp_buf, *out_len);
    }

    gpgme_free(tmp_buf);
    gpgme_release(gpg_ctx);

    return(res);
}

#endif /* HAVE_LIBGPGME */

/***EOF***/
