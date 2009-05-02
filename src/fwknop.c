/* $Id$
 *****************************************************************************
 *
 * File:    fwknop.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: An implementation of an fwknop client.
 *
 * Copyright (C) 2009 Damien Stuart (dstuart@dstuart.org)
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
#include "fwknop.h"
#include "config_init.h"
#include "spa_comm.h"
#include "utils.h"
#include "getpasswd.h"

/* Used by the get_user_pw function below.
*/
#define CRYPT_OP_ENCRYPT 1
#define CRYPT_OP_DECRYPT 2
char* get_user_pw(fko_cli_options_t *options, int crypt_op);

int
main(int argc, char **argv)
{
    fko_ctx_t           ctx, ctx2;
    int                 res;
    char               *pw, *spa_data, *version;
    char                access_buf[MAX_LINE_LEN];

    fko_cli_options_t   options;

    /* Handle command line
    */
    config_init(&options, argc, argv);

    /* Intialize the context
    */
    res = fko_new(&ctx);
    if(res != FKO_SUCCESS)
        fprintf(stderr, "Error #%i from fko_new: %s\n", res, fko_errstr(res));

    fko_get_version(ctx, &version);

    if (options.version) {
        fprintf(stdout, "[+] fwknop-%s\n", version);
        exit(0);
    }

    /* Set up for using GPG if specified.
    */
    if(options.use_gpg)
    {
        /* If use-gpg-agent was not specified, then remove the GPG_AGENT_INFO
         * ENV variable if it exists.
        */
        if(!options.use_gpg_agent)
            unsetenv("GPG_AGENT_INFO");

        res = fko_set_spa_encryption_type(ctx, FKO_ENCRYPTION_GPG);
        if(res != FKO_SUCCESS)
        {
            fprintf(stderr,
                "Error #%i from fko_set_spa_encryption_type: %s\n",
                res, fko_errstr(res)
            );

            exit(EXIT_FAILURE);
        }

        /* If a GPG home dir was specified, set it here.  Note: Setting
         * this has to occur before calling any of the other GPG-related
         * functions.
        */
        if(options.gpg_home_dir != NULL && strlen(options.gpg_home_dir) > 0)
        {
            res = fko_set_gpg_home_dir(ctx, options.gpg_home_dir);
            if(res != FKO_SUCCESS)
            {
                fprintf(stderr,
                    "Error #%i from fko_set_gpg_home_dir: %s\n",
                    res, fko_errstr(res)
                );
                exit(EXIT_FAILURE);
            }
        }

        res = fko_set_gpg_recipient(ctx, options.gpg_recipient_key);
        if(res != FKO_SUCCESS)
        {
            fprintf(stderr,
                "Error #%i from fko_set_gpg_recipient: %s\n",
                res, fko_errstr(res)
            );

            if(IS_GPG_ERROR(res))
                fprintf(stderr, "GPG ERR: %s\n", fko_gpg_errorstr(ctx));
    
            exit(EXIT_FAILURE);
        }

        res = fko_set_gpg_signer(ctx, options.gpg_signer_key);
        if(res != FKO_SUCCESS)
        {
            fprintf(stderr,
                "Error #%i from fko_set_gpg_signer: %s\n",
                res, fko_errstr(res)
            );

            if(IS_GPG_ERROR(res))
                fprintf(stderr, "GPG ERR: %s\n", fko_gpg_errorstr(ctx));

            exit(EXIT_FAILURE);
        }
    }

    /* Set message type
    res = fko_set_spa_message_type(ctx, FKO_ACCESS_MSG);
    if(res != FKO_SUCCESS)
        fprintf(stderr, "Error #%i from fko_set_spa_message_type: %s\n", res, fko_errstr(res));
    */

    /* Set a message string by combining the allow IP and the port/protocol
    */
    snprintf(access_buf, MAX_LINE_LEN, "%s%s%s",
            options.allow_ip_str, ",", options.access_str);
    res = fko_set_spa_message(ctx, access_buf);
    if(res != FKO_SUCCESS)
    {
        fprintf(stderr, "Error #%i from fko_set_spa_message: %s\n", res, fko_errstr(res));
        exit(EXIT_FAILURE);
    }

    /* Set Digest type.
    */
    if(options.digest_type)
    {
        fko_set_spa_digest_type(ctx, options.digest_type);
        if(res != FKO_SUCCESS)
        {
            fprintf(stderr,
                "Error #%i from fko_set_spa_digest: %s\n",
                res, fko_errstr(res)
            );

            exit(EXIT_FAILURE);
        }
    }

    /* Set net access string.
    res = fko_set_spa_nat_access(ctx, "192.168.1.2,22");
    if(res != FKO_SUCCESS)
        fprintf(stderr, "Error #%i from fko_set_spa_nat_access: %s\n", res, fko_errstr(res));
    */

    /* Set client timeout value
    fko_set_spa_client_timeout(ctx, 120);
    */

    /* Set a serer auth string.
    res = fko_set_spa_server_auth(ctx, "crypt,SomePW");
    if(res != FKO_SUCCESS)
        fprintf(stderr, "Error #%i from fko_set_spa_server_auth: %s\n", res, fko_errstr(res));
    */

    /* Finalize the context data (encrypt and encode the SPA data)
    */
    res = fko_spa_data_final(ctx, get_user_pw(&options, CRYPT_OP_ENCRYPT));
    if(res != FKO_SUCCESS)
    {
        fprintf(stderr,
            "Error #%i from fko_spa_data_final: %s\n",
            res, fko_errstr(res)
        );

        if(IS_GPG_ERROR(res))
            fprintf(stderr, "GPG ERR: %s\n", fko_gpg_errorstr(ctx));

        exit(EXIT_FAILURE);
    }

    /* Display the context data.
    */
    if (! options.quiet)
        display_ctx(ctx);

    if (options.save_packet_file[0] != 0x0)
        write_spa_packet_data(ctx, &options);

    /* If not in test mode, send the SPA data across the wire with a
     * protocol/port specified on the command line (default is UDP/62201).
     * Otherwise, run through a decode cycle (--DSS XXX: This test/decode
     * portion should be moved elsewhere).
    */
    if (! options.test)
    {
        send_spa_packet(ctx, &options);
    }
    else
    {
        /************** Decoding now *****************/

        /* Now we create a new context based on data from the first one.
        */
        res = fko_get_spa_data(ctx, &spa_data);

        if(res != FKO_SUCCESS)
        {
            fprintf(stderr,
                "Error #%i from fko_get_spa_data: %s\n",
                res, fko_errstr(res)
            );
            exit(EXIT_FAILURE);
        }

        /* If gpg-home-dir is specified, we have to defer decrypting if we
         * use the fko_new_with_data() function because we need to set the
         * gpg home dir after the context is created, but before we attempt
         * to decrypt the data.  Therefore we either pass NULL for the
         * decryption key to fko_new_with_data() or use fko_new() to create
         * an empty context, populate it with the encrypted data, set our
         * options, then decode it.
        */
        res = fko_new_with_data(&ctx2, spa_data, NULL);
                                //get_user_pw(&options, CRYPT_OP_DECRYPT));
        if(res != FKO_SUCCESS)
        {
            fprintf(stderr,
                "Error #%i from fko_new_with_data: %s\n",
                res, fko_errstr(res)
            );
            exit(EXIT_FAILURE);
        }

        /* If gpg-home-dir is specified, we have to defer decrypting if we
         * use the fko_new_with_data() function because we need to set the
         * gpg home dir after the context is created, but before we attempt
         * to decrypt the data.  Therefore we either pass NULL for the
         * decryption key to fko_new_with_data() or use fko_new() to create
         * an empty context, populate it with the encrypted data, set our
         * options, then decode it.
        res = fko_new(&ctx2);
        if(res != FKO_SUCCESS)
        {
            fprintf(stderr,
                "Error #%i from fko_new: %s\n",
                res, fko_errstr(res)
            );

            exit(EXIT_FAILURE);
        }
        */

        /* Populate the new context with the encrypted data from the
         * old context.
        res = fko_set_spa_data(ctx2, spa_data);
        if(res != FKO_SUCCESS)
        {
            fprintf(stderr,
                "Error #%i from fko_set_spa_data: %s\n",
                res, fko_errstr(res)
            );

            exit(EXIT_FAILURE);
        }
        */

        if(options.use_gpg)
        {
            if(options.gpg_home_dir != NULL && strlen(options.gpg_home_dir) > 0)
            {
                res = fko_set_gpg_home_dir(ctx2, options.gpg_home_dir);
                if(res != FKO_SUCCESS)
                {
                    fprintf(stderr,
                        "Error #%i from fko_set_gpg_home_dir: %s\n",
                        res, fko_errstr(res)
                    );
                    exit(EXIT_FAILURE);
                }
            }
        }

        res = fko_decrypt_spa_data(
            ctx2, get_user_pw(&options, CRYPT_OP_DECRYPT)
        );

        if(res != FKO_SUCCESS)
        {
            fprintf(stderr,
                "Error #%i from fko_decrypt_spa_data: %s\n",
                res, fko_errstr(res)
            );

            if(IS_GPG_ERROR(res))
                fprintf(stderr, "GPG ERR: %s\n", fko_gpg_errorstr(ctx));

            exit(EXIT_FAILURE);
        }

/* --DSS temp for test
if(options.use_gpg)
{
  char *fpr, *id;
  fko_get_gpg_signature_fpr(ctx2, &fpr);
  printf("++ SIG FPR: %s\n", fpr);
  fko_get_gpg_signature_id(ctx2, &id);
  printf("++ SIG  ID: %s\n", id);
}
*/

        if (! options.quiet) {
            printf("\nDump of the Decoded Data\n");
            display_ctx(ctx2);
        }

        fko_destroy(ctx2);
    }

    fko_destroy(ctx);

    return(0);
}

char*
get_user_pw(fko_cli_options_t *options, int crypt_op)
{
    if(options->use_gpg)
    {
        return(options->use_gpg_agent ? ""
            : getpasswd("Enter passphrase for secret key: "));
    }
    else if (options->get_key_file[0] != 0x0) {
        /* grab the key/password from the --get-key file
        */
        return(getpasswd_file(options->get_key_file,
                        options->spa_server_ip_str));
    }
    else
    {
        if(crypt_op == CRYPT_OP_ENCRYPT)
            return(getpasswd("Enter encryption password: "));
        else if(crypt_op == CRYPT_OP_DECRYPT)
            return(getpasswd("Enter decryption password: "));
        else
            return(getpasswd("Enter password: "));
    }
}

static void
display_ctx(fko_ctx_t ctx)
{
    char            *rand_val, *username, *version, *spa_message, *nat_access,
                    *server_auth, *enc_data, *spa_digest, *spa_data;
    unsigned int    timestamp=0;
    short           msg_type=-1, digest_type=-1;
    int             client_timeout=-1, res;

    /* Should be checking return values, but this is temp code. --DSS
    */
    fko_get_rand_value(ctx, &rand_val);
    fko_get_username(ctx, &username);
    fko_get_timestamp(ctx, &timestamp);
    fko_get_version(ctx, &version);
    fko_get_spa_message_type(ctx, &msg_type);
    fko_get_spa_message(ctx, &spa_message);
    fko_get_spa_nat_access(ctx, &nat_access);
    fko_get_spa_server_auth(ctx, &server_auth);
    fko_get_spa_client_timeout(ctx, &client_timeout);
    fko_get_spa_digest_type(ctx, &digest_type);
    fko_get_encoded_data(ctx, &enc_data);
    fko_get_spa_digest(ctx, &spa_digest);
    fko_get_spa_data(ctx, &spa_data);

    printf(
        "\nFKO Context Values:\n===================\n\n"
        "   Random Value: %s\n"
        "       Username: %s\n"
        "      Timestamp: %u\n"
        "    FKO Version: %s\n"
        "   Message Type: %i\n"
        " Message String: %s\n"
        "     Nat Access: %s\n"
        "    Server Auth: %s\n"
        " Client Timeout: %u\n"
        "    Digest Type: %u\n"
        "\n   Encoded Data: %s\n"
        "\nSPA Data Digest: %s\n"
        "\nFinal Packed/Encrypted/Encoded Data:\n\n%s\n\n"
        ,
        rand_val == NULL ? "<NULL>" : rand_val,
        username == NULL ? "<NULL>" : username,
        timestamp,
        version == NULL ? "<NULL>" : version,
        msg_type,
        spa_message == NULL ? "<NULL>" : spa_message,
        nat_access == NULL ? "<NULL>" : nat_access,
        server_auth == NULL ? "<NULL>" : server_auth,
        client_timeout,
        digest_type,
        enc_data == NULL ? "<NULL>" : enc_data,
        spa_digest == NULL ? "<NULL>" : spa_digest,
        spa_data == NULL ? "<NULL>" : spa_data
    );

}

/***EOF***/
