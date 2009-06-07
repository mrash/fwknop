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

/* prototypes
*/
char* get_user_pw(fko_cli_options_t *options, int crypt_op);
static void display_ctx(fko_ctx_t ctx);
void  errmsg(char *msg, int err);

int
main(int argc, char **argv)
{
    fko_ctx_t           ctx, ctx2;
    int                 res;
    char               *spa_data, *version;
    char                access_buf[MAX_LINE_LEN];

    fko_cli_options_t   options;

    /* Handle command line
    */
    config_init(&options, argc, argv);

    /* Intialize the context
    */
    res = fko_new(&ctx);
    if(res != FKO_SUCCESS)
    {
        errmsg("fko_new", res);
        return(1);
    }

    /* Display version info and exit.
    */
    if (options.version) {
        fko_get_version(ctx, &version);

        fprintf(stdout, "[+] fwknop client %s, FKO protocol version %s\n",
            MY_VERSION, version);

        return(0);
    }

    /* Set up for using GPG if specified.
    */
    if(options.use_gpg)
    {
        /* If use-gpg-agent was not specified, then remove the GPG_AGENT_INFO
         * ENV variable if it exists.
        */
#ifndef WIN32
        if(!options.use_gpg_agent)
            unsetenv("GPG_AGENT_INFO");
#endif

        res = fko_set_spa_encryption_type(ctx, FKO_ENCRYPTION_GPG);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_spa_encryption_type", res);
            return(1);
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
                errmsg("fko_set_gpg_home_dir", res);
                return(1);
            }
        }

        res = fko_set_gpg_recipient(ctx, options.gpg_recipient_key);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_gpg_recipient", res);

            if(IS_GPG_ERROR(res))
                fprintf(stderr, "GPG ERR: %s\n", fko_gpg_errorstr(ctx));
    
            return(1);
        }

        if(options.gpg_signer_key != NULL && strlen(options.gpg_signer_key))
        {
            res = fko_set_gpg_signer(ctx, options.gpg_signer_key);
            if(res != FKO_SUCCESS)
            {
                errmsg("fko_set_gpg_signer", res);

                if(IS_GPG_ERROR(res))
                    fprintf(stderr, "GPG ERR: %s\n", fko_gpg_errorstr(ctx));

                return(1);
            }
        }
    }

    /* Set a message string by combining the allow IP and the port/protocol
    */
    snprintf(access_buf, MAX_LINE_LEN, "%s%s%s",
            options.allow_ip_str, ",", options.access_str);
    res = fko_set_spa_message(ctx, access_buf);
    if(res != FKO_SUCCESS)
    {
        errmsg("fko_set_spa_message", res);
        return(1);
    }

    /* Set Digest type.
    */
    if(options.digest_type)
    {
        fko_set_spa_digest_type(ctx, options.digest_type);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_spa_digest_type", res);
            return(1);
        }
    }

    /* Finalize the context data (encrypt and encode the SPA data)
    */
    res = fko_spa_data_final(ctx, get_user_pw(&options, CRYPT_OP_ENCRYPT));
    if(res != FKO_SUCCESS)
    {
        errmsg("fko_spa_data_final", res);

        if(IS_GPG_ERROR(res))
            fprintf(stderr, "GPG ERR: %s\n", fko_gpg_errorstr(ctx));

        return(1);
    }

    /* Display the context data.
    */
    if (options.verbose || options.test)
        display_ctx(ctx);

    /* Save packet data payload if requested.
    */
    if (options.save_packet_file[0] != 0x0)
        write_spa_packet_data(ctx, &options);

    /* If not in test mode, send the SPA data across the wire with a
     * protocol/port specified on the command line (default is UDP/62201).
     * Otherwise, run through a decode cycle (--DSS XXX: This test/decode
     * portion should be moved elsewhere).
    */
    if (!options.test)
    {
        res = send_spa_packet(ctx, &options);
        if(res < 0)
        {
            perror("send_spa_packet");
            return(1);
        }
        else
        {
            if(options.verbose)
                fprintf(stderr, "[+] send_spa_packet: bytes sent: %i\n", res);
        }
    }
    else
    {
        /************** Decoding now *****************/

        /* Now we create a new context based on data from the first one.
        */
        res = fko_get_spa_data(ctx, &spa_data);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_get_spa_data", res);
            return(1);
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
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_new_with_data", res);
            return(1);
        }

        /* See if we are using gpg and if we need to set the GPG home dir.
        */
        if(options.use_gpg)
        {
            if(options.gpg_home_dir != NULL && strlen(options.gpg_home_dir) > 0)
            {
                res = fko_set_gpg_home_dir(ctx2, options.gpg_home_dir);
                if(res != FKO_SUCCESS)
                {
                    errmsg("fko_set_gpg_home_dir", res);
                    return(1);
                }
            }
        }

        res = fko_decrypt_spa_data(
            ctx2, get_user_pw(&options, CRYPT_OP_DECRYPT)
        );

        if(res != FKO_SUCCESS)
        {
            errmsg("fko_decrypt_spa_data", res);

            if(IS_GPG_ERROR(res))
                fprintf(stderr, "GPG ERR: %s\n", fko_gpg_errorstr(ctx2));

            return(1);
        }

        printf("\nDump of the Decoded Data\n");
        display_ctx(ctx2);

        fko_destroy(ctx2);
    }

    fko_destroy(ctx);

    return(0);
}

/* Prompt for and receive a user password.
*/
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

/* Display an FKO error message.
*/
void
errmsg(char *msg, int err) {
    fprintf(stderr, "[*] %s: %s: Error %i - %s\n",
        MY_NAME, msg, err, fko_errstr(err));
}

/* Show the fields of the FKO context.
*/
static void
display_ctx(fko_ctx_t ctx)
{
    char       *rand_val        = NULL;
    char       *username        = NULL;
    char       *version         = NULL;
    char       *spa_message     = NULL;
    char       *nat_access      = NULL;
    char       *server_auth     = NULL;
    char       *enc_data        = NULL;
    char       *spa_digest      = NULL;
    char       *spa_data        = NULL;

    time_t      timestamp       = 0;
    short       msg_type        = -1;
    short       digest_type     = -1;
    int         client_timeout  = -1;

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

    printf("\nFKO Field Values:\n=================\n\n");
    printf("   Random Value: %s\n", rand_val == NULL ? "<NULL>" : rand_val);
    printf("       Username: %s\n", username == NULL ? "<NULL>" : username);
    printf("      Timestamp: %u\n", timestamp);
    printf("    FKO Version: %s\n", version == NULL ? "<NULL>" : version);
    printf("   Message Type: %i\n", msg_type);
    printf(" Message String: %s\n", spa_message == NULL ? "<NULL>" : spa_message);
    printf("     Nat Access: %s\n", nat_access == NULL ? "<NULL>" : nat_access);
    printf("    Server Auth: %s\n", server_auth == NULL ? "<NULL>" : server_auth);
    printf(" Client Timeout: %u\n", client_timeout);
    printf("    Digest Type: %u\n", digest_type);
    printf("\n   Encoded Data: %s\n", enc_data == NULL ? "<NULL>" : enc_data);
    printf("\nSPA Data Digest: %s\n", spa_digest == NULL ? "<NULL>" : spa_digest);
    printf("\nFinal Packed/Encrypted/Encoded Data:\n\n%s\n\n", spa_data);
}

/***EOF***/
