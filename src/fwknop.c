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

/* Used be the getpw function below.
*/
#define CRYPT_OP_ENCRYPT 1
#define CRYPT_OP_DECRYPT 2
char* getpw(fko_cli_options_t *options, int crypt_op);

int
main(int argc, char **argv)
{
    fko_ctx_t           ctx, ctx2;
    int                 res;
    char               *pw;

    fko_cli_options_t   options;

    /* Handle command line
    */
    config_init(&options, argc, argv);

    /* Intialize the context
    */
    res = fko_new(&ctx);
    if(res != FKO_SUCCESS)
        fprintf(stderr, "Error #%i from fko_new: %s\n", res, fko_errstr(res));

    if (options.version) {
        fprintf(stdout, "[+] fwknop-%s\n", fko_version(ctx));
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

            exit(1);
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
    
            exit(1);
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

            exit(1);
        }
    }

    /* Set message type
    res = fko_set_spa_message_type(ctx, FKO_ACCESS_MSG);
    if(res != FKO_SUCCESS)
        fprintf(stderr, "Error #%i from fko_set_spa_message_type: %s\n", res, fko_errstr(res));
    */

    /* Set a message string
    */
    res = fko_set_spa_message(ctx, "0.0.0.0,tcp/22");
    if(res != FKO_SUCCESS)
    {
        fprintf(stderr, "Error #%i from fko_set_spa_message: %s\n", res, fko_errstr(res));
        exit(1);
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

            exit(1);
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
    res = fko_spa_data_final(ctx, getpw(&options, CRYPT_OP_ENCRYPT));
    if(res != FKO_SUCCESS)
    {
        fprintf(stderr,
            "Error #%i from fko_spa_data_final: %s\n",
            res, fko_errstr(res)
        );

        if(IS_GPG_ERROR(res))
            fprintf(stderr, "GPG ERR: %s\n", fko_gpg_errorstr(ctx));

        exit(1);
    }

    /* Display the context data.
    */
    if (! options.quiet)
        display_ctx(ctx);

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
        res = fko_new_with_data(&ctx2, fko_get_spa_data(ctx),
                                getpw(&options, CRYPT_OP_DECRYPT));
        if(res != FKO_SUCCESS)
        {
            fprintf(stderr,
                "Error #%i from fko_new_with_data: %s\n",
                res, fko_errstr(res)
            );

            if(IS_GPG_ERROR(res))
                fprintf(stderr, "GPG ERR: %s\n", fko_gpg_errorstr(ctx));

            exit(1);
        }

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
getpw(fko_cli_options_t *options, int crypt_op)
{
    if(options->use_gpg)
    {
        return(options->use_gpg_agent ? ""
            : getpasswd("Enter passphrase for secret key: "));
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
    printf("\nFKO Context Values:\n===================\n\n");

    printf(
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
        fko_get_rand_value(ctx),
        (fko_get_username(ctx) == NULL) ? "<NULL>" : fko_get_username(ctx),
        fko_get_timestamp(ctx),
        fko_version(ctx),
        fko_get_spa_message_type(ctx),
        (fko_get_spa_message(ctx) == NULL) ? "<NULL>" : fko_get_spa_message(ctx),
        (fko_get_spa_nat_access(ctx) == NULL) ? "<NULL>" : fko_get_spa_nat_access(ctx),
        (fko_get_spa_server_auth(ctx) == NULL) ? "<NULL>" : fko_get_spa_server_auth(ctx),
        fko_get_spa_client_timeout(ctx),
        fko_get_spa_digest_type(ctx),
        (fko_get_encoded_data(ctx) == NULL) ? "<NULL>" : fko_get_encoded_data(ctx),
        (fko_get_spa_digest(ctx) == NULL) ? "<NULL>" : fko_get_spa_digest(ctx),

        (fko_get_spa_data(ctx) == NULL) ? "<NULL>" : fko_get_spa_data(ctx)
    );

}

/***EOF***/
