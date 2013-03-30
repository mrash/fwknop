/* This code is designed to call libfko functions multiple times without
 * calling fko_destroy() until the very end.  This allows valgrind to verify
 * whether memory is proerly handled between calls.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "fko_common.h"
#include "common.h"
#include "fko_limits.h"
#include "fwknop.h"
#include "fko.h"

#define ENABLE_GPG_TESTS 0
#define FCN_CALLS 5

static void display_ctx(fko_ctx_t ctx);

int main(void) {

    fko_ctx_t  ctx = NULL, decrypt_ctx = NULL;
    int        i;
    char       *spa_data;

    printf("fko_new(): %d\n", fko_new(&ctx));

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_set_spa_client_timeout(30): %d\n",
                fko_set_spa_client_timeout(ctx, 30));
    }

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_set_spa_message_type(FKO_COMMAND_MSG): %d\n",
                fko_set_spa_message_type(ctx, FKO_COMMAND_MSG));
    }

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_set_spa_message_type(FKO_ACCESS_MSG): %d\n",
                fko_set_spa_message_type(ctx, FKO_ACCESS_MSG));
    }

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_set_timestamp(%d): %d\n",
                i, fko_set_timestamp(ctx, i));
    }

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_set_spa_message(1.1.1.1,tcp/22): %d\n",
                fko_set_spa_message(ctx, "1.1.1.1,tcp/22"));
    }

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_set_spa_nat_access(1.2.3.4,1234): %d\n",
                fko_set_spa_nat_access(ctx, "1.2.3.4,1234"));
    }

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_set_username(someuser): %d\n",
                fko_set_username(ctx, "someuser"));
    }

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_set_spa_encryption_type(FKO_ENCRYPTION_RIJNDAEL): %d\n",
                fko_set_spa_encryption_type(ctx, FKO_ENCRYPTION_RIJNDAEL));
    }

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_set_spa_encryption_mode(FKO_ENC_MODE_CBC): %d\n",
                fko_set_spa_encryption_mode(ctx, FKO_ENC_MODE_CBC));
    }

    if (ENABLE_GPG_TESTS) {
        for (i=0; i<FCN_CALLS; i++) {
            printf("fko_set_spa_encryption_type(FKO_ENCRYPTION_GPG): %d\n",
                    fko_set_spa_encryption_type(ctx, FKO_ENCRYPTION_GPG));
        }

        for (i=0; i<FCN_CALLS; i++) {
            printf("fko_set_gpg_home_dir(/home/mbr/.gnupg): %d\n",
                    fko_set_gpg_home_dir(ctx, "/home/mbr/.gnupg"));
        }

        for (i=0; i<FCN_CALLS; i++) {
            printf("fko_set_gpg_recipient(1234asdf): %d\n",
                fko_set_gpg_recipient(ctx, "1234asdf"));
        }
    }

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_set_spa_digest_type(FKO_DEFAULT_DIGEST): %d\n",
                fko_set_spa_digest_type(ctx, FKO_DEFAULT_DIGEST));
    }

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_set_spa_hmac_type(FKO_HMAC_SHA256): %d\n",
                fko_set_spa_hmac_type(ctx, FKO_HMAC_SHA256));
    }

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_spa_data_final(testtest, 8, hmactest, 8): %d\n",
                fko_spa_data_final(ctx, "testtest", 8, "hmactest", 8));
    }

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_get_spa_data(): %d\n",
                fko_get_spa_data(ctx, &spa_data));
        printf("    %s\n", spa_data);
    }

    /* now decrypt */
    printf("fko_new_with_data(): %d\n",
        fko_new_with_data(&decrypt_ctx, spa_data, NULL,
        0, ctx->encryption_mode, NULL, 0, 0));

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_decrypt_spa_data(): %d\n",
            fko_decrypt_spa_data(decrypt_ctx, "testtest", 8));
    }

    for (i=0; i<FCN_CALLS; i++) {
        display_ctx(decrypt_ctx);
    }

    fko_destroy(ctx);
    fko_destroy(decrypt_ctx);

    return 0;
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
    char       *hmac_data       = NULL;
    char       *spa_digest      = NULL;
    char       *spa_data        = NULL;

    time_t      timestamp       = 0;
    short       msg_type        = -1;
    short       digest_type     = -1;
    short       hmac_type       = -1;
    int         encryption_mode = -1;
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
    fko_get_spa_hmac_type(ctx, &hmac_type);
    fko_get_spa_encryption_mode(ctx, &encryption_mode);
    fko_get_encoded_data(ctx, &enc_data);
    fko_get_spa_hmac(ctx, &hmac_data);
    fko_get_spa_digest(ctx, &spa_digest);
    fko_get_spa_data(ctx, &spa_data);

    printf("\nFKO Field Values:\n=================\n\n");
    printf("   Random Value: %s\n", rand_val == NULL ? "<NULL>" : rand_val);
    printf("       Username: %s\n", username == NULL ? "<NULL>" : username);
    printf("      Timestamp: %u\n", (unsigned int) timestamp);
    printf("    FKO Version: %s\n", version == NULL ? "<NULL>" : version);
    printf("   Message Type: %i\n", msg_type);
    printf(" Message String: %s\n", spa_message == NULL ? "<NULL>" : spa_message);
    printf("     Nat Access: %s\n", nat_access == NULL ? "<NULL>" : nat_access);
    printf("    Server Auth: %s\n", server_auth == NULL ? "<NULL>" : server_auth);
    printf(" Client Timeout: %u\n", client_timeout);
    printf("    Digest Type: %d\n", digest_type);
    printf("      HMAC Type: %d\n", hmac_type);
    printf("Encryption Mode: %d\n", encryption_mode);
    printf("\n   Encoded Data: %s\n", enc_data == NULL ? "<NULL>" : enc_data);
    printf("SPA Data Digest: %s\n", spa_digest == NULL ? "<NULL>" : spa_digest);
    printf("           HMAC: %s\n", hmac_data == NULL ? "<NULL>" : hmac_data);

    if (enc_data != NULL && spa_digest != NULL)
        printf("      Plaintext: %s:%s\n", enc_data, spa_digest);

    printf("\nFinal Packed/Encrypted/Encoded Data:\n\n%s\n\n", spa_data);
}

