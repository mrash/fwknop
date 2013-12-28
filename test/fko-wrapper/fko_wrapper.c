/*
 * This code is designed to repeatedly call libfko functions multiple times
 * with and without calling fko_destroy().  This allows valgrind to verify
 * whether memory is properly handled between calls.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "fko.h"

#define ENABLE_GPG_TESTS 0
#define FCN_CALLS        5
#define CTX_DESTROY      0
#define NO_CTX_DESTROY   1
#define NEW_CTX          0
#define NO_NEW_CTX       1

static void display_ctx(fko_ctx_t ctx);
static void test_loop(int new_ctx_flag, int destroy_ctx_flag);
static void spa_func_exec_int(fko_ctx_t *ctx, char *name,
        int (*spa_func)(fko_ctx_t ctx, const int modifier), int min, int max,
        int final_val, int new_ctx_flag, int destroy_ctx_flag);
static void spa_func_exec_short(fko_ctx_t *ctx, char *name,
        int (*spa_func)(fko_ctx_t ctx, const short modifier), int min, int max,
        int final_val, int new_ctx_flag, int destroy_ctx_flag);

int main(void) {
    int i;

    test_loop(NO_NEW_CTX, NO_CTX_DESTROY);
    test_loop(NEW_CTX, CTX_DESTROY);
    test_loop(NEW_CTX, NO_CTX_DESTROY);
    test_loop(NO_NEW_CTX, CTX_DESTROY);

    /* call fko_errstr() across valid and invalid values
    */
    for (i=-5; i < FKO_LAST_ERROR+5; i++)
        printf("libfko error (%d): %s\n", i, fko_errstr(i));

    return 0;
}

static void
test_loop(int new_ctx_flag, int destroy_ctx_flag)
{
    fko_ctx_t  ctx = NULL, decrypt_ctx = NULL;
    int        i;
    char       *spa_data = NULL;

    printf("fko_new(): %s\n", fko_errstr(fko_new(&ctx)));
    fko_destroy(ctx);
    ctx = NULL;
    printf("fko_new(): %s\n", fko_errstr(fko_new(&ctx)));

    spa_func_exec_int(&ctx, "fko_set_spa_client_timeout",
            &fko_set_spa_client_timeout, -100, 100, 10,
            new_ctx_flag, destroy_ctx_flag);

    spa_func_exec_short(&ctx, "fko_set_spa_message_type",
            &fko_set_spa_message_type, -100, 100, FKO_ACCESS_MSG,
            new_ctx_flag, destroy_ctx_flag);

    spa_func_exec_int(&ctx, "fko_set_timestamp",
            &fko_set_spa_client_timeout, -100, 100, 10,
            new_ctx_flag, destroy_ctx_flag);

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_set_spa_message(1.1.1.1,tcp/22): %s\n",
                fko_errstr(fko_set_spa_message(ctx, "1.1.1.1,tcp/22")));
        if (destroy_ctx_flag == CTX_DESTROY)
        {
            fko_destroy(ctx);
            ctx = NULL;
        }
    }

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_set_spa_nat_access(1.2.3.4,1234): %s\n",
                fko_errstr(fko_set_spa_nat_access(ctx, "1.2.3.4,1234")));
        if (destroy_ctx_flag == CTX_DESTROY)
        {
            fko_destroy(ctx);
            ctx = NULL;
        }
    }

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_set_username(someuser): %s\n",
                fko_errstr(fko_set_username(ctx, "someuser")));
        if (destroy_ctx_flag == CTX_DESTROY)
        {
            fko_destroy(ctx);
            ctx = NULL;
        }
    }

    spa_func_exec_short(&ctx, "fko_set_spa_encryption_type",
            &fko_set_spa_encryption_type, -100, 100, FKO_ENCRYPTION_RIJNDAEL,
            new_ctx_flag, destroy_ctx_flag);

    spa_func_exec_int(&ctx, "fko_set_spa_encryption_mode",
            &fko_set_spa_encryption_mode, -100, 100, FKO_ENC_MODE_CBC,
            new_ctx_flag, destroy_ctx_flag);

    if (ENABLE_GPG_TESTS) {
        for (i=0; i<FCN_CALLS; i++) {
            printf("fko_set_spa_encryption_type(FKO_ENCRYPTION_GPG): %s\n",
                    fko_errstr(fko_set_spa_encryption_type(ctx, FKO_ENCRYPTION_GPG)));
            if (destroy_ctx_flag == CTX_DESTROY)
            {
                fko_destroy(ctx);
                ctx = NULL;
            }
        }

        for (i=0; i<FCN_CALLS; i++) {
            printf("fko_set_gpg_home_dir(/home/mbr/.gnupg): %s\n",
                    fko_errstr(fko_set_gpg_home_dir(ctx, "/home/mbr/.gnupg")));
            if (destroy_ctx_flag == CTX_DESTROY)
            {
                fko_destroy(ctx);
                ctx = NULL;
            }
        }

        for (i=0; i<FCN_CALLS; i++) {
            printf("fko_set_gpg_recipient(1234asdf): %s\n",
                fko_errstr(fko_set_gpg_recipient(ctx, "1234asdf")));
            if (destroy_ctx_flag == CTX_DESTROY)
            {
                fko_destroy(ctx);
                ctx = NULL;
            }

        }
    }

    spa_func_exec_short(&ctx, "fko_set_spa_digest_type",
            &fko_set_spa_digest_type, -100, 100, FKO_DEFAULT_DIGEST,
            new_ctx_flag, destroy_ctx_flag);

    spa_func_exec_short(&ctx, "fko_set_spa_hmac_type",
            &fko_set_spa_hmac_type, -100, 100, FKO_HMAC_SHA256,
            new_ctx_flag, destroy_ctx_flag);

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_spa_data_final(testtest, 8, hmactest, 8): %s\n",
                fko_errstr(fko_spa_data_final(ctx, "testtest", 8, "hmactest", 8)));
        if (destroy_ctx_flag == CTX_DESTROY)
        {
            fko_destroy(ctx);
            ctx = NULL;
        }
    }

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_get_spa_data(): %s\n",
                fko_errstr(fko_get_spa_data(ctx, &spa_data)));
        printf("    %s\n", spa_data == NULL ? "<NULL>" : spa_data);
        if (destroy_ctx_flag == CTX_DESTROY)
        {
            fko_destroy(ctx);
            ctx = NULL;
        }
    }

    printf("fko_new_with_data(): %s\n",
        fko_errstr(fko_new_with_data(&decrypt_ctx, spa_data, NULL,
        0, FKO_ENC_MODE_CBC, NULL, 0, FKO_HMAC_SHA256)));

    /* verify hmac, decrypt, and display ctx all together*/
    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_verify_hmac(): %s\n",
            fko_errstr(fko_verify_hmac(decrypt_ctx, "hmactest", 8)));

        printf("fko_decrypt_spa_data(): %s\n",
            fko_errstr(fko_decrypt_spa_data(decrypt_ctx, "testtest", 8)));

        display_ctx(decrypt_ctx);

        if (destroy_ctx_flag == CTX_DESTROY)
        {
            fko_destroy(ctx);
            ctx = NULL;
        }
    }

    /* now, separately verify hmac, decrypt, and display ctx */
    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_verify_hmac(): %s\n",
            fko_errstr(fko_verify_hmac(decrypt_ctx, "hmactest", 8)));
        if (destroy_ctx_flag == CTX_DESTROY)
        {
            fko_destroy(ctx);
            ctx = NULL;
        }
    }

    /* now decrypt */
    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_decrypt_spa_data(): %s\n",
            fko_errstr(fko_decrypt_spa_data(decrypt_ctx, "testtest", 8)));
        if (destroy_ctx_flag == CTX_DESTROY)
        {
            fko_destroy(ctx);
            ctx = NULL;
        }
    }

    for (i=0; i<FCN_CALLS; i++) {
        display_ctx(decrypt_ctx);
        if (destroy_ctx_flag == CTX_DESTROY)
        {
            fko_destroy(ctx);
            ctx = NULL;
        }
    }

    for (i=0; i<FCN_CALLS; i++) {
        fko_destroy(ctx);
        ctx = NULL;
    }

    for (i=0; i<FCN_CALLS; i++) {
        fko_destroy(decrypt_ctx);
        decrypt_ctx = NULL;
    }

    return;
}


static void spa_func_exec_int(fko_ctx_t *ctx, char *name,
        int (*spa_func)(fko_ctx_t ctx, const int modifier), int min, int max,
        int final_val, int new_ctx_flag, int destroy_ctx_flag)
{
    int i;

    printf("[+] calling libfko function: %s\n", name);
    for (i=min; i <= max; i++) {
        printf("%s(%d): %s\n", name, i, fko_errstr((spa_func)(*ctx, i)));
        printf("%s(%d): %s (DUPE)\n", name, i, fko_errstr((spa_func)(*ctx, i)));
        if (destroy_ctx_flag == CTX_DESTROY)
        {
            fko_destroy(*ctx);
            *ctx = NULL;
        }
        if (new_ctx_flag == NEW_CTX) {
            fko_destroy(*ctx);  /* always destroy before re-creating */
            *ctx = NULL;
            printf("fko_new(): %s\n", fko_errstr(fko_new(ctx)));
        }
    }
    printf("%s(%d): %s (FINAL)\n", name, final_val,
            fko_errstr((spa_func)(*ctx, final_val)));
    display_ctx(*ctx);
    return;
}

static void spa_func_exec_short(fko_ctx_t *ctx, char *name,
        int (*spa_func)(fko_ctx_t ctx, const short modifier), int min, int max,
        int final_val, int new_ctx_flag, int destroy_ctx_flag)
{
    int i;

    printf("[+] calling libfko function: %s\n", name);
    for (i=min; i <= max; i++) {
        printf("%s(%d): %s\n", name, i, fko_errstr((spa_func)(*ctx, i)));
        printf("%s(%d): %s (DUPE)\n", name, i, fko_errstr((spa_func)(*ctx, i)));
        if (destroy_ctx_flag == CTX_DESTROY)
        {
            fko_destroy(*ctx);
            *ctx = NULL;
        }
        if (new_ctx_flag == NEW_CTX) {
            fko_destroy(*ctx);  /* always destroy before re-creating */
            *ctx = NULL;
            printf("fko_new(): %s\n", fko_errstr(fko_new(ctx)));
        }
    }
    printf("%s(%d): %s (FINAL)\n", name, final_val,
            fko_errstr((spa_func)(*ctx, final_val)));
    display_ctx(*ctx);
    return;
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
    printf(" Client Timeout: %d\n", client_timeout);
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
