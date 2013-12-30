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
#define F_INT            100
#define CTX_DESTROY      0
#define NO_CTX_DESTROY   1
#define NEW_CTX          0
#define NO_NEW_CTX       1
#define DO_PRINT         1
#define NO_PRINT         2
#define ENC_KEY          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" /* 32 bytes */
#define HMAC_KEY         "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" /* 32 bytes */

static void display_ctx(fko_ctx_t ctx);
static void test_loop(int new_ctx_flag, int destroy_ctx_flag);
static void ctx_update(fko_ctx_t *ctx, int new_ctx_flag,
        int destroy_ctx_flag, int print_flag);
static void spa_default_ctx(fko_ctx_t *ctx);

static void spa_func_int(fko_ctx_t *ctx, char *name,
        int (*spa_func)(fko_ctx_t ctx, const int modifier), int min, int max,
        int final_val, int new_ctx_flag, int destroy_ctx_flag);
static void spa_func_getset_int(fko_ctx_t *ctx, char *set_name,
        int (*spa_set)(fko_ctx_t ctx, const int modifier),
        char *get_name, int (*spa_get)(fko_ctx_t ctx, int *val),
        int min, int max, int final_val, int new_ctx_flag, int destroy_ctx_flag);

static void spa_func_getset_short(fko_ctx_t *ctx, char *set_name,
        int (*spa_set)(fko_ctx_t ctx, const short modifier),
        char *get_name, int (*spa_get)(fko_ctx_t ctx, short *val),
        int min, int max, int final_val, int new_ctx_flag, int destroy_ctx_flag);

int spa_calls = 0;

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

    printf("\n[+] Total libfko function calls: %d\n\n", spa_calls);

    return 0;
}

static void
test_loop(int new_ctx_flag, int destroy_ctx_flag)
{
    fko_ctx_t  ctx = NULL, decrypt_ctx = NULL;
    int        i, j;
    char       *spa_data = NULL;

    printf("fko_new(): %s\n", fko_errstr(fko_new(&ctx)));
    fko_destroy(ctx);
    ctx = NULL;
    printf("fko_new(): %s\n", fko_errstr(fko_new(&ctx)));

    spa_func_getset_int(&ctx, "fko_set_spa_client_timeout",
            &fko_set_spa_client_timeout, "fko_get_spa_client_timeout",
            &fko_get_spa_client_timeout, -F_INT, F_INT, 10,
            new_ctx_flag, destroy_ctx_flag);

    spa_func_getset_short(&ctx, "fko_set_spa_message_type",
            &fko_set_spa_message_type, "fko_get_spa_message_type",
            &fko_get_spa_message_type, FKO_COMMAND_MSG-F_INT,
            FKO_LAST_MSG_TYPE+F_INT, FKO_ACCESS_MSG,
            new_ctx_flag, destroy_ctx_flag);

    spa_func_int(&ctx, "fko_set_timestamp",
            &fko_set_spa_client_timeout, -F_INT, F_INT, 10,
            new_ctx_flag, destroy_ctx_flag);

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_set_spa_message(1.1.1.1,tcp/22): %s\n",
                fko_errstr(fko_set_spa_message(ctx, "1.1.1.1,tcp/22")));
        ctx_update(&ctx, new_ctx_flag, destroy_ctx_flag, DO_PRINT);
    }

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_set_spa_nat_access(1.2.3.4,1234): %s\n",
                fko_errstr(fko_set_spa_nat_access(ctx, "1.2.3.4,1234")));
        ctx_update(&ctx, new_ctx_flag, destroy_ctx_flag, DO_PRINT);
    }

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_set_username(someuser): %s\n",
                fko_errstr(fko_set_username(ctx, "someuser")));
        ctx_update(&ctx, new_ctx_flag, destroy_ctx_flag, DO_PRINT);
    }

    spa_func_getset_short(&ctx, "fko_set_spa_encryption_type",
            &fko_set_spa_encryption_type, "fko_get_spa_encryption_type",
            &fko_get_spa_encryption_type, FKO_ENCRYPTION_INVALID_DATA-F_INT,
            FKO_LAST_ENCRYPTION_TYPE+F_INT, FKO_ENCRYPTION_RIJNDAEL,
            new_ctx_flag, destroy_ctx_flag);

    spa_func_getset_int(&ctx, "fko_set_spa_encryption_mode",
            &fko_set_spa_encryption_mode, "fko_get_spa_encryption_mode",
            &fko_get_spa_encryption_mode, FKO_ENC_MODE_UNKNOWN-F_INT,
            FKO_LAST_ENC_MODE+F_INT, FKO_ENC_MODE_CBC,
            new_ctx_flag, destroy_ctx_flag);

    if (ENABLE_GPG_TESTS) {
        for (i=0; i<FCN_CALLS; i++) {
            printf("fko_set_spa_encryption_type(FKO_ENCRYPTION_GPG): %s\n",
                    fko_errstr(fko_set_spa_encryption_type(ctx, FKO_ENCRYPTION_GPG)));
            ctx_update(&ctx, new_ctx_flag, destroy_ctx_flag, DO_PRINT);
        }

        for (i=0; i<FCN_CALLS; i++) {
            printf("fko_set_gpg_home_dir(/home/mbr/.gnupg): %s\n",
                    fko_errstr(fko_set_gpg_home_dir(ctx, "/home/mbr/.gnupg")));
            ctx_update(&ctx, new_ctx_flag, destroy_ctx_flag, DO_PRINT);
        }

        for (i=0; i<FCN_CALLS; i++) {
            printf("fko_set_gpg_recipient(1234asdf): %s\n",
                fko_errstr(fko_set_gpg_recipient(ctx, "1234asdf")));
            ctx_update(&ctx, new_ctx_flag, destroy_ctx_flag, DO_PRINT);
        }
    }

    spa_func_getset_short(&ctx, "fko_set_spa_digest_type",
            &fko_set_spa_digest_type, "fko_get_spa_digest_type",
            &fko_get_spa_digest_type, FKO_DIGEST_INVALID_DATA-F_INT,
            FKO_LAST_DIGEST_TYPE+F_INT, FKO_DEFAULT_DIGEST,
            new_ctx_flag, destroy_ctx_flag);

    spa_func_getset_short(&ctx, "fko_set_raw_spa_digest_type",
            &fko_set_spa_digest_type, "fko_get_raw_spa_digest_type",
            &fko_get_spa_digest_type, FKO_DIGEST_INVALID_DATA-F_INT,
            FKO_LAST_DIGEST_TYPE+F_INT, FKO_DEFAULT_DIGEST,
            new_ctx_flag, destroy_ctx_flag);

    spa_func_getset_short(&ctx, "fko_set_spa_hmac_type",
            &fko_set_spa_hmac_type, "fko_get_spa_hmac_type",
            &fko_get_spa_hmac_type, FKO_HMAC_INVALID_DATA-F_INT,
            FKO_LAST_HMAC_MODE+F_INT, FKO_HMAC_SHA256,
            new_ctx_flag, destroy_ctx_flag);

    printf("Trying encrypt / authenticate step with bogus key lengths...\n");
    for (i=-100; i < 200; i += 10) {
        for (j=-100; j < 200; j += 10) {
            fko_spa_data_final(ctx, ENC_KEY, i, HMAC_KEY, j);
            ctx_update(&ctx, new_ctx_flag, destroy_ctx_flag, NO_PRINT);
        }
    }

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_spa_data_final(ENC_KEY, 8, HMAC_KEY, 8): %s\n",
                fko_errstr(fko_spa_data_final(ctx, ENC_KEY, 16, HMAC_KEY, 16)));
        ctx_update(&ctx, new_ctx_flag, destroy_ctx_flag, DO_PRINT);
    }

    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_get_spa_data(): %s\n",
                fko_errstr(fko_get_spa_data(ctx, &spa_data)));
        printf("    SPA DATA: %s\n", spa_data == NULL ? "<NULL>" : spa_data);
        ctx_update(&ctx, new_ctx_flag, destroy_ctx_flag, DO_PRINT);
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

        ctx_update(&ctx, new_ctx_flag, destroy_ctx_flag, DO_PRINT);
    }

    /* now, separately verify hmac, decrypt, and display ctx */
    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_verify_hmac(): %s\n",
            fko_errstr(fko_verify_hmac(decrypt_ctx, "hmactest", 8)));
        ctx_update(&ctx, new_ctx_flag, destroy_ctx_flag, DO_PRINT);
    }

    /* now decrypt */
    for (i=0; i<FCN_CALLS; i++) {
        printf("fko_decrypt_spa_data(): %s\n",
            fko_errstr(fko_decrypt_spa_data(decrypt_ctx, "testtest", 8)));
        ctx_update(&ctx, new_ctx_flag, destroy_ctx_flag, DO_PRINT);
    }

    for (i=0; i<FCN_CALLS; i++) {
        display_ctx(decrypt_ctx);
        ctx_update(&ctx, new_ctx_flag, destroy_ctx_flag, DO_PRINT);
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

static void ctx_update(fko_ctx_t *ctx, int new_ctx_flag,
        int destroy_ctx_flag, int print_flag)
{
    if (destroy_ctx_flag == CTX_DESTROY) {
        if (print_flag == DO_PRINT)
            printf("fko_destroy(): %s\n", fko_errstr(fko_destroy(*ctx)));
        else
            fko_destroy(*ctx);
        *ctx = NULL;
    }
    if (new_ctx_flag == NEW_CTX) {
        /* always destroy before re-creating */
        if (print_flag == DO_PRINT)
            printf("fko_destroy(): %s\n", fko_errstr(fko_destroy(*ctx)));
        else
            fko_destroy(*ctx);
        *ctx = NULL;

        if (print_flag == DO_PRINT)
            printf("fko_new(): %s\n", fko_errstr(fko_new(ctx)));
        else
            fko_new(ctx);
    }
    return;
}

static void spa_default_ctx(fko_ctx_t *ctx)
{
    fko_new(ctx);
    fko_spa_data_final(*ctx, ENC_KEY, 16, HMAC_KEY, 16);
    fko_set_spa_message(*ctx, "123.123.123.123,tcp/22");
    fko_spa_data_final(*ctx, ENC_KEY, 16, HMAC_KEY, 16);
    fko_set_spa_message_type(*ctx, FKO_ACCESS_MSG);
    fko_spa_data_final(*ctx, ENC_KEY, 16, HMAC_KEY, 16);
    fko_set_username(*ctx, "someuser");
    fko_spa_data_final(*ctx, ENC_KEY, 16, HMAC_KEY, 16);
    fko_set_spa_encryption_type(*ctx, FKO_ENCRYPTION_RIJNDAEL);
    fko_spa_data_final(*ctx, ENC_KEY, 16, HMAC_KEY, 16);
    fko_set_spa_encryption_mode(*ctx, FKO_ENC_MODE_CBC);
    fko_spa_data_final(*ctx, ENC_KEY, 16, HMAC_KEY, 16);
    fko_set_spa_digest_type(*ctx, FKO_DEFAULT_DIGEST);
    fko_spa_data_final(*ctx, ENC_KEY, 16, HMAC_KEY, 16);
    fko_set_spa_hmac_type(*ctx, FKO_HMAC_SHA256);
    fko_spa_data_final(*ctx, ENC_KEY, 16, HMAC_KEY, 16);
    // display_ctx(*ctx);

    spa_calls += 16;
    return;
}

static void spa_func_getset_int(fko_ctx_t *ctx, char *set_name,
        int (*spa_set)(fko_ctx_t ctx, const int modifier),
        char *get_name, int (*spa_get)(fko_ctx_t ctx, int *val),
        int min, int max, int final_val, int new_ctx_flag, int destroy_ctx_flag)
{
    fko_ctx_t default_ctx = NULL;
    int get_val;
    int i, res;

    spa_default_ctx(&default_ctx);

    printf("[+] calling libfko get/set: %s/%s\n", get_name, set_name);
    for (i=min; i <= max; i++) {
        get_val = 1234;  /* meaningless default */
        printf("%s(%d): %s\n", set_name, i, fko_errstr((spa_set)(*ctx, i)));
        printf("%s(%d): %s (DUPE)\n", set_name, i, fko_errstr((spa_set)(*ctx, i)));
        res = (spa_get)(*ctx, &get_val);
        printf("%s(%d): %s\n", get_name, get_val, fko_errstr(res));

        ctx_update(ctx, new_ctx_flag, destroy_ctx_flag, DO_PRINT);
        spa_calls += 3;

        /* also set on a fully populated context */
        (spa_set)(default_ctx, i);
    }
    printf("%s(%d): %s (FINAL)\n", set_name, final_val,
            fko_errstr((spa_set)(*ctx, final_val)));
    display_ctx(*ctx);

    fko_spa_data_final(default_ctx, ENC_KEY, 16, HMAC_KEY, 16);
    fko_destroy(default_ctx);
    default_ctx = NULL;

    return;
}

static void spa_func_int(fko_ctx_t *ctx, char *name,
        int (*spa_set)(fko_ctx_t ctx, const int modifier), int min, int max,
        int final_val, int new_ctx_flag, int destroy_ctx_flag)
{
    fko_ctx_t default_ctx = NULL;
    int i;

    spa_default_ctx(&default_ctx);

    printf("[+] calling libfko function: %s\n", name);
    for (i=min; i <= max; i++) {
        printf("%s(%d): %s\n", name, i, fko_errstr((spa_set)(*ctx, i)));
        printf("%s(%d): %s (DUPE)\n", name, i, fko_errstr((spa_set)(*ctx, i)));

        ctx_update(ctx, new_ctx_flag, destroy_ctx_flag, DO_PRINT);
        spa_calls += 2;

        /* also set on a fully populated context */
        (spa_set)(default_ctx, i);
    }
    printf("%s(%d): %s (FINAL)\n", name, final_val,
            fko_errstr((spa_set)(*ctx, final_val)));
    display_ctx(*ctx);

    fko_spa_data_final(default_ctx, ENC_KEY, 16, HMAC_KEY, 16);
    fko_destroy(default_ctx);
    default_ctx = NULL;

    return;
}

static void spa_func_getset_short(fko_ctx_t *ctx, char *set_name,
        int (*spa_set)(fko_ctx_t ctx, const short modifier),
        char *get_name, int (*spa_get)(fko_ctx_t ctx, short *val),
        int min, int max, int final_val, int new_ctx_flag, int destroy_ctx_flag)
{
    fko_ctx_t default_ctx = NULL;
    short get_val;
    int i, res;

    spa_default_ctx(&default_ctx);

    printf("[+] calling libfko get/set: %s/%s\n", get_name, set_name);
    for (i=min; i <= max; i++) {
        get_val = 1234;  /* meaningless default */
        printf("%s(%d): %s\n", set_name, i, fko_errstr((spa_set)(*ctx, i)));
        printf("%s(%d): %s (DUPE)\n", set_name, i, fko_errstr((spa_set)(*ctx, i)));
        res = (spa_get)(*ctx, &get_val);
        printf("%s(%d): %s\n", get_name, get_val, fko_errstr(res));

        ctx_update(ctx, new_ctx_flag, destroy_ctx_flag, DO_PRINT);
        spa_calls += 3;

        /* also set on a fully populated context */
        (spa_set)(default_ctx, i);
    }
    printf("%s(%d): %s (FINAL)\n", set_name, final_val,
            fko_errstr((spa_set)(*ctx, final_val)));

    display_ctx(*ctx);

    fko_spa_data_final(default_ctx, ENC_KEY, 16, HMAC_KEY, 16);
    fko_destroy(default_ctx);
    default_ctx = NULL;

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
