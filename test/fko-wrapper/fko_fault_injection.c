#include <stdio.h>
#include <stdlib.h>
#include <fiu.h>
#include <fiu-control.h>
#include "fko.h"

const char *fiu_tags[] = {
    "fko_new_calloc",
    "fko_new_strdup",
    "fko_set_rand_value_init",
    "fko_set_rand_value_lenval",
    "fko_set_rand_value_strdup",
    "fko_set_rand_value_read",
    "fko_set_rand_value_calloc1",
    "fko_set_rand_value_calloc2",
    "fko_set_username_init",
    "fko_set_username_strdup1",
    "fko_set_username_valuser",
    "fko_set_username_strdup2",
    "fko_set_timestamp_init",
    "fko_set_timestamp_val",
    "set_spa_digest_type_init",
    "set_spa_digest_type_val",
    "fko_set_spa_encryption_type_init",
    "fko_set_spa_encryption_type_val",
    "fko_set_spa_encryption_mode_init",
    "fko_set_spa_encryption_mode_val",
    "fko_set_spa_message_type_init",
    "fko_set_spa_message_type_val"
};
const int fiu_rvs[] = {
    FKO_ERROR_MEMORY_ALLOCATION,
    FKO_ERROR_MEMORY_ALLOCATION,
    FKO_ERROR_CTX_NOT_INITIALIZED,
    FKO_ERROR_INVALID_DATA_RAND_LEN_VALIDFAIL,
    FKO_ERROR_MEMORY_ALLOCATION,
    FKO_ERROR_FILESYSTEM_OPERATION,
    FKO_ERROR_MEMORY_ALLOCATION,
    FKO_ERROR_MEMORY_ALLOCATION,
    FKO_ERROR_CTX_NOT_INITIALIZED,
    FKO_ERROR_MEMORY_ALLOCATION,
    FKO_ERROR_INVALID_DATA,
    FKO_ERROR_MEMORY_ALLOCATION,
    FKO_ERROR_CTX_NOT_INITIALIZED,
    FKO_ERROR_INVALID_DATA_TIMESTAMP_VALIDFAIL,
    FKO_ERROR_CTX_NOT_INITIALIZED,
    FKO_ERROR_INVALID_DATA_ENCODE_DIGEST_VALIDFAIL,
    FKO_ERROR_CTX_NOT_INITIALIZED,
    FKO_ERROR_INVALID_DATA_ENCRYPT_TYPE_VALIDFAIL,
    FKO_ERROR_CTX_NOT_INITIALIZED,
    FKO_ERROR_INVALID_DATA_ENCRYPT_MODE_VALIDFAIL,
    FKO_ERROR_CTX_NOT_INITIALIZED,
    FKO_ERROR_INVALID_DATA_MESSAGE_TYPE_VALIDFAIL,
    FKO_ERROR_CTX_NOT_INITIALIZED,
    FKO_ERROR_INVALID_DATA_TIMESTAMP_VALIDFAIL
};

int main(void) {
    fko_ctx_t       ctx = NULL;
    int             res = 0, i;

    fiu_init(0);

    for (i=0; i < sizeof(fiu_rvs)/sizeof(int); i++) {
        printf("[+] libfiu injection tag: %s\n", fiu_tags[i]);

        fiu_enable(fiu_tags[i], fiu_rvs[i], NULL, 0);

        res = fko_new(&ctx);
        if (res == FKO_SUCCESS)
            printf("[-] fko_new(): %s\n", fko_errstr(res));
        else
            printf("[+] fko_new(): %s\n", fko_errstr(res));
        fko_destroy(ctx);

        fiu_disable(fiu_tags[i]);
    }

    return 0;
}
