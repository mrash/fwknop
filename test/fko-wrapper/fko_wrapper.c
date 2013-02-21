#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "fko_common.h"
#include "common.h"
#include "fko_limits.h"
#include "fwknop.h"
#include "fko.h"

#define ENABLE_GPG_TESTS 0

int main(void) {

    fko_ctx_t  ctx = NULL;
    int        i;
    char       *spa_data;

    for (i=0; i<5; i++) {
        /* call fko_new() several times without also calling fko_destroy() */
        printf("fko_new(): %d\n", fko_new(&ctx));
    }

    for (i=0; i<5; i++) {
        printf("fko_set_spa_client_timeout(30): %d\n",
                fko_set_spa_client_timeout(ctx, 30));
    }

    for (i=0; i<5; i++) {
        printf("fko_set_spa_message_type(FKO_COMMAND_MSG): %d\n",
                fko_set_spa_message_type(ctx, FKO_COMMAND_MSG));
    }

    for (i=0; i<5; i++) {
        printf("fko_set_spa_message_type(FKO_ACCESS_MSG): %d\n",
                fko_set_spa_message_type(ctx, FKO_ACCESS_MSG));
    }

    for (i=0; i<5; i++) {
        printf("fko_set_timestamp(%d): %d\n",
                i, fko_set_timestamp(ctx, i));
    }

    for (i=0; i<5; i++) {
        printf("fko_set_spa_message(1.1.1.1,tcp/22): %d\n",
                fko_set_spa_message(ctx, "1.1.1.1,tcp/22"));
    }

    for (i=0; i<5; i++) {
        printf("fko_set_spa_nat_access(1.2.3.4,1234): %d\n",
                fko_set_spa_nat_access(ctx, "1.2.3.4,1234"));
    }

    for (i=0; i<5; i++) {
        printf("fko_set_username(someuser): %d\n",
                fko_set_username(ctx, "someuser"));
    }

    for (i=0; i<5; i++) {
        printf("fko_set_spa_encryption_type(FKO_ENCRYPTION_RIJNDAEL): %d\n",
                fko_set_spa_encryption_type(ctx, FKO_ENCRYPTION_RIJNDAEL));
    }

    if (ENABLE_GPG_TESTS) {
        for (i=0; i<5; i++) {
            printf("fko_set_spa_encryption_type(FKO_ENCRYPTION_GPG): %d\n",
                    fko_set_spa_encryption_type(ctx, FKO_ENCRYPTION_GPG));
        }

        for (i=0; i<5; i++) {
            printf("fko_set_gpg_home_dir(/home/mbr/.gnupg): %d\n",
                    fko_set_gpg_home_dir(ctx, "/home/mbr/.gnupg"));
        }

        for (i=0; i<5; i++) {
            printf("fko_set_gpg_recipient(1234asdf): %d\n",
                fko_set_gpg_recipient(ctx, "1234asdf"));
        }
    }

    for (i=0; i<5; i++) {
        printf("fko_set_spa_digest_type(FKO_DEFAULT_DIGEST): %d\n",
                fko_set_spa_digest_type(ctx, FKO_DEFAULT_DIGEST));
    }

    for (i=0; i<5; i++) {
        printf("fko_spa_data_final(testtest, 8, NULL, 0): %d\n",
                fko_spa_data_final(ctx, "testtest", 8, NULL, 0));
    }

    for (i=0; i<5; i++) {
        printf("fko_get_spa_data(): %d\n",
                fko_get_spa_data(ctx, &spa_data));
        printf("    %s\n", spa_data);
    }

    fko_destroy(ctx);

    return 0;
}
