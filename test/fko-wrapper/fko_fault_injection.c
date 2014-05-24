#include <stdio.h>
#include <stdlib.h>
#include <fiu-local.h>
#include <fiu-control.h>
#include "fko.h"

const char *fiu_tags[] = {
    "fko_new_calloc",
    "fko_new_strdup"
};
const int fiu_rvs[] = {
    FKO_ERROR_MEMORY_ALLOCATION,
    FKO_ERROR_MEMORY_ALLOCATION
};
const int num_fiu_tags = 2;

int main(void) {
    fko_ctx_t       ctx = NULL;
    int             res = 0, i;

    fiu_init(0);

    for (i=0; i < num_fiu_tags; i++) {
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
