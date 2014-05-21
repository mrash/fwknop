#include <stdio.h>
#include <stdlib.h>
#include <fiu-local.h>
#include <fiu-control.h>
#include "fko.h"

int main(void) {
    fko_ctx_t       ctx = NULL;
    int             res = 0;

    fiu_init(0);

    if (0) {
    fiu_enable("fko_strdup1", FKO_ERROR_MEMORY_ALLOCATION, NULL, 0);
    res = fko_new(&ctx);
    if (res == FKO_SUCCESS)
        printf("[-] fko_new(): %s\n", fko_errstr(res));
    else
        printf("[+] fko_new(): %s\n", fko_errstr(res));
    fko_destroy(ctx);
    fiu_disable("fko_strdup1");
    }

    fiu_enable("fko_set_rand_value1", FKO_ERROR_MEMORY_ALLOCATION, NULL, 0);
    res = fko_new(&ctx);
    if (res == FKO_SUCCESS)
        printf("[-] fko_new(): %s\n", fko_errstr(res));
    else
        printf("[+] fko_new(): %s\n", fko_errstr(res));
    fko_destroy(ctx);
    fiu_disable("fko_set_rand_value1");

    return 0;
}
