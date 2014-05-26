#include <stdio.h>
#include <stdlib.h>
#include "../../config.h"
#include "fko.h"

#if HAVE_LIBFIU
  #include <fiu.h>
  #include <fiu-control.h>
#endif

int main(void) {
    fko_ctx_t       ctx = NULL;
    int             res = 0;

    res = fko_new(&ctx);

    if (res == FKO_SUCCESS)
        printf("[+] fko_new(): %s\n", fko_errstr(res));
    else
        printf("[-] fko_new(): %s\n", fko_errstr(res));

    fko_destroy(ctx);

    return 0;
}
