/**
 * \file lib/fko_utests.c
 *
 * \brief Main CUnit test function for libfko
 */

#include "CUnit/Basic.h"

#include "fko.h"

#include "fko_util.h"
/**
 * Register test suites from FKO files.
 *
 * The module should fetch functions according to used modules. All of them follow the same
 * naming convention.
 */
static void register_test_suites(void)
{
    register_ts_fko_decode();
    register_ts_hmac_test();
    register_ts_digest_test();
    register_ts_aes_test();
    register_utils_test();
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int main()
{
    /* initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    /* Register test suites from fko files */
    register_test_suites();

    /* RUN ALL TESTS USING THE CUNIT BASIC INTERFACE */
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return CU_get_error();
}
