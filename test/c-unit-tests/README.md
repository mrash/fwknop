# Build
~~~
$ ./autogen.sh
$ ./configure --enable-c-unit-tests --prefix=/usr --sysconfdir=/etc --enable-profile-coverage
$ make
~~~

~~~
$ ./test-fwknop.pl --enable-profile-coverage-check --loopback lo
~~~

The HAVE_C_UNIT_TESTS constant is used in source files to define c-unit test code. 
Source code is built against libcunit.

# Run test suites
Once the build is complete, two test programs allow the user to run the tests suites:

 * fwknopd_utests: program to run fwknopd c unit test suites
 * fwknop_utests: program to run fwknop c unit test suites

~~~
$ test/c-unit-tests/fwknopd_utests

     CUnit - A unit testing framework for C - Version 2.1-2
     http://cunit.sourceforge.net/

Suite: Access test suite
  Test: check compare_port_list function ...FAILED
    1. ../../server/access.c:2017  - compare_port_list(acc_pl, in1_pl, 0) == 0

Run Summary:    Type  Total    Ran Passed Failed Inactive
              suites      1      1    n/a      0        0
               tests      1      1      0      1        0
             asserts      6      6      5      1      n/a

Elapsed time =    0.000 seconds
~~~

~~~
$ test/c-unit-tests/fwknop_utests

     CUnit - A unit testing framework for C - Version 2.1-2
     http://cunit.sourceforge.net/

Suite: Config init test suite
  Test: Check critcial vars ...passed
  Test: Check var_bitmask functions ...passed

Run Summary:    Type  Total    Ran Passed Failed Inactive
              suites      1      1    n/a      0        0
               tests      2      2      2      0        0
             asserts     12     12     12      0      n/a

Elapsed time =    0.000 seconds
~~~

# Manage C unit tests
C unit tests are implemented in source files directly and registered in a test suite.
All test suites are then added to fwknopd or fwknop test programs

In order to add new tests, the user must follow the below steps:

 * Declare the tests suite
 * Declare an initialization function
 * Declare a cleanup function
 * Create one or more unit tests
 * Create a function to register new tests

## Declare the tests suite

In access.c file:

~~~
 #ifdef HAVE_C_UNIT_TESTS
 DECLARE_TEST_SUITE(access, "Access test suite");
 #endif
~~~

In the above example, we create a test suite using the DECLARE_TEST_SUITE macro:
 
 * the test suite is named "access".
 * the test suite description is "Access test suite" and is displayed on the console 
   when the test program is executed

## Declare an initialization function

To declare an init function to execute before runnning the test suite to initiize the context use the DECLARE_TEST_SUITE_INIT macro as follow:

    DECLARE_TEST_SUITE_INIT(filename)

~~~
DECLARE_TEST_SUITE_INIT(access)
{
    log_set_verbosity(LOG_VERBOSITY_ERROR);
    return 0;
}
~~~

In the above example, the log message verbosity is decreeased to error to only display error messages since debug messages are useless.

## Declare a cleanup function

To declare a cleanup function to execute at the end of the test suite to cleanup the context use the DECLARE_TEST_SUITE_CLEANUP macro as follow:

    DECLARE_TEST_SUITE_CLEANUP(filename)

~~~
DECLARE_TEST_SUITE_CLEANUP(access)
{
    return 0;
}
~~~

In the above example, the cleanup function returns 0 and does strictly nothing. There is no need to declare such function and
thus could be replaced by a NULL pointer at test suite initialization

## Create unit tests

In access.c file:

~~~
#ifdef HAVE_C_UNIT_TESTS


DECLARE_UTEST(compare_port_list, "check compare_port_list function")
{
    acc_port_list_t *in1_pl = NULL;
    acc_port_list_t *in2_pl = NULL;
    acc_port_list_t *acc_pl = NULL;

    /* Match any test */
    free_acc_port_list(in1_pl);
    free_acc_port_list(acc_pl);
    add_port_list_ent(&in1_pl, "udp/6002");
    add_port_list_ent(&in2_pl, "udp/6002, udp/6003");
    add_port_list_ent(&acc_pl, "udp/6002, udp/6003");
    CU_ASSERT(compare_port_list(in1_pl, acc_pl, 1) == 1);       /* Only one match is needed from access port list - 1 */
    CU_ASSERT(compare_port_list(in2_pl, acc_pl, 1) == 1);       /* Only match is needed from access port list - 2 */
    CU_ASSERT(compare_port_list(in1_pl, acc_pl, 0) == 1);       /* All ports must match access port list - 1 */
    CU_ASSERT(compare_port_list(in2_pl, acc_pl, 0) == 1);       /* All ports must match access port list - 2 */
    CU_ASSERT(compare_port_list(acc_pl, in1_pl, 0) == 0);       /* All ports must match in1 port list - 1 */
    CU_ASSERT(compare_port_list(acc_pl, in2_pl, 0) == 1);       /* All ports must match in2 port list - 2 */
}

#endif /* HAVE_C_UNIT_TESTS */
~~~

In the above example, we create a c-unit test using the DECLARE_UTEST macro:

 * the unit test is named "compare_port_list". This id must be unique
 * the unit test description is "check compare_port_list function" and is displayed on the console 
   when the test program is executed

## Create a function to register new tests

In access.c file:

~~~
#ifdef HAVE_C_UNIT_TESTS

int register_ts_access(void)
{
    ts_init(&TEST_SUITE(access), TEST_SUITE_DESCR(access), TEST_SUITE_INIT(access), TEST_SUITE_CLEANUP(access));
    ts_add_utest(&TEST_SUITE(access), UTEST_FCT(compare_port_list), UTEST_DESCR(compare_port_list));

    return register_ts(&TEST_SUITE(access));
}
#endif /* HAVE_C_UNIT_TESTS */
~~~

If no init or cleanup function is defined, they have to be replaced by a NULL pointer at test suite initialization.

In access.h file:

~~~
#ifdef HAVE_C_UNIT_TESTS
int register_ts_access(void);
#endif
~~~
In fwknopd_utests.c file:

~~~
static void register_test_suites(void)
{
        register_ts_access();
}
~~~

The register_ts_access function create the new test suite and add unit test to it.

## Check gcov coverage