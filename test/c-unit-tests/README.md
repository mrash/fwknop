# Build

C unit library is used to perform c unit testing. Source code associated to those tests
must be started with

~~~
#ifdef HAVE_C_UNIT_TESTS
~~~

and closed with:

~~~
#endif /* HAVE_C_UNIT_TESTS */
~~~
In order to build the test suite use the following commands with the **--enable-c-unit-tests**
switch

~~~
$ ./autogen.sh
$ ./configure --enable-c-unit-tests --prefix=/usr --sysconfdir=/etc --enable-profile-coverage
$ make
~~~

~~~
$ ./test-fwknop.pl --enable-profile-coverage-check --loopback lo --client-only-mode
~~~

# Run test suites
Once the build is complete, three test programs allow the user to run the tests suites:

 * fwknopd_utests: program to run fwknopd c unit test suites
 * fwknop_utests: program to run fwknop c unit test suites
 * fko_utests: program to run fko c unit test suites

~~~
$ test/c-unit-tests/fwknopd_utests

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

Suite: Config init test suite
  Test: Check critcial vars ...passed
  Test: Check var_bitmask functions ...passed

Run Summary:    Type  Total    Ran Passed Failed Inactive
              suites      1      1    n/a      0        0
               tests      2      2      2      0        0
             asserts     12     12     12      0      n/a

Elapsed time =    0.000 seconds
~~~

~~~
$ test/c-unit-tests/fko_utests

Suite: FKO decode test suite
  Test: Count the number of SPA fields in a SPA packet ...passed
  Test: Count the number of bytes to the last : ...passed

Run Summary:    Type  Total    Ran Passed Failed Inactive
              suites      1      1    n/a      0        0
               tests      2      2      2      0        0
             asserts     19     19     19      0      n/a

Elapsed time =    0.000 seconds
~~~

# Manage C unit tests
C unit tests are implemented in source files and registered in a test suite.
All test suites are then added to fwknopd, fwknop or fko test programs

In order to add new tests, the user must follow the below steps:

 * Declare a test suite
 * Declare an initialization function
 * Declare a clean up function
 * Create one or more unit tests
 * Create a function to register new tests
 
## Declare a test suite

In *source* file:

~~~
 #ifdef HAVE_C_UNIT_TESTS
 DECLARE_TEST_SUITE(access, "Access test suite");
 #endif
~~~

In the above example, we create a test suite using the **DECLARE_TEST_SUITE** macro:
 
 * the test suite is named "access".
 * the test suite description is "Access test suite" and is displayed on the console 
   when the test program is executed

## Declare an initialization function

Before running the test suite, an init function can be used to initialize the test suite context.
To declare such a function use the **DECLARE_TEST_SUITE_INIT** macro.

In *source* file:

~~~
DECLARE_TEST_SUITE_INIT(access)
{
    log_set_verbosity(LOG_VERBOSITY_ERROR);
    return 0;
}
~~~

In the above example, the log message verbosity is decreased to error level to only display error
messages since debug messages are too verbose.

In some cases, there is no need for such a function and thus this declaration is not mandatory.

## Declare a clean-up function

In order to clean up the context at the end of the test suite, it is possible to declare a clean up
function with the **DECLARE_TEST_SUITE_CLEANUP** macro

In *source* file:

~~~
DECLARE_TEST_SUITE_CLEANUP(access)
{
    return 0;
}
~~~

In the above example, the clean up function returns 0 and does strictly nothing. 

In some cases, there is no need for such function and thus this declaration is not mandatory.

## Create unit tests

In *source* file:

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
    CU_ASSERT(compare_port_list(in1_pl, acc_pl, 1) == 1);
    CU_ASSERT(compare_port_list(in2_pl, acc_pl, 1) == 1);
    CU_ASSERT(compare_port_list(in1_pl, acc_pl, 0) == 1);
    CU_ASSERT(compare_port_list(in2_pl, acc_pl, 0) == 1);
    CU_ASSERT(compare_port_list(acc_pl, in1_pl, 0) == 0);
    CU_ASSERT(compare_port_list(acc_pl, in2_pl, 0) == 1);
}

#endif /* HAVE_C_UNIT_TESTS */
~~~

In the above example, we create a c-unit test using the **DECLARE_UTEST** macro:

 * The unit test is named "compare_port_list" ; This id must be unique
 * The unit test description is "check compare_port_list function" and is displayed on the console 
   when the test program is executed

## Create a function to register new tests

We have previously declared unit tests, but they have to be registered to a test suite
to be executed.

In *source* file:

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

If no init or cleanup function is defined, they have to be replaced by a NULL pointer
at test suite initialization : **ts_init**

Each unit test must be added using **ts_add_utest** function.

In *header* file, add the register function prototype as follows:

~~~
#ifdef HAVE_C_UNIT_TESTS
int register_ts_access(void);
#endif
~~~

In the unit test program, add the test suite to the current list of existing
test suite.

~~~
static void register_test_suites(void)
{
        register_ts_access();
}
~~~

## Check gcov coverage