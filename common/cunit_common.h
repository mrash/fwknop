#ifndef CUNIT_COMMON_H
#define CUNIT_COMMON_H

	typedef struct c_unit_test
	{
		char description[128];
		void (*func)(void);
	} c_unit_test_t;
	
	typedef struct c_unit_test_suite
	{
		char description[128];
		c_unit_test_t test_array[12];
		int nb_c_unit_test;
	} c_unit_test_suite_t;

    #define UTEST_DESCR(name)       ut_descr_##name
    #define UTEST_FCT(name)         ut_##name
	#define TEST_SUITE(name)		ts_##name
	#define TEST_SUITE_DESCR(name)	ts_descr_##name
	
	#define DECLARE_TEST_SUITE(name, description)		static const char ts_descr_##name[] = description; \
														static c_unit_test_suite_t ts_##name;	
    #define DECLARE_UTEST(name, description)    		static const char ut_descr_##name[] = description;  \
														static void ut_##name(void)
												
void ts_init(c_unit_test_suite_t* ts, const char* description);
void ts_add_utest(c_unit_test_suite_t* ts, void (*utest_func)(void), const char* utest_description);
int register_ts(c_unit_test_suite_t *ts);
												
#endif // CUNIT_COMMON_H