#!/bin/sh -x

TEST_CASES_DIR=test-cases

LD_LIBRARY_PATH=../../lib/.libs afl-cmin -i $TEST_CASES_DIR/spa-pkts -o $TEST_CASES_DIR/spa-pkts.cmin  ../../server/.libs/fwknopd -c ../conf/default_fwknopd.conf -a ../conf/default_access.conf -A -f -t

exit $?
