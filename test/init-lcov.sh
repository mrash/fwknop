#!/bin/sh -x

. ./lcov.env

cd ..
[ ! -d $TOP_DIR ] && mkdir $TOP_DIR
[ -d $LCOV_RESULTS_DIR ] && rm -rf $LCOV_RESULTS_DIR
[ ! -d $LCOV_RESULTS_DIR ] && mkdir $LCOV_RESULTS_DIR

lcov $LCOV_RC_BC --no-checksum --zerocounters --directory .
lcov $LCOV_RC_BC --no-checksum --capture --initial --directory . --output-file $LCOV_BASE

cd $TOP_DIR
exit
