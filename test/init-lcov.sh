#!/bin/sh -x

. ./lcov.env

cd ..
[ ! -d $TOP_DIR ] && mkdir $TOP_DIR
[ -d $LCOV_RESULTS_DIR ] && rm -rf $LCOV_RESULTS_DIR
[ ! -d $LCOV_RESULTS_DIR ] && mkdir $LCOV_RESULTS_DIR

lcov --rc lcov_branch_coverage=1 --no-checksum --zerocounters --directory .
lcov --rc lcov_branch_coverage=1 --no-checksum --capture --initial --directory . --output-file $LCOV_BASE

cd $TOP_DIR
exit
