#!/bin/sh -x

. ./lcov.env

cd ..
[ ! -d $TOP_DIR ] && mkdir $TOP_DIR
[ -f $LCOV_BASE ] && rm -f $LCOV_BASE
[ -f $LCOV_INFO ] && rm -f $LCOV_INFO
[ -f $LCOV_INFO_FINAL ] && rm -f $LCOV_INFO_FINAL
[ -d $LCOV_RESULTS_DIR ] && rm -rf $LCOV_RESULTS_DIR
[ ! -d $LCOV_RESULTS_DIR ] && mkdir $LCOV_RESULTS_DIR

lcov $LCOV_RC_BC --no-checksum --zerocounters --directory .
lcov $LCOV_RC_BC --no-checksum --capture --initial --directory . --output-file $LCOV_BASE

cd $TOP_DIR
exit
