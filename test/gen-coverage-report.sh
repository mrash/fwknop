#!/bin/sh -x

. ./lcov.env

cd ..

lcov $LCOV_RC_BC --no-checksum --capture --directory . --output-file $LCOV_INFO
lcov $LCOV_RC_BC --no-checksum -a $LCOV_BASE -a $LCOV_INFO --output-file $LCOV_INFO_FINAL
lcov $LCOV_RC_BC --no-checksum -r $LCOV_INFO /usr/include/\* --output-file $LCOV_INFO_FINAL
genhtml $GENHTML_USE_BC --output-directory $LCOV_RESULTS_DIR --branch-coverage $LCOV_INFO_FINAL

cd $TOP_DIR
exit
