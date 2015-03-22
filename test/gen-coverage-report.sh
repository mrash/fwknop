#!/bin/sh -x

. ./lcov.env

cd ..

lcov --rc lcov_branch_coverage=1 --no-checksum --capture --directory . --output-file $LCOV_INFO
lcov --rc lcov_branch_coverage=1 --no-checksum -a $LCOV_BASE -a $LCOV_INFO --output-file $LCOV_INFO_FINAL
lcov --rc lcov_branch_coverage=1 --no-checksum -r $LCOV_INFO /usr/include/\* --output-file $LCOV_INFO_FINAL
genhtml --branch-coverage --output-directory $LCOV_RESULTS_DIR --branch-coverage $LCOV_INFO_FINAL

cd $TOP_DIR
exit
