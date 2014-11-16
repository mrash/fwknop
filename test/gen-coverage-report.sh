#!/bin/sh -x

TOP_DIR="test"
LCOV_INFO="$TOP_DIR/lcov_coverage.info"
LCOV_INFO_FINAL="$TOP_DIR/lcov_coverage_final.info"
LCOV_RESULTS_DIR="$TOP_DIR/lcov-results"

cd ..
[ ! -d $TOP_DIR ] && mkdir $TOP_DIR
[ -d $LCOV_RESULTS_DIR ] && rm -rf $LCOV_RESULTS_DIR
[ ! -d $LCOV_RESULTS_DIR ] && mkdir $LCOV_RESULTS_DIR

for d in client server
do
    cd $d
    gcov -b -u *.gcno
    cd ..
done

cd lib/.libs
gcov -b -u *.gcno
cd ../..

lcov --rc lcov_branch_coverage=1 --capture --directory . --output-file $LCOV_INFO
lcov --rc lcov_branch_coverage=1 -r $LCOV_INFO /usr/include/\* --output-file $LCOV_INFO_FINAL
genhtml --rc genhtml_branch_coverage=1 $LCOV_INFO_FINAL --output-directory $LCOV_RESULTS_DIR

cd test
exit
