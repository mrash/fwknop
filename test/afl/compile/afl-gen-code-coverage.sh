#!/bin/sh -x

RESULTS_DIR=afl-lcov-results
[ -d $RESULTS_DIR ] && rm -rf $RESULTS_DIR

cd ..
./gen-coverage-report.sh
mv lcov-results afl/$RESULTS_DIR
cd afl

echo "[+] Code coverage available in the $RESULTS_DIR/ directory"

exit $?
