#!/bin/sh -x

cd ..
./rm-coverage-files.sh
cd afl

./compile/afl-compile.sh --enable-profile-coverage

exit $?
