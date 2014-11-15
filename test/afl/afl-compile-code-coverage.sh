#!/bin/sh -x

cd ..
./rm-coverage-files.sh
cd afl

./afl-compile.sh --enable-profile-coverage

exit
