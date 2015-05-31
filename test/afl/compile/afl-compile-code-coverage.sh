#!/bin/sh -x
#
# Recompile fwknop with AFL code enabled, but without using afl-gcc. The
# purpose of this is to allow the generated fuzzing corpus under an AFL
# fuzzing run to be sent back through the fwknop code to see which
# functions/lines were executed by AFL. This can be used to help tune the
# original test case inputs. A main consumer of fwknop compiled in this way
# is the afl-cov project (https://github.com/mrash/afl-cov/) which shows code
# coverage achieved by test inputs.
#

cd ../../

./extras/apparmor/configure_args.sh --enable-afl-fuzzing --enable-profile-coverage $@

if [ $? -ne 0 ]
then
    echo "[*] autogen configure script failure, exiting"
    exit 1
fi

make clean
make

cd test/afl

exit $?
