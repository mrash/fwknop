#!/bin/sh -x

HANG_DIR="fuzzing-output/client-rc.out/hangs"
HELPER_SH="fuzzing-wrappers/helpers/fwknop-rc-test.sh"

for f in `find $HANG_DIR -name 'id*'`
do
    ./$HELPER_SH $f
done

exit $?
