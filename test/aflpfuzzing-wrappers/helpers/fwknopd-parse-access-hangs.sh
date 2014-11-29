#!/bin/sh -x

HANG_DIR="fuzzing-output/server-access.out/hangs"
HELPER_SH="fuzzing-wrappers/helpers/fwknopd-parse-access.sh"

for f in `find $HANG_DIR -name 'id*'`
do
    ./$HELPER_SH $f
done

exit $?
