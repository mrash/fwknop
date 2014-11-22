#!/bin/sh -x

HANG_DIR="fuzzing-output/server-conf.out/hangs"
HELPER_SH="fuzzing-wrappers/helpers/fwknopd-parse-conf.sh"

for f in `find $HANG_DIR -name 'id*'`
do
    ./$HELPER_SH $f
done

exit
