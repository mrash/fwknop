#!/bin/sh -x

HANG_DIR="fuzzing-output/spa-pkts.out/hangs"
HELPER_SH="fuzzing-wrappers/helpers/fwknopd-stdin-test.sh"

for f in `find $HANG_DIR -name 'id*'`
do
    ./$HELPER_SH $f
done

exit
