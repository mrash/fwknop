#!/bin/sh -x

for f in `find fuzzing-output/client-rc.out/hangs -name 'id*'`
do
    ./fuzzing-wrappers/helpers/fwknop-rc-test.sh $f
done

exit
