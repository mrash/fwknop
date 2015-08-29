#!/bin/sh -x

RC_FILE="test-cases/client-rc/fwknoprc2"

if [ $@ ]
then
    RC_FILE=$@
fi

LD_LIBRARY_PATH=../../lib/.libs ../../client/.libs/fwknop -v -v --rc-file $RC_FILE -T -a 1.1.1.1 -n testhost2.com

exit $?
