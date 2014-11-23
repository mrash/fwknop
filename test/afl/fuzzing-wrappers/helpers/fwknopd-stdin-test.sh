#!/bin/sh -x

SPA_PKT="1716411011200157:root:1397329899:2.0.1:1:127.0.0.2,tcp/22:AAAAA"

echo -n $SPA_PKT | LD_LIBRARY_PATH=../../lib/.libs ../../server/.libs/fwknopd -c ../conf/default_fwknopd.conf -a ../conf/default_access.conf -A -f -t

exit $?
