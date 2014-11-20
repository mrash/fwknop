#!/bin/sh -x

LD_LIBRARY_PATH=../../lib/.libs ../../server/.libs/fwknopd -c test-cases/server-conf/fwknopd.conf -a ../conf/default_access.conf -A -f -t --exit-parse-config -D
