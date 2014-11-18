#!/bin/sh -x

LD_LIBRARY_PATH=../../lib/.libs ../../server/.libs/fwknopd -c ../conf/default_fwknopd.conf -a ../conf/default_access.conf -A -f -t --exit-parse-config -D
