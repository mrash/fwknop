#!/bin/sh -x

LD_LIBRARY_PATH=../../lib/.libs ../../server/.libs/fwknopd -c ../conf/default_fwknopd.conf -a ../conf/default_access.conf -A --afl-pkt-file test-cases/enc-pkts/spa.enc -f -t

exit $?
