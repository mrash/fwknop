#!/bin/sh -x

IN_DIR="test-cases/spa-pkts.cmin"

for spa_pkt_file in $IN_DIR/*
do
    cat $spa_pkt_file | LD_LIBRARY_PATH=../../lib/.libs ../../server/.libs/fwknopd -c ../conf/default_fwknopd.conf -a ../conf/default_access.conf -A -f -t || exit $?
done

exit 0
