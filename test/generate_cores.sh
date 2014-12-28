#!/bin/sh -x
#
# minor helper script for the fwknop test suite in --enable-cores-pattern mode
#

DIR=/tmp/fwknop-cores

service apport stop
ulimit -c unlimited
mkdir $DIR
echo "$DIR/core.%e.%p.%h.%t" > /proc/sys/kernel/core_pattern

exit
