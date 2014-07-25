#!/bin/sh -x

if [ $@ ]; then
    LD_LIBRARY_PATH=../../lib/.libs $@
else
    echo "[*] Usage: ./run.sh ./<binary>"
fi
