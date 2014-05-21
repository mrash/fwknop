#!/bin/sh -x

if [ $@ ]; then
    LD_LIBRARY_PATH=../../lib/.libs valgrind --leak-check=full --show-reachable=yes --track-origins=yes $@
else
    echo "[*] Usage: ./run_valgrind.sh ./<binary>"
fi
