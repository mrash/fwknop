#!/bin/sh -x

if [ $@ ]; then
    LD_LIBRARY_PATH=../../lib/.libs valgrind --leak-check=full \
        --show-reachable=yes --track-origins=yes --suppressions=../valgrind_suppressions $@
else
    echo "[*] Usage: ./run_valgrind.sh ./<binary>"
fi
