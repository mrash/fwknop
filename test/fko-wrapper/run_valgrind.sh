#!/bin/sh

LD_LIBRARY_PATH=../../lib/.libs valgrind --leak-check=full --show-reachable=yes --track-origins=yes ./fko_wrapper
