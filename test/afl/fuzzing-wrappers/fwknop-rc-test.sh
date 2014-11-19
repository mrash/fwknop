#!/bin/sh -x

LD_LIBRARY_PATH=../../lib/.libs ../../client/.libs/fwknop --rc-file test-cases/client-rc/fwknoprc -T
