#!/bin/sh
#
# autogen.sh
#
# Run this script to generate all the initial makefiles, etc.
#
aclocal
libtoolize --automake
automake -a
autoconf

###EOF###
