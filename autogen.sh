#!/bin/sh
#
# autogen.sh
#
# Run this script to generate all the initial makefiles, etc.
#
aclocal
libtoolize --automake
autoheader
automake -a
autoconf

###EOF###
