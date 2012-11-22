#!/bin/sh
#
# autogen.sh
#
# Run this script to generate all the initial makefiles, etc.
#
set -x

if [ ! -d m4 ]; then
	mkdir m4
fi
if [ ! -d config ]; then
	mkdir config
fi
libtoolize --automake --copy --force
aclocal -I config
autoheader
automake --add-missing --copy
autoconf

###EOF###
