#!/bin/sh
#
# autogen.sh
#
# Run this script to generate all the initial makefiles, etc.
#
aclocal -I config
libtoolize --automake
autoheader
automake --add-missing --copy --foreign
autoconf

###EOF###
