#!/bin/sh
#
# autogen.sh
#
# Run this script to generate all the initial makefiles, etc.
#
aclocal -I config
libtoolize --automake --copy --force
autoheader
automake --add-missing --copy --foreign
autoconf

###EOF###
