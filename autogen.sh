#!/bin/sh
#
# autogen.sh
#
# Run this script to generate all the initial makefiles, etc.
#
set -x

aclocal -I config -I m4
libtoolize --automake --copy --force
autoheader
automake --add-missing --copy
autoconf

###EOF###
