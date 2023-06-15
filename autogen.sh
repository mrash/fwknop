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

gnulib-tool --lib=libgnu --libtool --lgpl=3orGPLv2 --source-base=gnulib --import \
    stdint \
    sys_types largefile \
    strndup

if which libtoolize &> /dev/null ; then
  libtoolize --automake --copy --force
elif which glibtoolize &> /dev/null ; then
  glibtoolize --automake --copy --force
else
  echo 'No libtoolize or glibtoolize found!'
  exit 1
fi

aclocal -I config -I m4
autoheader
automake --add-missing --copy
autoconf
###EOF###
