#!/bin/sh
#
# The safeest way to run the fwknop test suite is by using this script - on
# some platforms setting the LD_LIBRARY_PATH variable via the standard perl
# perl %ENV hash does not seem to work properly when running in
# --enable-perl-module-checks mode.  This mode is used to test the perl FKO
# libfko bindings.  CentOS 6.3 was one platform where this seemed to be an
# issue, but setting LD_LIBRARY_PATH on the command line manually causes things
# to work properly.
#

LD_LIBRARY_PATH=../lib/.libs DYLD_LIBRARY_PATH=../lib/.libs ./test-fwknop.pl "$@"

exit
