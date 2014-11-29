#!/bin/sh -x

#
# Fuzz the fwknop client fwknoprc file
#

. ./fuzzing-wrappers/fcns

FDIR="client-rc.out"
OUT_DIR="$TOP_DIR/$FDIR"
PREV_OUT_DIR=''
IN_DIR="test-cases/client-rc"

### build up our afl-fuzz text banner
TSTR="fwknop,fwknoprc"
GIT_STR=''
git_banner GIT_STR
BANNER="$TSTR$GIT_STR"

### set up directories
dir_init $ARCHIVE_DIR $FDIR $OUT_DIR PREV_OUT_DIR

### support resuming from a previous run
if [ $@ ] && [ "$1" = "resume" ]
then
    IN_DIR=$PREV_OUT_DIR
fi

### make sure the client can handle the rc file
./fuzzing-wrappers/helpers/fwknop-rc-test.sh || \
    { echo "[*] Client rc file fuzzing requires compilation with ./compile/afl-compile-no-enable-args.sh"; exit 1; }

LD_LIBRARY_PATH=$LIB_DIR afl-fuzz \
    -T $BANNER -t 1000 -i $IN_DIR -o $OUT_DIR -f $OUT_DIR/fwknoprc \
    $CLIENT --rc-file $OUT_DIR/fwknoprc -T -a 1.1.1.1 -n testhost.com

exit $?
