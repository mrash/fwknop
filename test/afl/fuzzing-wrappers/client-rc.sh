#!/bin/sh -x

#
# Fuzz the fwknop client fwknoprc file. This wrapper also has the ability to
# kick off afl-cov to produce code coverage results at the same time. Note that
# CODE_DIR points to the fwknop project code compiled with gcov profiling
# support.
#
# $ AFL_COV=1 CODE_DIR=/path/to/code/fwknop.git ./fuzzing-wrappers/client-rc.sh
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

### see if we're going to enable code coverage with afl-cov
if [ "$AFL_COV" != "" ]
then
    echo "[+] Enabling afl-cov coverage mode..."
    if [ "$CODE_DIR" = "" ]
    then
        echo "[*] Must set CODE_DIR with path to gcov compiled code"
        exit 1
    fi

    ### kick off afl-cov in --background mode
    afl-cov -d $OUT_DIR --live --background --sleep 10 --coverage-cmd \
        "LD_LIBRARY_PATH=$CODE_DIR/test/afl/$LIB_DIR $CODE_DIR/test/afl/$CLIENT --rc-file AFL_FILE -T -a 1.1.1.1 -n testhost2.com" \
        --code-dir $CODE_DIR
fi

### make sure the client rc file can be parsed (a failure
### exit status is expected though)
./fuzzing-wrappers/helpers/fwknop-rc-test.sh && exit $?

### support resuming from a previous run
if [ $@ ] && [ "$1" = "resume" ]
then
    IN_DIR=$PREV_OUT_DIR
fi

LD_LIBRARY_PATH=$LIB_DIR afl-fuzz \
    -m $MEM_LIMIT -T $BANNER -t $TIMEOUT \
    -i $IN_DIR -o $OUT_DIR -f $OUT_DIR/fwknoprc \
    $CLIENT --rc-file $OUT_DIR/fwknoprc -T \
    -a 1.1.1.1 -n testhost2.com

exit $?
