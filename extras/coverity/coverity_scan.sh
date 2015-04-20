#!/bin/sh +x

make clean
export PATH=$PATH:/home/mbr/coverity/cov-analysis-linux64-7.6.0/bin
cov-build --dir cov-int make
tar cvfz fwknop.tgz cov-int

echo "[+] Submit build tarball (./fwknop.tgz) here: http://scan.coverity.com/upload.html"

exit
