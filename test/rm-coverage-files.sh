#!/bin/sh -x

cd ..
for d in client server lib common
do
    for s in *.gcda *.gcno *.gcov
    do
        find $d -name $s | xargs rm -f
    done
done
cd test
exit
