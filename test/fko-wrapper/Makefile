
CC = gcc
LIBDIR = ../../lib/.libs
INCDIR = ../../lib
CLANG = clang

all: fko_wrapper.c fko_basic.c
	cc -Wall -g -I$(INCDIR) fko_wrapper.c -o fko_wrapper -L$(LIBDIR) -lfko
	cc -Wall -g -I$(INCDIR) fko_basic.c -o fko_basic -L$(LIBDIR) -lfko

coverage: fko_wrapper.c fko_basic.c
	$(CC) -Wall -fprofile-arcs -ftest-coverage -fno-inline -g -I$(INCDIR) fko_wrapper.c -o fko_wrapper -L$(LIBDIR) -lfko
	$(CC) -Wall -fprofile-arcs -ftest-coverage -fno-inline -g -I$(INCDIR) fko_basic.c -o fko_basic -L$(LIBDIR) -lfko

asan: fko_wrapper.c fko_basic.c
	$(CC) -Wall -fsanitize=address -fno-omit-frame-pointer -g -I$(INCDIR) fko_wrapper.c -o fko_wrapper -L$(LIBDIR) -lfko
	$(CC) -Wall -fsanitize=address -fno-omit-frame-pointer -g -I$(INCDIR) fko_basic.c -o fko_basic -L$(LIBDIR) -lfko

ubsan: fko_wrapper.c fko_basic.c
	$(CC) -Wall -fsanitize=undefined -g -I$(INCDIR) fko_wrapper.c -o fko_wrapper -L$(LIBDIR) -lfko
	$(CC) -Wall -fsanitize=undefined -fno-omit-frame-pointer -g -I$(INCDIR) fko_basic.c -o fko_basic -L$(LIBDIR) -lfko

fuzzing: fko_wrapper.c
	$(CC) -Wall -g -DFUZZING_INTERFACES -I$(INCDIR) fko_wrapper.c -o fko_wrapper -L$(LIBDIR) -lfko

faultinjection: fko_fault_injection.c
	$(CC) -Wall -g -DFIU_ENABLE -I$(INCDIR) fko_fault_injection.c -o fko_fault_injection -L$(LIBDIR) -lfiu -lfko

clean:
	rm -f fko_wrapper fko_basic fko_fault_injection *gcno *gcda
