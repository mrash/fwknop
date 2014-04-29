
all : fko_wrapper.c
	gcc -Wall -g -I../../lib fko_wrapper.c -o fko_wrapper -L../../lib/.libs -lfko

fuzzing: fko_wrapper.c
	gcc -Wall -g -DFUZZING_INTERFACES -I../../lib fko_wrapper.c -o fko_wrapper -L../../lib/.libs -lfko

clean:
	rm -f fko_wrapper
