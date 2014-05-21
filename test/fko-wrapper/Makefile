
all : fko_wrapper.c
	gcc -Wall -g -I../../lib fko_wrapper.c -o fko_wrapper -L../../lib/.libs -lfko
	gcc -Wall -g -I../../lib fko_basic.c -o fko_basic -L../../lib/.libs -lfko

fuzzing: fko_wrapper.c
	gcc -Wall -g -DFUZZING_INTERFACES -I../../lib fko_wrapper.c -o fko_wrapper -L../../lib/.libs -lfko

faultinjection: fko_fault_injection.c
	gcc -Wall -g -DFIU_ENABLE -I../../lib fko_fault_injection.c -o fko_fault_injection -L../../lib/.libs -lfiu -lfko

clean:
	rm -f fko_wrapper fko_basic fko_fault_injection
