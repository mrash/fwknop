
all : fko_wrapper.c
	gcc -Wall -g -I../../common -I../../client -I../../lib fko_wrapper.c -o fko_wrapper -L../../lib/.libs -lfko

clean:
	rm -f fko_wrapper
