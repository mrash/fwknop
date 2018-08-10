
all : use-after-free.c
	cc -Wall -O1 -g -fsanitize=address -fno-omit-frame-pointer use-after-free.c

clean:
	rm -f a.out
