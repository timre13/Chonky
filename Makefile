all: test

clean:
	rm chonky

chonky: main.c
	gcc main.c -Wall -Wextra -pedantic-errors -std=c11 -g -o chonky

test.img:
	rm -f test.img
	mkfs.fat -v -F32 -n "TEST FS" -C test.img 1048576

test: chonky test.img
	./chonky test.img

