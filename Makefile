all: test

clean:
	rm chonky

chonky: main.c fat32.c fat32.h
	gcc main.c fat32.c -o chonky -Wall -Wextra -pedantic-errors -std=c11 -ggdb3 -fsanitize=address,leak,undefined

test.img:
	rm -f test.img
	mkfs.fat -v -F32 -n "TEST FS" -C test.img 1048576

test: chonky test.img
	./chonky test.img

