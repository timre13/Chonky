all: test

chonky: main.c fat32.c fat32.h
	gcc main.c fat32.c -o chonky -Wall -Wextra -pedantic-errors -std=c11 -ggdb3 -fsanitize=address,leak,undefined
	#gcc main.c fat32.c -o chonky -Wall -Wextra -pedantic-errors -std=c11 -ggdb3

test.img:
	rm -f test.img
	/usr/sbin/mkfs.fat -v -F32 -n "TEST FS" -C test.img 1048576
	sudo mkdir -p /mnt/test_img
	sudo mount test.img /mnt/test_img
	sudo cp -r testfiles/* /mnt/test_img
	sudo umount test.img
	sudo rmdir /mnt/test_img

test: chonky test.img
	./chonky test.img

check-img:
	/usr/sbin/dosfsck -bnU test.img
	/usr/sbin/fatlabel test.img

clean:
	rm chonky

