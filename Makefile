CC := gcc
CFLAGS := -g3 -std=c11 -Wall -Wextra -Wshadow -pedantic -Werror -Warray-bounds=2 -Wwrite-strings -Wcast-qual -fno-omit-frame-pointer -fsanitize=address 
CFLAGS += -fsanitize-address-use-after-scope -fsanitize=undefined -fsanitize=leak -fsanitize-address-use-after-scope -fsanitize=bounds-strict 
CFLAGS += -fsanitize=null -fsanitize-recover=all -fstack-protector-all

my_objdump: my_objdump.o 
	$(CC) $(CFLAGS) my_objdump.o -Wall -Werror -g -o my_objdump
	make clean2

my_objdump.o: my_objdump.c
	$(CC) $(CFLAGS) my_objdump.c -Wall -Werror -g -c -o my_objdump.o

clean:
	rm -f my_objdump conversions.o my_objdump.o

clean2:
	rm -f conversions.o my_objdump.o
