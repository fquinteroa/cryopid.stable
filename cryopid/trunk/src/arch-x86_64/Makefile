R_CHUNK_OBJS = 
W_CHUNK_OBJS = 
CFLAGS = -g -Wall -Os -fpic -I..

all: arch_r_objs.o arch_w_objs.o

arch_r_objs.o: stub.o $(R_CHUNK_OBJS)
	$(LD) -m elf_x86_64  -r -o $@ $^

arch_w_objs.o: process.o elfwriter.o $(W_CHUNK_OBJS)
	$(LD) -m elf_x86_64  -r -o $@ $^

