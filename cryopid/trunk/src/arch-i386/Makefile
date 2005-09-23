R_CHUNK_OBJS = cp_r_regs.o cp_r_tls.o cp_r_i387.o
W_CHUNK_OBJS = cp_w_regs.o cp_w_tls.o cp_w_i387.o
CFLAGS = -g -Wall -Os -fpic -I. -I..

all: arch_r_objs.o arch_w_objs.o

arch_r_objs.o: stub.o $(R_CHUNK_OBJS)
	$(LD) -m elf_i386  -r -o $@ $^

arch_w_objs.o: process.o elfwriter.o $(W_CHUNK_OBJS)
	$(LD) -m elf_i386  -r -o $@ $^

