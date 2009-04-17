COMMON_OBJS = 
R_CHUNK_OBJS = cp_r_regs.o start.o
W_CHUNK_OBJS = cp_w_regs.o
override CFLAGS += -g -Wall -Os -fpic -I. -I..

all: arch_r_objs.o arch_w_objs.o

arch_r_objs.o: $(COMMON_OBJS) stub.o $(R_CHUNK_OBJS)
	$(LD) -m elf32_sparc  -r -o $@ $^

arch_w_objs.o: $(COMMON_OBJS) process.o elfwriter.o $(W_CHUNK_OBJS)
	$(LD) -m elf32_sparc  -r -o $@ $^

