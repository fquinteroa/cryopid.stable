TARGETS = freeze
CHUNK_OBJS = cp_fd.o cp_i387.o cp_misc.o cp_regs.o \
		cp_sighand.o cp_tls.o cp_vma.o
OBJECTS = common.o cpimage.o writer_raw.o list.o process.o tcpcp.o $(CHUNK_OBJS)

CFLAGS = -g -Wall -O0

CHPAX = /sbin/chpax
DEPAX = test ! -x $(CHPAX) || $(CHPAX) -xperms

# Switch the commenting on the following lines if we suspect wacky uclibc bugs
#LIBC = -nostdlib -nostartfiles ../uclibc/libc.a ../uclibc/crt0.o ../uclibc/crti.o
LIBC = -lc

all: $(TARGETS)

# elfwriter.o freeze.o imagewriter.o process.o stub.o tcpcp.o: process.h tcpcp.h

clean:
	rm -f *.o $(TARGETS) stub.bin

# freeze: freeze.o process.o imagewriter.o elfwriter.o stub-image.o tcpcp.o

stub-image.o: stub.bin
	ld -m elf_i386 --format binary --oformat elf32-i386 -r stub.bin \
		-o stub-image.o

freeze: $(OBJECTS) freeze.o elfwriter.o stub-image.o
	gcc -Os -o $@ $^ $(LIBC)

stub.bin: stub.o supervisor.o $(OBJECTS)
	gcc -static -Tstub-linking.x -Os -o $@ $^ $(LIBC)
	# strip $@
	$(DEPAX) $@

