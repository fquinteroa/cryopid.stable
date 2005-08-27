CHUNK_OBJS = cp_fd.o cp_fd_console.o cp_fd_file.o cp_fd_socket.o cp_i387.o \
		cp_misc.o cp_regs.o cp_sighand.o cp_tls.o cp_vma.o
OBJECTS = common.c cpimage.o list.o asmfuncs.o \
		process.o tcpcp.o $(CHUNK_OBJS)
# STUB_TYPES = raw buffered lzo
STUB_TYPES = raw
STUBS = $(patsubst %,stub-%,$(STUB_TYPES))
TARGETS = freeze $(STUBS)

CFLAGS = -g -Wall -O0 -fpic

CHPAX = /sbin/chpax
DEPAX = test ! -x $(CHPAX) || $(CHPAX) -xperms

# Switch the commenting on the following lines if we suspect wacky uclibc bugs
#LIBC = -nostdlib -nostartfiles ../uclibc/libc.a ../uclibc/crt0.o ../uclibc/crti.o
LIBC = -lc

all: $(TARGETS)

clean:
	rm -f *.o $(TARGETS) 

stub-image-%.o: stub-%
	@echo Generating binary object of $^
	@$(LD) -m elf_i386 --format binary --oformat elf32-i386 -r $< -o $@

stub-%: stub.o supervisor.o $(OBJECTS) writer_%.c
	@echo Linking $@
	$(CC) -static -fpic -DCOMPILING_STUB -Tstub-linking.x -Os -o $@ $^ $(LIBC) -llzo
	#@strip $@
	@$(DEPAX) $@

freeze: $(OBJECTS) freeze.o elfwriter.o $(patsubst %,stub-image-%.o,$(STUB_TYPES)) $(patsubst %,writer_%.c,$(STUB_TYPES))
	@echo Linking $@
	$(CC) -Os -o $@ $^ $(LIBC) -llzo

