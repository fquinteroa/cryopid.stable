R_CHUNK_OBJS = cpimage_r.o cp_r_fd.o cp_r_fd_console.o cp_r_fd_file.o cp_r_fd_socket.o cp_r_i387.o cp_r_misc.o cp_r_regs.o cp_r_sighand.o cp_r_tls.o cp_r_vma.o tcpcp_r.o
W_CHUNK_OBJS = cpimage_w.o cp_w_fd.o cp_w_fd_console.o cp_w_fd_file.o cp_w_fd_socket.o cp_w_i387.o cp_w_misc.o cp_w_regs.o cp_w_sighand.o cp_w_tls.o cp_w_vma.o tcpcp_w.o
COMMON_OBJS = common.c list.o asmfuncs.o
# STUB_TYPES = raw buffered lzo gzip
STUB_TYPES = gzip
STUBS = $(patsubst %,stub-%,$(STUB_TYPES))
TARGETS = freeze $(STUBS)

CFLAGS = -g -Wall -Os -fpic

CHPAX = /sbin/chpax
DEPAX = test ! -x $(CHPAX) || $(CHPAX) -xperms

# Switch the commenting on the following lines if we suspect wacky uclibc bugs
LIBC = -DPROVIDE_MALLOC -nostdlib -nostartfiles ../uclibc/libc.a ../uclibc/crt0.o ../uclibc/crti.o
#LIBC = -lc

all: $(TARGETS)

clean:
	rm -f *.o $(TARGETS) 

stub-image-%.o: stub-%
	@echo Generating binary object of $^
	@$(LD) -m elf_i386 --format binary --oformat elf32-i386 -r $< -o $@

stub-%: stub.o supervisor.o $(COMMON_OBJS) $(R_CHUNK_OBJS) writer_%.c
	@echo Linking $@
	$(CC) -static $(CFLAGS) -DCOMPILING_STUB -Tstub-linking.x -Os -o $@ $^ $(LIBC) -lz
	@strip $@
	@$(DEPAX) $@

freeze: $(COMMON_OBJS) $(W_CHUNK_OBJS) freeze.o process.o elfwriter.o $(patsubst %,stub-image-%.o,$(STUB_TYPES)) $(patsubst %,writer_%.c,$(STUB_TYPES))
	@echo Linking $@
	$(CC) -Os -o $@ $^ -lz
