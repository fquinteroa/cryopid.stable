ARCH=$(shell arch)

ifneq ($(filter i%86,$(ARCH)), )
ARCH=i386
ARCH_OFORMAT=elf32-i386
endif

ifeq ($(ARCH), x86_64)
ARCH_OFORMAT=elf64-x86-64
endif

R_CHUNK_OBJS = cpimage_r.o cp_r_fd.o cp_r_fd_console.o cp_r_fd_file.o cp_r_fd_socket.o cp_r_misc.o cp_r_sighand.o cp_r_vma.o tcpcp_r.o arch/arch_r_objs.o
W_CHUNK_OBJS = cpimage_w.o cp_w_fd.o cp_w_fd_console.o cp_w_fd_file.o cp_w_fd_socket.o cp_w_misc.o cp_w_sighand.o cp_w_vma.o tcpcp_w.o arch/arch_w_objs.o
COMMON_OBJS = common.c list.o arch/asmfuncs.o
STUB_TYPES = gzip # raw buffered lzo
STUBS = $(patsubst %,stub-%,$(STUB_TYPES))
TARGETS = freeze

CFLAGS = -g -Wall -Os -fpic -I. -Iarch -D__$(ARCH)__

CHPAX = /sbin/chpax
DEPAX = test ! -x $(CHPAX) || $(CHPAX) -xperms

# Switch the commenting on the following lines if we suspect wacky uclibc bugs
LIBC = -DPROVIDE_MALLOC -nostdlib -nostartfiles ../dietlibc-$(ARCH)/dietlibc.a /usr/lib/gcc/x86_64-linux-gnu/4.0.2/libgcc.a

all: arch $(TARGETS)

arch:
	! test -h arch && rm -f arch && ln -s arch-$(ARCH) arch || true
	make -C arch

clean:
	rm -f *.o arch/*.o $(TARGETS) 
	rm -f arch

stub-image-%.o: stub-%
	@echo Generating binary object of $^
	@$(LD) -m elf_$(ARCH) --format binary --oformat $(ARCH_OFORMAT) -r $< -o $@

stub-%: stub_common.o $(COMMON_OBJS) $(R_CHUNK_OBJS) writer_%.c
	@echo Linking $@
	$(CC) -static $(CFLAGS) -DCOMPILING_STUB -Tarch/stub-linking.x -Os -o $@ $^ -lz $(LIBC)
	#@strip $@
	@$(DEPAX) $@

freeze: $(COMMON_OBJS) $(W_CHUNK_OBJS) freeze.o $(patsubst %,stub-image-%.o,$(STUB_TYPES)) $(patsubst %,writer_%.c,$(STUB_TYPES))
	@echo Linking $@
	$(CC) $(CFLAGS) -Os -o $@ $^ -lz

.PHONY: arch
