# Disabling tcpcp support saves a few KB in the binary.
USE_TCPCP=y
USE_GTK=y

ARCH=$(shell arch)

ifneq ($(filter i%86,$(ARCH)), )
ARCH=i386
ARCH_OFORMAT=elf32-i386
endif

ifeq ($(ARCH), x86_64)
ARCH_OFORMAT=elf64-x86-64
endif

ifeq ($(ARCH), sparc)
ARCH_OFORMAT=elf32-sparc
endif

R_CHUNK_OBJS = cpimage_r.o cp_r_fd.o cp_r_fd_console.o cp_r_fd_file.o cp_r_fd_socket.o cp_r_misc.o cp_r_sighand.o cp_r_vma.o cp_r_header.o arch/arch_r_objs.o fork2.o
W_CHUNK_OBJS = cpimage_w.o cp_w_fd.o cp_w_fd_console.o cp_w_fd_file.o cp_w_fd_socket.o cp_w_misc.o cp_w_sighand.o cp_w_vma.o cp_w_header.o arch/arch_w_objs.o list.o 
COMMON_OBJS = common.c arch/asmfuncs.o
STUB_TYPES = gzip # raw buffered lzo
STUBS = $(patsubst %,stub-%,$(STUB_TYPES))
TARGETS = freeze

CFLAGS = -Wall -Os -I. -Iarch -D__$(ARCH)__

CHPAX = /sbin/chpax
DEPAX = test ! -x $(CHPAX) || $(CHPAX) -xperms

# Switch the commenting on the following lines if we suspect wacky uclibc bugs
LIBC = -DPROVIDE_MALLOC -nostdlib -nostartfiles ../dietlibc-$(ARCH)/dietlibc.a -lgcc
#LIBC = -nostdlib -nostartfiles -lc

ifeq ($(USE_TCPCP),y)
R_CHUNK_OBJS += tcpcp_r.o 
W_CHUNK_OBJS += tcpcp_w.o 
CFLAGS += -DUSE_TCPCP
endif

ifeq ($(USE_GTK),y)
R_CHUNK_OBJS += gtk_support.o
CFLAGS += -DUSE_GTK
TARGETS += fork2_helper
endif

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
	@strip $@
	@$(DEPAX) $@

freeze: $(COMMON_OBJS) $(W_CHUNK_OBJS) freeze.o $(patsubst %,stub-image-%.o,$(STUB_TYPES)) $(patsubst %,writer_%.c,$(STUB_TYPES))
	@echo Linking $@
	$(CC) $(CFLAGS) -Os -o $@ $^ -lz

gtk_support.o: gtk_support.c
	$(CC) $(CFLAGS) -I/usr/include/gtk-2.0 -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/usr/include/pango-1.0 -I/usr/lib/gtk-2.0/include -I/usr/include/atk-1.0 -c $<

fork2_helper: fork2_helper.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: arch
