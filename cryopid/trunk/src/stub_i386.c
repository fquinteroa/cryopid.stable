//#define _FILE_OFFSET_BITS 64

#include <sys/ptrace.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>
#include <asm/ldt.h>
#include <asm/ucontext.h>
#include <linux/unistd.h>
#include <linux/elf.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

#include "cryopid.h"
#include "cpimage.h"
#include "process.h"

char tramp[100];
extern char tramp[] __attribute__((__section__((".tramp"))));
static int image_fd, real_fd;

int verbosity = 0;
int do_pause = 0;
int want_pid = 0;
int translate_pids = 0;
char ignorefds[256];
int reforked = 0;

int real_argc;
char** real_argv;
char** real_environ;
extern char** environ;

static void safe_read(int fd, void* dest, size_t count, char* desc)
{
    int ret;
    ret = read(fd, dest, count);
    if (ret == -1) {
	fprintf(stderr, "Read error on %s: %s\n", desc, strerror(errno));
	exit(1);
    }
    if (ret < count) {
	fprintf(stderr, "Short read on %s\n", desc);
	exit(1);
    }
}

static void read_process()
{
    void *fptr;

    fptr = stream_ops->init(image_fd, O_RDONLY);
    if (!fptr)
	bail("Unable to initialize reader.");

    /* Read and process all chunks. */
    while (read_chunk(fptr, ACTION_LOAD | ((verbosity>0)?ACTION_PRINT:0)));

    /* Cleanup the input file. */
    stream_ops->finish(fptr);
    close(console_fd);

    /* The trampoline code should now be magically loaded at 0x10000.
     * Jumping there will restore registers and continue execution.
     */

    if (do_pause)
	sleep(2);

    asm("jmp *%%eax\n" : : "a"(TRAMPOLINE_ADDR));
}

static void* find_top_of_stack()
{
    unsigned int tmp;
    /* Return the top of the current stack page. */
    return (void*)(((long)&tmp + PAGE_SIZE - 1) & ~(PAGE_SIZE-1));
}

static void seek_to_image(int fd)
{
    Elf32_Ehdr e;
    Elf32_Shdr s;
    int i;
    char* strtab;

    syscall_check(lseek(fd, 0, SEEK_SET), 0, "lseek");
    safe_read(fd, &e, sizeof(e), "Elf32_Ehdr");
    if (e.e_shoff == 0) {
	fprintf(stderr, "No section header found in self! Bugger.\n");
	exit(1);
    }
    if (e.e_shentsize != sizeof(Elf32_Shdr)) {
	fprintf(stderr, "Section headers incorrect size. Bugger.\n");
	exit(1);
    }
    if (e.e_shstrndx == SHN_UNDEF) {
	fprintf(stderr, "String section missing. Bugger.\n");
	exit(1);
    }
    
    /* read the string table */
    syscall_check(lseek(fd, e.e_shoff+(e.e_shstrndx*sizeof(Elf32_Shdr)), SEEK_SET), 0, "lseek");
    safe_read(fd, &s, sizeof(s), "string table section header");
    syscall_check(lseek(fd, s.sh_offset, SEEK_SET), 0, "lseek");
    strtab = xmalloc(s.sh_size);
    safe_read(fd, strtab, s.sh_size, "string table");

    for (i=0; i < e.e_shnum; i++) {
	long offset;

	syscall_check(
		lseek(fd, e.e_shoff+(i*sizeof(Elf32_Shdr)), SEEK_SET), 0, "lseek");
	safe_read(fd, &s, sizeof(s), "Elf32_Shdr");
	if (s.sh_type != SHT_PROGBITS || s.sh_name == 0)
	    continue;

	/* We have potential data! Is it really ours? */
	if (memcmp(strtab+s.sh_name, "cryopid.image", 13) != 0)
	    continue;

	if (s.sh_info != IMAGE_VERSION) {
	    fprintf(stderr, "Incorrect image version found (%d)! Keeping on trying.\n", s.sh_info);
	    continue;
	}

	/* Woo! got it! */
	syscall_check(
		lseek(fd, s.sh_offset, SEEK_SET), 0, "lseek");

	safe_read(fd, &offset, 4, "offset");

	syscall_check(
		lseek(fd, offset, SEEK_SET), 0, "lseek");

	return;
    }
    fprintf(stderr, "Program image not found!\n");
    exit(1);
}

static int open_self()
{
    int fd;
    if (verbosity > 0)
	fprintf(stderr, "Reading image...\n");
    fd = open("/proc/self/exe", O_RDONLY);
    if (fd == -1) {
	fprintf(stderr, "Couldn't open self: %s\n", strerror(errno));
	exit(1);
    }
    return fd;
}

void usage(char* argv0)
{
    fprintf(stderr,
"Usage: %s [options]\n"
"\n"
"This is a saved image of process. To resume this process, you can simply run\n"
"this executable. Some options that may be of interest when restoring\n"
"this process:\n"
"\n"
"    -v      Be verbose while resuming.\n"
"    -i <fd> Do not restore the given file descriptor.\n"
"    -p      Pause between steps before resuming (for debugging)\n"
"    -P      Attempt to gain original PID by way of fork()'ing a lot\n"
"    -t      Use ptrace to translate PIDs in system calls (Experimental and\n"
"	    incomplete!)"
"\n"
"This image was created by CryoPID. http://cryopid.berlios.de/\n",
    argv0);
    exit(1);
}

static void real_main(int argc, char** argv) __attribute__((noreturn));
static void real_main(int argc, char** argv)
{
    image_fd = 42;
    /* See if we're being executed for the second time. If so, read arguments
     * from the file.
     */
    if (lseek(image_fd, 0, SEEK_SET) != -1) {
	safe_read(image_fd, &argc, sizeof(argc), "argc from cryopid.state");
	argv = (char**)xmalloc(sizeof(char*)*argc+1);
	argv[argc] = NULL;
	int i, len;
	for (i=0; i < argc; i++) {
	    safe_read(image_fd, &len, sizeof(len), "argv len from cryopid.state");
	    argv[i] = (char*)xmalloc(len);
	    safe_read(image_fd, argv[i], len, "new argv from cryopid.state");
	}
	close(image_fd);
	reforked = 1;
    } else {
	if (errno != EBADF) {
	    /* EBADF is the only error we should be expecting! */
	    fprintf(stderr, "Unexpected error on lseek. Aborting (%s).\n",
		    strerror(errno));
	    exit(1);
	}
    }

    /* Parse options */
    memset(ignorefds, 0, sizeof(ignorefds));
    while (1) {
	int option_index = 0;
	int c;
	static struct option long_options[] = {
	    {0, 0, 0, 0},
	};
	
	c = getopt_long(argc, argv, "vpPc:ti:",
		long_options, &option_index);
	if (c == -1)
	    break;
	switch(c) {
	    case 'v':
		verbosity++;
		break;
	    case 'p':
		do_pause = 1;
		break;
	    case 'P':
		want_pid = 1;
		break;
	    case 't':
		translate_pids = 1;
		break;
	    case 'i':
		if (atoi(optarg) >= 256) {
		    fprintf(stderr, "Ignored fd number too high! Not ignoring.\n");
		    exit(1);
		}
		ignorefds[atoi(optarg)] = 1;
		break;
	    case '?':
		/* invalid option */
		fprintf(stderr, "Unknown option on command line.\n");
		usage(argv[0]);
		break;
	}
    }

    if (argc - optind) {
	fprintf(stderr, "Extra arguments not expected (%s ...)!\n", argv[optind]);
	usage(argv[0]);
    }

    image_fd = real_fd;
    seek_to_image(image_fd);

    read_process();

    fprintf(stderr, "Something went wrong :(\n");
    exit(1);
}

static inline void relocate_stack()
{
    void *top_of_old_stack;
    void *top_of_new_stack;
    void *top_of_our_memory = (void*)MALLOC_END;
    void *top_of_all_memory;
    long size_of_new_stack;

    /* Reposition the stack at top_of_old_stack */
    top_of_old_stack = find_top_of_stack();
    top_of_all_memory = (void*)get_task_size();

    top_of_new_stack = (void*)TOP_OF_STACK;
    size_of_new_stack = PAGE_SIZE;

    syscall_check( (int)
	mmap(top_of_new_stack - size_of_new_stack, size_of_new_stack,
	    PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANONYMOUS|MAP_FIXED|MAP_GROWSDOWN|MAP_PRIVATE, -1, 0),
	0, "mmap(newstack)");
    memset(top_of_new_stack - size_of_new_stack, 0, size_of_new_stack);
    memcpy(top_of_new_stack - size_of_new_stack,
	    top_of_old_stack - size_of_new_stack, /* FIX ME */
	    size_of_new_stack);
    __asm__ ("addl %0, %%esp" : : "a"(top_of_new_stack - top_of_old_stack));
    __asm__ ("addl %0, %%ebp" : : "a"(top_of_new_stack - top_of_old_stack));

    /* unmap absolutely everything above us! */
    syscall_check(
	    munmap(top_of_our_memory,
		(top_of_all_memory - top_of_our_memory)),
		0, "munmap(stack)");
}

int main(int argc, char**argv)
{
    int i;

    /* Take a copy of our argc/argv and environment below we blow them away */
    real_argc = argc;
    real_argv = (char**)xmalloc((sizeof(char*)*argc)+1);
    for(i=0; i < argc; i++)
	real_argv[i] = strdup(argv[i]);
    real_argv[i] = NULL;

    for(i = 0; environ[i]; i++); /* count environment variables */
    real_environ = xmalloc((sizeof(char*)*i)+1);
    for(i = 0; environ[i]; i++)
	*real_environ++ = strdup(environ[i]);
    *real_environ = NULL;
    environ = real_environ;

    real_fd = open_self();
    relocate_stack();

    /* Now hope for the best! */
    real_main(real_argc, real_argv);

    /* We should never return */
    return 42;
}

/* vim:set ts=8 sw=4 noet: */
