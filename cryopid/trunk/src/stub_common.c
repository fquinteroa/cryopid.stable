#include <getopt.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "cryopid.h"
#include "cpimage.h"
#include "process.h"
#include "stub.h"

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

    jump_to_trampoline();
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

void real_main(int argc, char** argv) __attribute__((noreturn));
void real_main(int argc, char** argv) __attribute__((noinline));
void real_main(int argc, char** argv)
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
	if (errno && errno != EBADF) {
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

int main(int argc, char**argv, char **envp)
{
    int i;

#ifdef __x86_64__
    /* FIXME: this doesn't belong here. */
    extern void set_fs();
    set_fs();
#endif

    get_task_size();

    /* Take a copy of our argc/argv and environment below we blow them away */
    real_argc = argc;
    real_argv = (char**)xmalloc((sizeof(char*)*argc)+1);
    for(i=0; i < argc; i++)
	real_argv[i] = strdup(argv[i]);
    real_argv[i] = NULL;

    for(i = 0; envp[i]; i++); /* count environment variables */
    real_environ = xmalloc((sizeof(char*)*i)+1);
    for(i = 0; envp[i]; i++)
	*real_environ++ = strdup(envp[i]);
    *real_environ = NULL;
    environ = real_environ;

    real_fd = open_self();
    relocate_stack();

    /* Now hope for the best! */
    real_main(real_argc, real_argv);
}

/* vim:set ts=8 sw=4 noet: */
