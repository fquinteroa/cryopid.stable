/*
 * Process state saver
 *   (C) 2004 Bernard Blackham <bernard@blackham.com.au>
 *
 * Licensed under a BSD-ish license.
 */


#include <sys/types.h>
#include <linux/user.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include "cryopid.h"
#include "cpimage.h"
#include "process.h"
#include "list.h"

struct stream_ops *stream_ops = NULL;

void usage(char* argv0)
{
    fprintf(stderr,
"Usage: %s [options] <output filename> <pid>\n"
"\n"
"This is used to suspend the state of a single running process to a\n"
"self-executing file.\n"
"\n"
"    -w <writer> Nomiate an output writer to use.\n"
"    -l      Include libraries in the image of the file for a full image.\n"
"    -f      Save the contents of open files into the image. (Broken!)\n"
"    -c      Save children of this process as well.\n"
"\n"
"This program is part of CryoPID. http://cryopid.berlios.de/\n",
    argv0);
    exit(1);
}

void set_default_writer()
{
    extern checker_f __stubs_start;
    __stubs_start(NULL, 1);
}

void set_writer(char *writer)
{
    extern checker_f __stubs_start, __stubs_end;
    checker_f *p;
    if (stream_ops)
	bail("Multiple writers specified!");
    for (p = &__stubs_start; p < &__stubs_end; p++) {
	if ((*p)(writer, 0))
	    return;
    }
    bail("No such writer (%s)!", writer);
}

int main(int argc, char** argv)
{
    pid_t target_pid;
    struct list proc_image;
    int c;
    int flags = 0;
    int get_children = 0;
    int fd;
    long heap_start;

    /* Parse options */
    while (1) {
	int option_index = 0;
	static struct option long_options[] = {
	    {"libraries", 0, 0, 'l'},
	    {"files", 0, 0, 'f'},
	    {"children", 0, 0, 'c'},
	    {"writer", 1, 0, 'w'},
	    {0, 0, 0, 0},
	};

	c = getopt_long(argc, argv, "lfcw:", long_options, &option_index);
	if (c == -1)
	    break;
	switch(c) {
	    case 'l':
		flags |= GET_LIBRARIES_TOO;
		break;
	    case 'f':
		flags |= GET_OPEN_FILE_CONTENTS;
		break;
	    case 'c':
		get_children = 1;
		break;
	    case 'w':
		set_writer(optarg);
		break;
	    case '?':
		/* invalid option */
		usage(argv[0]);
		break;
	}
    }

    if (argc - optind != 2) {
	usage(argv[0]);
	return 1;
    }

    if (!stream_ops)
	set_default_writer();

    target_pid = atoi(argv[optind+1]);
    if (target_pid <= 1) {
	fprintf(stderr, "Invalid pid: %d\n", target_pid);
	return 1;
    }

    list_init(proc_image);
    get_process(target_pid, flags, &proc_image, &heap_start);

    fd = open(argv[optind], O_CREAT|O_WRONLY|O_TRUNC, 0777);
    if (fd == -1) {
	fprintf(stderr, "Couldn't open %s for writing: %s\n", argv[optind],
	    strerror(errno));
	return 1;
    }

    write_stub(fd, heap_start);

    write_process(fd, proc_image);

    close(fd);

    return 0;
}

/* vim:set ts=8 sw=4 noet: */
