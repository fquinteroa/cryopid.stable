#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/user.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include "cryopid.h"
#include "cpimage.h"

void fetch_fd_file(pid_t pid, int flags, int fd, int inode, char *fd_path,
	struct cp_file *file)
{
    int bufsz = 512;
    int retsz;
    char *buf = NULL;

    file->filename = NULL;
    file->size = 0;
    file->contents = NULL;

    do {
	buf = xmalloc(bufsz);
	retsz = readlink(fd_path, buf, bufsz);
	if (retsz <= 0) {
	    fprintf(stderr, "Error reading FD %d: %s\n", fd, strerror(errno));
	    goto out;
	} else if (retsz < bufsz) {
	    /* Read was successful */
	    buf[retsz] = '\0';
	    file->filename = strdup(buf);
	    break;
	}
	/* Otherwise, double the buffer size and try again */
	free(buf);
	bufsz <<= 1;
    } while (bufsz <= 8192); /* Keep it sane */
out:
    free(buf);
}

void write_chunk_fd_file(void *fptr, struct cp_file *file)
{
    write_string(fptr, file->filename);
    write_bit(fptr, &file->size, sizeof(int));
    if (file->size)
	write_bit(fptr, file->contents, file->size);
}

/* vim:set ts=8 sw=4 noet: */
