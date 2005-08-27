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

void restore_fd_file(struct cp_fd *fd, int action)
{
}

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
	buf = malloc(bufsz);
	retsz = readlink(fd_path, buf, bufsz);
	if (retsz <= 0) {
	    fprintf(stderr, "Error reading FD %d: %s\n", fd, strerror(errno));
	    goto out;
	} else if (retsz < bufsz) {
	    /* Read was successful */
	    buf[retsz] = '\0';
	    file->filename = strdup(buf);
	    goto out;
	}
	/* Otherwise, double the buffer size and try again */
	free(buf);
	bufsz <<= 1;
    } while (bufsz <= 8192); /* Keep it sane */
out:
    free(buf);
}

void read_chunk_fd_file(void *fptr, struct cp_fd *fd, int action)
{
    struct cp_file file;

    file.filename = read_string(fptr, NULL, 0);
    read_bit(fptr, &file.size, sizeof(int));
    if (file.size) {
	file.contents = malloc(file.size);
	read_bit(fptr, file.contents, file.size);
    } else
	file.contents = NULL;

    if (action & ACTION_LOAD)
	restore_fd_file(fd, action);
}

void write_chunk_fd_file(void *fptr, struct cp_file *file)
{
    write_string(fptr, file->filename);
    write_bit(fptr, &file->size, sizeof(int));
    if (file->size)
	write_bit(fptr, file->contents, file->size);
}

/* vim:set ts=8 sw=4 noet: */
