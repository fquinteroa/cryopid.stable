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
    int ffd;
    ffd = open(fd->file.filename, fd->mode);
    if (ffd == -1) {
	fprintf(stderr, "no longer exists! ");
	return;
    }
    if (ffd != fd->fd) {
	dup2(ffd, fd->fd);
	close(ffd);
    }
}

void read_chunk_fd_file(void *fptr, struct cp_fd *fd, int action)
{
    fd->file.filename = read_string(fptr, NULL, 0);
    read_bit(fptr, &fd->file.size, sizeof(int));
    if (fd->file.size) {
	fd->file.contents = xmalloc(fd->file.size);
	read_bit(fptr, fd->file.contents, fd->file.size);
    } else
	fd->file.contents = NULL;

    if (action & ACTION_PRINT)
	fprintf(stderr, "%s ", fd->file.filename);

    if (action & ACTION_LOAD)
	restore_fd_file(fd, action);
}

/* vim:set ts=8 sw=4 noet: */
