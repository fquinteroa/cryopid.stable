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

/* vim:set ts=8 sw=4 noet: */
