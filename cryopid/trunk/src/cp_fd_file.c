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

void restore_fd_file(int fd, struct cp_file *file)
{

}

void save_fd_file(pid_t pid, int flags, int fd, int inode, struct cp_file *file)
{

}

void read_chunk_fd_file(void *fptr, struct cp_file *cptr, int load, int fd)
{
    struct cp_file file;
    if (load) {
	restore_fd_file(fd, &file);
    } else {
	abort();
    }
}

void write_chunk_fd_file(void *fptr, struct cp_file *file)
{

}

/* vim:set ts=8 sw=4 noet: */
