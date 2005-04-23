#include <sys/ptrace.h>
#include <linux/user.h>

#include "cryopid.h"
#include "cpimage.h"

static off_t get_file_offset(pid_t pid, int fd, off_t offset, int whence) {
    struct user_regs_struct r;

    if (ptrace(PTRACE_GETREGS, pid, 0, &r) == -1)
	bail("ptrace(GETREGS): %s", strerror(errno));

    /* FIXME: large file support? llseek and offset to 64-bit? */
    r.eax = __NR_lseek;
    r.ebx = fd;
    r.ecx = offset;
    r.edx = whence;

    if (!do_syscall(pid, &r)) return 0;

    /* Error checking! */
    if (r.eax < 0) {
	errno = -r.eax;
	return (off_t)(-1);
    }

    return r.eax;
}


void read_chunk_fd(void *fptr, struct cp_fd *data, int load) {
    /* FIXME */
}

void write_chunk_fd(void *fptr, struct cp_fd *data) {
    /* FIXME */
}

static void get_term_dev(pid_t pid) {
    char tmp_fn[80];
    int term_dev = 0;

    snprintf(tmp_fn, 80, "/proc/%d/stat", pid);
    memset(stat_line, 0, sizeof(stat_line));
    f = fopen(tmp_fn, "r");
    fgets(stat_line, 80, f);
    fclose(f);
    stat_ptr = strrchr(stat_line, ')');
    if (stat_ptr != NULL) {
	int tty = -1;

	stat_ptr += 2;
	sscanf(stat_ptr, "%*c %*d %*d %*d %d", &tty);
	if (tty > 0) {
	    term_dev = (dev_t)tty;
	    printf("[+] Terminal device appears to be %d:%d\n", tty >> 8, tty & 0xFF);
	}
    }
    return term_dev;
}

void fetch_chunks_fd(pid_t pid, int flags, struct list *l) {
    struct cp_chunk *chunk = NULL;
    struct dirent *fd_dirent;
    struct stat stat_buf;
    int proc_fd;
    char tmp_fn[1024], tmp2_fn[1024];

    snprintf(tmp_fn, 30, "/proc/%d/fd", pid);
    proc_fd = opendir(tmp_fn);
    for (;;) {
	if (!chunk)
	    chunk = xmalloc(sizeof(struct cp_chunk));

	fd_dirent = readdir(proc_fd);
	if (fd_dirent == NULL)
	    break;

	if (fd_dirent->d_type != DT_LNK)
	    continue;

	/* Find out if it's open for r/w/rw */
	snprintf(tmp_fn, 1024, "/proc/%d/fd/%s", pid, fd_dirent->d_name);
	lstat(tmp_fn, &stat_buf);

	if ((stat_buf.st_mode & S_IRUSR) && (stat_buf.st_mode & S_IWUSR))
	    chunk->mode = O_RDWR;
	else if (stat_buf.st_mode & S_IWUSR)
	    chunk->mode = O_WRONLY;
	else
	    chunk->mode = O_RDONLY;

	/* Now work out what file this FD points to */
	memset(tmp2_fn, 0, sizeof(tmp2_fn));
	readlink(tmp_fn, tmp2_fn, sizeof(tmp2_fn)-1);

	/* This time stat the file/fifo/socket/etc, not the link */
	if (stat(tmp2_fn, &stat_buf) < 0)
	    bail("Failed to stat(%s): %s", tmp2_fn, strerror(errno));

	switch (stat_buf.st_mode & S_IFMT) {
	    case S_IFSOCK:
	    case S_IFREG:
	    case S_IFCHR:
		/* is our terminal? */
	    case S_IFBLK:
	    case S_IFDIR:
	    case S_IFIFO:
	    case S_IFLNK:
	    default:
		/* ummmm */
		break;
	}

	/* Record it */
	chunk->fd = atoi(fd_dirent->d_name);
	chunk->type = CP_CHUNK_FD;
	list_add(l, chunk);
	chunk = NULL;
    }
}

/* vim:set ts=8 sw=4 noet: */
