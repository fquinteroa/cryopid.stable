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

int console_fd;

static off_t get_file_offset(pid_t pid, int fd, off_t offset, int whence)
{
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

static int get_fcntl_status(pid_t pid, int fd)
{
    struct user_regs_struct r;

    if (ptrace(PTRACE_GETREGS, pid, 0, &r) == -1)
	bail("ptrace(GETREGS): %s", strerror(errno));

    r.eax = __NR_fcntl64;
    r.ebx = fd;
    r.ecx = F_GETFL;

    if (!do_syscall(pid, &r)) return 0;

    /* Error checking! */
    if (r.eax < 0) {
	errno = -r.eax;
	return -1;
    }

    debug("get_fcntl_status of fd %d is %ld", fd, r.eax);
    return r.eax;
}

static int get_fcntl_close_on_exec(pid_t pid, int fd)
{
    struct user_regs_struct r;

    if (ptrace(PTRACE_GETREGS, pid, 0, &r) == -1)
	bail("ptrace(GETREGS): %s", strerror(errno));

    r.eax = __NR_fcntl64;
    r.ebx = fd;
    r.ecx = F_GETFD;

    if (!do_syscall(pid, &r)) return 0;

    /* Error checking! */
    if (r.eax < 0) {
	errno = -r.eax;
	return -1;
    }

    return r.eax;
}


void read_chunk_fd(void *fptr, struct cp_fd *data, int load)
{
    int fd, type, mode, close_on_exec, fcntl_status;
    off_t offset;
    if (!load)
	abort(); /* FIXME: unsupported as yet. need to rethink this. */

    read_bit(fptr, &fd, sizeof(int));
    read_bit(fptr, &type, sizeof(int));
    read_bit(fptr, &mode, sizeof(int));
    read_bit(fptr, &close_on_exec, sizeof(int));
    read_bit(fptr, &fcntl_status, sizeof(int));
    read_bit(fptr, &offset, sizeof(off_t));

    switch (type) {
	case CP_CHUNK_FD_CONSOLE:
	    read_chunk_fd_console(fptr, NULL, load, fd);
	    break;
	case CP_CHUNK_FD_MAXFD:
	    /* No read routines needed, however, we do need to move our fd */
	    stream_ops->dup2(fptr, fd+1);
	    /* And make sure we can get a console on max_fd+2 in case we need it */
	    console_fd = fd+2;
	    dup2(0, console_fd);
	    break;
	case CP_CHUNK_FD_FILE:
	    break;
	case CP_CHUNK_FD_SOCKET:
	    read_chunk_fd_socket(fptr, NULL, load, fd);
	    break;
	default:
	    bail("Invalid FD chunk type %d!", type);
    }
    if (close_on_exec != -1)
	fcntl(fd, F_SETFD, close_on_exec);
    if (fcntl_status != -1)
	fcntl(fd, F_SETFL, fcntl_status);
    lseek(fd, offset, SEEK_SET);
}

void write_chunk_fd(void *fptr, struct cp_fd *data)
{
    write_bit(fptr, &data->fd, sizeof(int));
    write_bit(fptr, &data->type, sizeof(int));
    write_bit(fptr, &data->mode, sizeof(int));
    write_bit(fptr, &data->close_on_exec, sizeof(int));
    write_bit(fptr, &data->fcntl_status, sizeof(int));
    write_bit(fptr, &data->offset, sizeof(off_t));

    switch (data->type) {
	case CP_CHUNK_FD_CONSOLE:
	    write_chunk_fd_console(fptr, &data->console);
	    break;
	case CP_CHUNK_FD_MAXFD:
	    /* No extra write routines needed. */
	    break;
	case CP_CHUNK_FD_FILE:
	    break;
	case CP_CHUNK_FD_SOCKET:
	    write_chunk_fd_socket(fptr, &data->socket);
	    break;
	default:
	    bail("Invalid FD chunk type %d!", data->type);
    }
}

static dev_t get_term_dev(pid_t pid)
{
    FILE *f;
    char tmp_fn[80], stat_line[80], *stat_ptr;
    dev_t term_dev = 0;

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

void fetch_chunks_fd(pid_t pid, int flags, struct list *l)
{
    struct cp_chunk *chunk = NULL;
    struct dirent *fd_dirent;
    struct stat stat_buf;
    DIR *proc_fd;
    char tmp_fn[1024];
    dev_t term_dev = get_term_dev(pid);
    int max_fd = 0;

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

	chunk->fd.fd = atoi(fd_dirent->d_name);

	if (chunk->fd.fd > max_fd)
	    max_fd = chunk->fd.fd;

	/* Find out if it's open for r/w/rw */
	snprintf(tmp_fn, 1024, "/proc/%d/fd/%d", pid, chunk->fd.fd);
	lstat(tmp_fn, &stat_buf);

	if ((stat_buf.st_mode & S_IRUSR) && (stat_buf.st_mode & S_IWUSR))
	    chunk->fd.mode = O_RDWR;
	else if (stat_buf.st_mode & S_IWUSR)
	    chunk->fd.mode = O_WRONLY;
	else
	    chunk->fd.mode = O_RDONLY;

	chunk->fd.close_on_exec = get_fcntl_close_on_exec(pid, chunk->fd.fd);
	chunk->fd.fcntl_status = get_fcntl_status(pid, chunk->fd.fd);
	chunk->fd.offset = get_file_offset(pid, chunk->fd.fd, 0, SEEK_CUR);

	/* This time stat the file/fifo/socket/etc, not the link */
	if (stat(tmp_fn, &stat_buf) < 0)
	    bail("Failed to stat(%s): %s", tmp_fn, strerror(errno));

	switch (stat_buf.st_mode & S_IFMT) {
	    case S_IFCHR:
		/* FIXME - only save termios for consoles once */
		/* is our terminal? */
		if (stat_buf.st_rdev == term_dev) {
		    save_fd_console(pid, flags, chunk->fd.fd, &chunk->fd.console);
		    chunk->fd.type = CP_CHUNK_FD_CONSOLE;
		    fprintf(stderr, "Saved console chunk (%d).\n", chunk->fd.fd);
		} else {
		    /* hmmm. what to do, what to do? */
		    debug("Ignoring open character device %s", tmp_fn);
		    continue;
		}
		break;
	    case S_IFSOCK:
		save_fd_socket(pid, flags, chunk->fd.fd, stat_buf.st_ino,
			&chunk->fd.socket);
		chunk->fd.type = CP_CHUNK_FD_SOCKET;
		break;
	    case S_IFREG:
		save_fd_file(pid, flags, chunk->fd.fd, stat_buf.st_ino,
			&chunk->fd.file);
		chunk->fd.type = CP_CHUNK_FD_FILE;
		break;
	    case S_IFBLK:
	    case S_IFDIR:
	    case S_IFIFO:
	    case S_IFLNK:
	    default:
		/* ummmm */
		continue;
	}

	/* Record it */
	chunk->type = CP_CHUNK_FD;
	list_append(l, chunk);
	chunk = NULL;
    }

    /* Note the highest used fd */
    chunk = xmalloc(sizeof(struct cp_chunk));
    chunk->type = CP_CHUNK_FD;
    chunk->fd.type = CP_CHUNK_FD_MAXFD;
    chunk->fd.fd = max_fd;
    list_insert(l, chunk);
}

/* vim:set ts=8 sw=4 noet: */
