#include <asm/termios.h>
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

static int get_termios(pid_t pid, int fd, struct termios *t)
{
    struct user_regs_struct r;

    if (ptrace(PTRACE_GETREGS, pid, 0, &r) == -1) {
	perror("ptrace(GETREGS)");
	return 0;
    }

    r.eax = __NR_ioctl;
    r.ebx = fd;
    r.ecx = TCGETS;
    r.edx = scribble_zone+0x50;

    if (!do_syscall(pid, &r)) return 0;

    /* Error checking! */
    if (r.eax < 0) {
	errno = -r.eax;
	perror("target ioctl");
	return 0;
    }

    memcpy_from_target(pid, t, (void*)(scribble_zone+0x50), sizeof(struct termios));

    return 1;
}

void fetch_fd_console(pid_t pid, int flags, int fd, struct cp_console *console)
{
    get_termios(pid, fd, &console->termios); /* FIXME: error checking? */
}

static void restore_fd_console(int fd, struct cp_console *console)
{
    /* Declare ioctl extern, as including sys/ioctl.h makes compilation unhappy :/ */
    extern int ioctl(int fd, unsigned long req, ...);
    dup2(console_fd, fd);
    ioctl(fd, TCSETS, &console->termios);
}

void read_chunk_fd_console(void *fptr, struct cp_fd *fd, int action)
{
    read_bit(fptr, &fd->console.termios, sizeof(struct termios));
    
    if (action & ACTION_PRINT)
	fprintf(stderr, "console FD ");

    if (action & ACTION_LOAD)
	restore_fd_console(fd->fd, &fd->console);
}

void write_chunk_fd_console(void *fptr, struct cp_fd *fd)
{
    write_bit(fptr, &fd->console.termios, sizeof(struct termios));
}

/* vim:set ts=8 sw=4 noet: */
