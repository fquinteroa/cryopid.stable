#ifndef _PROCESS_H_
#define _PROCESS_H_

#include <sys/types.h>
#include <linux/user.h>
#include <linux/kdev_t.h>
#include <linux/types.h>

#include "cryopid.h"
#include "cpimage.h"

#define MAX_SIGS 31

/* Flags for fd_entry_t.flags */
#define FD_IS_TERMINAL       1
#define FD_OFFSET_NOT_SAVED  2
#define FD_TERMIOS           4

struct proc_header_t {
    pid_t pid;

    int n_children;
    struct proc_header_t *children;

    int n_pipes;
    int *pipe_pairs; /* parent fd/child fd pipe pairs */
};

/* flags passed to get_proc_image */
#define GET_LIBRARIES_TOO          0x01
#define GET_OPEN_FILE_CONTENTS     0x02

int is_a_syscall(unsigned long inst, int canonical);
int is_in_syscall(pid_t pid, struct user *user);
void set_syscall_return(struct user* user, unsigned long val);
int memcpy_from_target(pid_t pid, void* dest, const void* src, size_t n);
int memcpy_into_target(pid_t pid, void* dest, const void* src, size_t n);

extern off_t r_lseek(pid_t pid, int fd, off_t offset, int whence);
extern int r_fcntl(pid_t pid, int fd, int cmd);
extern int r_mprotect(pid_t pid, void *start, size_t len, int flags);
extern int r_rt_sigaction(pid_t pid, int sig, struct k_sigaction *ksa,
	struct k_sigaction *oksa, size_t masksz);
extern int r_ioctl(pid_t pid, int fd, int req, void* val);
extern int r_socketcall(pid_t pid, int call, void* args);
extern int r_getpeername(pid_t pid, int s, struct sockaddr *name, socklen_t *namelen);
extern int r_getsockname(pid_t pid, int s, struct sockaddr *name, socklen_t *namelen);

#endif /* _PROCESS_H_ */

/* vim:set ts=8 sw=4 noet: */
