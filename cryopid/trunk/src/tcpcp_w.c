/*
 * tcpcp.c - TCP connection passing high-level API
 *
 * Written 2002 by Werner Almesberger
 * Distributed under the LGPL.
 */


#include <stddef.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/user.h>
#include <linux/net.h>
#include <sys/ptrace.h>

#include "linux/tcpcp.h"

#include "cryopid.h"
#include "cpimage.h"
#include "tcpcp.h"

/* ----- Interface to low-level API ---------------------------------------- */


static int tcp_max_ici_size(pid_t pid, int s,int *size)
{
    struct user_regs_struct r;
    int size_size = sizeof(*size);
    long args[5];

    /* return getsockopt(s,SOL_TCP,TCP_MAXICISIZE,size,&size_size); */

    if (ptrace(PTRACE_GETREGS, pid, 0, &r) == -1) {
	perror("ptrace(GETREGS)");
	return 0;
    }

    r.eax = __NR_socketcall;
    r.ebx = SYS_GETSOCKOPT;
    r.ecx = scribble_zone+0x40;

    args[0] = s;
    args[1] = SOL_TCP;
    args[2] = TCP_MAXICISIZE;
    args[3] = scribble_zone+0x60;
    args[4] = scribble_zone+0x70;

    memcpy_into_target(pid, (void*)(scribble_zone+0x40), args, sizeof(args));
    memcpy_into_target(pid, (void*)(scribble_zone+0x70), &size_size, sizeof(size_size));

    if (!do_syscall(pid, &r)) {
	errno = ENOSYS;
	return -1;
    }

    if (r.eax < 0) {
	errno = -r.eax;
	return -1;
    }

    memcpy_from_target(pid, size, (void*)(scribble_zone+0x60), size_size);

    return 0;
}


static int tcp_get_ici(pid_t pid, int s, void *ici, int size)
{
    struct user_regs_struct r;
    long args[5];

    /* return getsockopt(s,SOL_TCP,TCP_ICI,ici,&size); */

    if (ptrace(PTRACE_GETREGS, pid, 0, &r) == -1) {
	perror("ptrace(GETREGS)");
	return 0;
    }

    r.eax = __NR_socketcall;
    r.ebx = SYS_GETSOCKOPT;
    r.ecx = scribble_zone+0x40;

    args[0] = s;
    args[1] = SOL_TCP;
    args[2] = TCP_ICI;
    args[3] = scribble_zone+0x70;
    args[4] = scribble_zone+0x60;

    memcpy_into_target(pid, (void*)(scribble_zone+0x40), args, sizeof(args));
    memcpy_into_target(pid, (void*)(scribble_zone+0x60), &size, sizeof(size));

    if (!do_syscall(pid, &r)) {
	errno = ENOSYS;
	return -1;
    }

    if (r.eax < 0) {
	errno = -r.eax;
	return -1;
    }

    memcpy_from_target(pid, ici, (void*)(scribble_zone+0x70), size);

    return 0;
}



/* ----- Public functions -------------------------------------------------- */

int tcpcp_size(const void *ici)
{
    const struct tcpcp_ici *_ici = ici;

    return ntohl(_ici->ici_length);
}


void *tcpcp_get(pid_t pid, int s)
{
    int size,saved_errno;
    void *ici;

    if (tcp_max_ici_size(pid, s, &size) < 0)
	return NULL;

    ici = malloc(size);
    if (!ici)
	return NULL;

    if (!tcp_get_ici(pid, s, ici,size))
	return ici;

    saved_errno = errno;
    free(ici);
    errno = saved_errno;
    return NULL;
}

/* vim:set ts=8 sw=4 noet: */
