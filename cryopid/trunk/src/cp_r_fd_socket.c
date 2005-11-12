#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/user.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>

#include "cryopid.h"
#include "cpimage.h"
#include "tcpcp.h"

/* dietlibc doesn't play ball with isdigit */
#define isdigit(x) ((x) >= '0' && (x) <= '9')

#define PROTO_UNIX	1
#define PROTO_TCP	6
#define PROTO_UDP	17

static void read_chunk_fd_socket_tcp(void *fptr, int fd, struct cp_socket_tcp *tcp,
	int action)
{
#ifdef USE_TCPCP
    void *ici;
    int len, s;
#endif

    if (action & ACTION_PRINT)
	fprintf(stderr, "TCP socket ");

#ifdef USE_TCPCP
    read_bit(fptr, &len, sizeof(int));
    if (!len)
	return;
    ici = xmalloc(len);
    read_bit(fptr, ici, len);

    if (action & ACTION_LOAD) {
	syscall_check(s = tcpcp_create(ici), 0, "tcpcp_create");
	if (s != fd) {
	    syscall_check(dup2(s, fd), 0, "dup2");
	    close(s);
	}
	syscall_check(tcpcp_activate(fd), 0, "tcpcp_activate");
    }
#endif
}

static void read_chunk_fd_socket_unix(void *fptr, int fd,
	struct cp_socket_unix *u, int action)
{
    struct sockaddr_un sun;
    int s, xsocket;

    if (action & ACTION_PRINT)
	fprintf(stderr, "UNIX socket ");

    read_bit(fptr, &sun.sun_family, sizeof(sun.sun_family));
    read_string(fptr, sun.sun_path, sizeof(sun.sun_path));

#ifdef USE_GTK
    /* Determine if it's an X server socket (match against m#/X\d+$#) */
    char *p;
    xsocket = 0;
    for (p = &sun.sun_path[strlen(sun.sun_path)-1];
	    p >= sun.sun_path && *p != '/';
	    p--) {
	if (!isdigit(*p)) {
	    xsocket = (*p == 'X');
	    break;
	}
    }
    /* Make sure we actually had some digits */
    if (xsocket && !isdigit(sun.sun_path[strlen(sun.sun_path)-1]))
	xsocket = 0;
    if (xsocket)
	snprintf(sun.sun_path, 20, "(X server %s)", p+1);
#endif

    if (action & ACTION_PRINT)
	fprintf(stderr, "%s ", sun.sun_path);

    if (action & ACTION_LOAD) {
#ifdef USE_GTK
	if (xsocket) {
	    int sp[2];
	    socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
	    s = sp[1];
	    if (!sys_clone(0, 0)) { /* don't give parent notification on exit */
		extern void x_responder(int);
		close(sp[1]);
		x_responder(sp[0]);
	    } else
		close(sp[0]);
	}
	else
#endif
	{
	    syscall_check(s = socket(PF_UNIX, SOCK_STREAM, 0), 0, "socket(PF_UNIX)");
	    if (connect(s, (const struct sockaddr*)&sun, strlen(sun.sun_path)+2) < 0)
		fprintf(stderr, "connect to %s: %s", sun.sun_path, strerror(errno));
	}
	if (s != fd) {
	    dup2(s, fd);
	    close(s);
	}
    }
}

void read_chunk_fd_socket(void *fptr, struct cp_fd *fd, int action)
{
    read_bit(fptr, &fd->socket.proto, sizeof(int));
    switch (fd->socket.proto) {
	case PROTO_TCP:
	    read_chunk_fd_socket_tcp(fptr, fd->fd, &fd->socket.s_tcp, action);
	    break;
	case PROTO_UNIX:
	    read_chunk_fd_socket_unix(fptr, fd->fd, &fd->socket.s_unix, action);
	    break;
	case PROTO_UDP:
	default:
	    if (action & ACTION_PRINT)
		fprintf(stderr, "unsupported socket type (%d)",
			fd->socket.proto);
	    break;
    }
}

/* vim:set ts=8 sw=4 noet: */
