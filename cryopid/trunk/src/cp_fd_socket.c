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
#include "tcpcp.h"

#define PROTO_UNIX	1
#define PROTO_TCP	6
#define PROTO_UDP	17

static int get_tcp_socket(struct cp_socket_tcp *tcp, pid_t pid, int fd, int inode)
{
    char line[200], *p;
    int i;
    FILE *f;
    
    f = fopen("/proc/net/tcp", "r");
    if (f == NULL) {
	debug("Couldn't open /proc/net/tcp!");
	return 0;
    }

    fgets(line, 200, f); /* ignore first line */
    while ((p = fgets(line, 200, f))) {
	p = line;
	for (i = 0; i < 9; i++) {
	    while(*p && (*p == ' ' || *p == '\t')) p++;
	    while(*p && (*p != ' ' && *p != '\t')) p++;
	}
	/* p now points at inode */
	if (atoi(p) == inode) {
	    break;
	}
    }
    if (!p) /* no match */
	return 0;

    /* We have a match, now just parse the line */

    /* FIXME: verify state and handle other ones */

    p = line;
    tcp->ici = tcpcp_get(pid, fd);

    if (!tcp->ici)
	debug("tcpcp_get(%d, %d): %s (%d)", pid, fd, strerror(errno), errno);
    debug("ici is %p", tcp->ici);

    return 1;
}

static void read_chunk_fd_socket_tcp(void *fptr, int fd, struct cp_socket_tcp *tcp)
{
    void *ici;
    int len, s;

    read_bit(fptr, &len, sizeof(int));
    if (!len)
	return;
    ici = xmalloc(len);
    read_bit(fptr, ici, len);
    syscall_check(s = tcpcp_create(ici), 0, "tcpcp_create");
    if (s != fd) {
	syscall_check(dup2(s, fd), 0, "dup2");
	close(s);
    }
    syscall_check(tcpcp_activate(fd), 0, "tcpcp_activate");
}

static void write_chunk_fd_socket_tcp(void *fptr, struct cp_socket_tcp *tcp)
{
    int len = 0;
    if (!tcp->ici) {
	write_bit(fptr, &len, sizeof(int));
	return;
    }
    len = tcpcp_size(tcp->ici);
    write_bit(fptr, &len, sizeof(int));
    write_bit(fptr, tcp->ici, len);
}

void save_fd_socket(pid_t pid, int flags, int fd, int inode,
		struct cp_socket *socket)
{
    if (get_tcp_socket(&socket->s_tcp, pid, fd, inode)) {
	socket->proto = PROTO_TCP;
	return;
    }
}

static void restore_fd_socket(int fd, struct cp_socket *socket)
{
}

void read_chunk_fd_socket(void *fptr, struct cp_socket *cptr, int load, int fd)
{
    struct cp_socket socket;
    read_bit(fptr, &socket.proto, sizeof(int));
    switch (socket.proto) {
	case PROTO_TCP:
	    read_chunk_fd_socket_tcp(fptr, fd, &socket.s_tcp);
	    break;
	case PROTO_UNIX:
	case PROTO_UDP:
	    break;
    }
    if (load) {
	restore_fd_socket(fd, &socket);
    } else {
	abort();
    }
}

void write_chunk_fd_socket(void *fptr, struct cp_socket *socket)
{
    write_bit(fptr, &socket->proto, sizeof(int));
    switch (socket->proto) {
	case PROTO_TCP:
	    write_chunk_fd_socket_tcp(fptr, &socket->s_tcp);
	    break;
	case PROTO_UNIX:
	case PROTO_UDP:
	    break;
    }
}

/* vim:set ts=8 sw=4 noet: */
