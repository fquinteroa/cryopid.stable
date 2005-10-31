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
#ifdef USE_TCPCP
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
	if (atoi(p) == inode)
	    break;
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
#else
    return 0;
#endif
}

static int get_unix_socket(struct cp_socket_unix *u, pid_t pid, int fd,
	int inode)
{
    char line[200], *p;
    int i;
    FILE *f;
    
    f = fopen("/proc/net/unix", "r");
    if (f == NULL) {
	debug("Couldn't open /proc/net/unix!");
	return 0;
    }

    inode++; /* FIXME: will our remote end always have inode + 1? */

    fgets(line, 200, f); /* ignore first line */
    while ((p = fgets(line, 200, f))) {
	p = line;
	for (i = 0; i < 6; i++) {
	    while(*p && (*p == ' ' || *p == '\t')) p++;
	    while(*p && (*p != ' ' && *p != '\t')) p++;
	}
	/* p now points at inode */
	if (atoi(p) == inode)
	    break;
    }
    if (!p) /* no match */
	return 0;

    /* We have a match. The socket name follows. */
    while(*p && (*p == ' ' || *p == '\t')) p++;
    while(*p && (*p != ' ' && *p != '\t')) p++;
    while(*p && (*p == ' ' || *p == '\t')) p++;

    u->sun.sun_family = AF_UNIX;
    strncpy(u->sun.sun_path, p, sizeof(u->sun.sun_path));

    /* Force null termination */
    u->sun.sun_path[sizeof(u->sun.sun_path)-1] = '\0';

    /* Remove trailing LFs */
    for (p = u->sun.sun_path; *p != '\0' && *p != '\r' && *p != '\n'; *p++);
    *p = '\0';

    debug("UNIX socket connected to %s", u->sun.sun_path);

    return 1;
}

static void write_chunk_fd_socket_tcp(void *fptr, struct cp_socket_tcp *tcp)
{
#ifdef USE_TCPCP
    int len = 0;
    if (!tcp->ici) {
	write_bit(fptr, &len, sizeof(int));
	return;
    }
    len = tcpcp_size(tcp->ici);
    write_bit(fptr, &len, sizeof(int));
    write_bit(fptr, tcp->ici, len);
#endif
}

static void write_chunk_fd_socket_unix(void *fptr, struct cp_socket_unix *u)
{
    /* Almost certainly AF_UNIX, but do it anyway */
    write_bit(fptr, &u->sun.sun_family, sizeof(u->sun.sun_family));

    write_string(fptr, u->sun.sun_path);
}

void fetch_fd_socket(pid_t pid, int flags, int fd, int inode,
		struct cp_socket *socket)
{
    if (get_tcp_socket(&socket->s_tcp, pid, fd, inode))
	socket->proto = PROTO_TCP;
    else if (get_unix_socket(&socket->s_unix, pid, fd, inode))
	socket->proto = PROTO_UNIX;
}

void write_chunk_fd_socket(void *fptr, struct cp_socket *socket)
{
    write_bit(fptr, &socket->proto, sizeof(int));
    switch (socket->proto) {
	case PROTO_TCP:
	    write_chunk_fd_socket_tcp(fptr, &socket->s_tcp);
	    break;
	case PROTO_UNIX:
	    write_chunk_fd_socket_unix(fptr, &socket->s_unix);
	    break;
	case PROTO_UDP:
	    break;
    }
}

/* vim:set ts=8 sw=4 noet: */
