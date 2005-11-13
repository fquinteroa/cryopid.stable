#include <sys/stat.h>
#include <sys/types.h>
#include <linux/net.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include "cryopid.h"
#include "process.h"
#include "cpimage.h"
#include "tcpcp.h"

#define PROTO_UNIX	1
#define PROTO_TCP	6
#define PROTO_UDP	17

struct unix_sock_info_t {
    int listening;
    int type;
    int state;
    char path[108]; /* As defined in sys/un.h */
};

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

static int get_socket_info(int inode, struct unix_sock_info_t *info)
{
    FILE *f;
    char line[512], *p;

    f = fopen("/proc/net/unix", "r");
    if (f == NULL) {
	debug("Couldn't open /proc/net/unix!");
	return 0;
    }

    /*
     * Num       RefCount Protocol Flags    Type St Inode Path
     * efacc44c: 00000002 00000000 00000000 0002 01  3015 /tmp/.X11-unix/X0
     */
    fgets(line, sizeof(line), f); /* ignore first line */
#define skip_to_next() \
	    while(*p && (*p != ' ' && *p != '\t')) p++; \
	    while(*p && (*p == ' ' || *p == '\t')) p++

    while ((p = fgets(line, sizeof(line), f))) {
	p = line;
	/* Num */
	skip_to_next();
	/* RefCount */
	skip_to_next();
	/* Protocol */
	skip_to_next();
	/* Flags */
	info->listening = (strtoul(p, NULL, 16) & __SO_ACCEPTCON);
	skip_to_next();
	/* Type */
	info->type = strtoul(p, NULL, 16);
	skip_to_next();
	/* State */
	info->state = strtoul(p, NULL, 16);
	skip_to_next();
	/* Inode */
	if (atoi(p) == inode)
	    break;
    }
    fclose(f);

    if (!p) /* no match */
	return 0;

    /* We have a match. The socket name follows. */
    skip_to_next();
    /* Path */
    strncpy(info->path, p, sizeof(info->path));
    info->path[sizeof(info->path)-1] = '\0';
    for (p = info->path; *p != '\0' && *p != '\r' && *p != '\n'; *p++);
    *p = '\0';
#undef skip_to_next

    return 1;
}

static int get_unix_socket(struct cp_socket_unix *u, pid_t pid, int fd,
	int inode)
{
    struct unix_sock_info_t usi;
    socklen_t sz;

    if (!get_socket_info(inode, &usi))
	return 0;

    memset(u, 0, sizeof(*u));

    u->type = usi.type;
    u->listening = usi.listening;

    sz = sizeof(u->sockname);
    if (r_getsockname(pid, fd, (struct sockaddr*)&u->sockname, &sz) < 0)
	perror("r_getsockname");

    if (usi.state & SS_CONNECTED) {
	sz = sizeof(u->sockname);
	r_getpeername(pid, fd, (struct sockaddr*)&u->peername, &sz);
    }

    /* Force null termination */
    u->sockname.sun_path[sizeof(u->sockname.sun_path)-1] = '\0';
    u->peername.sun_path[sizeof(u->peername.sun_path)-1] = '\0';

    debug("fd %d (ino %d): UNIX socket connected from %s to %s (listening: %d)",
	    fd, inode, u->sockname.sun_path, u->peername.sun_path, u->listening);

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
    write_bit(fptr, u, sizeof(*u));
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
