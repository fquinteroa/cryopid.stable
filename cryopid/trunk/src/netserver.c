#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

#define bail(s, x...) do { fprintf(stderr, "Error in "s": %m\n", ##x); exit(1); } while (0)

#define LISTEN_PORT 9898

void launch_process(int socket)
{
	pid_t pid;

	dup2(socket, 42);
	close(socket);
	fcntl(42, F_SETFD, 0);
	switch ((pid = fork())) {
		case -1:
			bail("fork");
		case 0:
#if 0
			if (fork()) exit(0);
			setsid();
#endif
			execl("./stub-raw", NULL);
			exit(1);
		default:
			waitpid(pid, NULL, 0);
			break;
	}
	close(42);
}

void handle_connection(int socket, struct sockaddr_in *sin)
{
	printf("Received connection from %d.%d.%d.%d:%d\n", 
			(sin->sin_addr.s_addr >>  0) & 0xff,
			(sin->sin_addr.s_addr >>  8) & 0xff,
			(sin->sin_addr.s_addr >> 16) & 0xff,
			(sin->sin_addr.s_addr >> 24),
			ntohs(sin->sin_port));
	launch_process(socket);
}

void accept_connections()
{
	struct sockaddr_in sin;
	int listening_socket, client_socket, val;

	/* Create the socket */
	if ((listening_socket = socket(PF_INET, SOCK_STREAM, 0)) == -1)
		bail("socket");

	/* Set SO_REUSEADDR */
	val = 1;
	if ((setsockopt(listening_socket, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val))) == -1)
		bail("setsockopt");

	/* Bind to all interfaces */
	memset(&sin, 0, sizeof(sin));
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(LISTEN_PORT);
	if ((bind(listening_socket, (struct sockaddr*)&sin, sizeof(struct sockaddr_in))) == -1)
		bail("bind");

	if ((listen(listening_socket, 4)) == -1)
		bail("listen");
	
	/* And start accepting connections */
	val = sizeof(sin);
	while ((client_socket = accept(listening_socket, (struct sockaddr*)&sin, &val)) != -1) {
		/* Handle this client */
		handle_connection(client_socket, &sin);
	}
	bail("accept");
	close(listening_socket);
}

int main() {
	accept_connections();

	return 0;
}
