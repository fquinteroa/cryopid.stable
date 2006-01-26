#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

#include "cryopid.h"

#define DEFAULT_PORT 9898

int connect_to_host(char *host)
{
	int fd, val;
	struct sockaddr_in sin;
	struct hostent *hp;
	
	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		bail("socket");

	if ((hp = gethostbyname(host)) == NULL)
		bail("gethostbyname");

	if (!hp->h_addr_list[0])
		bail("No address records for host %s.\n", host);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(DEFAULT_PORT);
	memcpy(&sin.sin_addr, hp->h_addr_list[0], hp->h_length);

	if (connect(fd, (struct sockaddr*)&sin, sizeof(sin)) == -1)
		bail("connect");

	val = 3; write(fd, &val, sizeof(val)); /* argc = 3 */
	val = 14; write(fd, &val, sizeof(val)); write(fd, "remote-cryopid", 14);
	val = 2; write(fd, &val, sizeof(val)); write(fd, "-n", 2);
	val = 2; write(fd, &val, sizeof(val)); write(fd, "-v", 2);

	return fd;
}
