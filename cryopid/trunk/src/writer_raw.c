#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "cryopid.h"
#include "cpimage.h"

struct raw_data {
    FILE* f; /* So we can use buffering */
};

static void *raw_init(int fd, int mode) {
    struct raw_data *rd;

    rd = xmalloc(sizeof(struct raw_data));

    switch (mode) {
	case O_RDONLY:
	    rd->f = fdopen(fd, "r");
	    break;
	case O_WRONLY:
	    rd->f = fdopen(fd, "w");
	    break;
	case O_RDWR:
	    rd->f = fdopen(fd, "r+");
	    break;
	default:
	    bail("Invalid mode passed!");
    }
    if (!rd->f)
	bail("fdopen(): %s", strerror(errno));

    return rd;
}

static void raw_finish(void *fptr) {
    struct raw_data *rd = fptr;

    fflush(rd->f);
    free(rd);
}

static int raw_read(void *fptr, void *buf, int len) {
    int rlen, togo;
    struct raw_data *rd = fptr;
    char *p;

    togo = len;
    p = buf;
    while (togo > 0) {
	rlen = fread(p, 1, len, rd->f);
	if (rlen <= 0)
	    bail("fread(0x%p, 1, %d, rd->f) failed: %s", 
		    p, len, strerror(errno));
	p += rlen;
	togo -= rlen;
    }
    return len;
}

static int raw_write(void *fptr, void *buf, int len) {
    int wlen;
    struct raw_data *rd = fptr;

    wlen = fwrite(buf, 1, len, rd->f);
    return wlen;
}

struct stream_ops raw_ops = {
    .init = raw_init,
    .read = raw_read,
    .write = raw_write,
    .finish = raw_finish,
};

/* vim:set ts=8 sw=4 noet: */
