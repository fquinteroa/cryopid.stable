#include <fcntl.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "cpimage.h"
#include "cryopid.h"
#include "list.h"


unsigned int checksum(char *ptr, int len, unsigned int start)
{
    int sum = start, i;
    for (i = 0; i < len; i++)
	sum = ((sum << 5) + sum) ^ ptr[i];
    return sum;
}

void read_bit(void *fptr, void *buf, int len)
{
    int rlen;
    int c1, c2;

    if (len == 0)
	return;

    stream_ops->read(fptr, &c1, sizeof(c1));
    rlen = stream_ops->read(fptr, buf, len);
    if (rlen != len)
	bail("Read error (wanted %d bytes, got %d)!", len, rlen);
    c2 = checksum(buf, len, 0);
    if (c1 != c2)
	debug("CHECKSUM MISMATCH (len %d): should be 0x%x, measured 0x%x",
		len, c1, c2);
}

void discard_bit(void *fptr, int length)
{
    static char null[4096];
    int remaining;

    if (length == 0)
	return;

    stream_ops->read(fptr, null, sizeof(unsigned int));
    remaining = length;
    while (remaining > 0) {
	int len = sizeof(null);
	if (len > remaining)
	    len = remaining;
	remaining -= stream_ops->read(fptr, null, len);
    }
}

void write_bit(void *fptr, void *buf, int len)
{
    int c;

    if (len == 0)
	return;

    c = checksum(buf, len, 0);
    stream_ops->write(fptr, &c, sizeof(c));
    if (stream_ops->write(fptr, buf, len) != len)
	bail("Write error!");
}

char *read_string(void *fptr, char *buf, int maxlen)
{
    static char str_buf[1024];
    int len;

    read_bit(fptr, &len, sizeof(int));

    if (len > maxlen) /* We don't cater for this */
	bail("String longer than expected!");

    if (len > 1024) /* FIXME: hack */
	bail("String longer than can handle!");

    if (!buf)
	buf = str_buf;

    read_bit(fptr, buf, len);
    buf[len] = '\0';

    return buf;
}

void write_string(void *fptr, char *buf)
{
    int len = 0;
    
    if (buf)
	len = strlen(buf);
    write_bit(fptr, &len, sizeof(int));

    if (buf)
	write_bit(fptr, buf, len);
}

int read_chunk(void *fptr, struct cp_chunk **chunkp, int load)
{
    struct cp_chunk *chunk = NULL;
    int magic, type;
    
    /* debug("Reading chunk at %d...", ftell(*(FILE**)fptr)); */

    read_bit(fptr, &magic, sizeof(magic));
    if (magic != CP_CHUNK_MAGIC)
	bail("Invalid magic in chunk header (0x%x)!", magic);

    read_bit(fptr, &type, sizeof(type));

    if (!load) {
	chunk = xmalloc(sizeof(struct cp_chunk));
	chunk->type = type;
    }

    switch (type) {
	case CP_CHUNK_MISC:
	    read_chunk_misc(fptr, chunk?&chunk->misc:NULL, load);
	    break;
	case CP_CHUNK_REGS:
	    read_chunk_regs(fptr, chunk?&chunk->regs:NULL, load);
	    break;
	case CP_CHUNK_I387_DATA:
	    read_chunk_i387_data(fptr, chunk?&chunk->i387_data:NULL, load);
	    break;
	case CP_CHUNK_TLS:
	    read_chunk_tls(fptr, chunk?&chunk->tls:NULL, load);
	    break;
	case CP_CHUNK_FD:
	    read_chunk_fd(fptr, chunk?&chunk->fd:NULL, load);
	    break;
	case CP_CHUNK_VMA:
	    read_chunk_vma(fptr, chunk?&chunk->vma:NULL, load);
	    break;
	case CP_CHUNK_SIGHAND:
	    read_chunk_sighand(fptr, chunk?&chunk->sighand:NULL, load);
	    break;
	case CP_CHUNK_FINAL:
	    free(chunk);
	    return 0;
	default:
	    bail("Unknown chunk type read (0x%x)", chunk->type)
    }

    if (chunkp)
	*chunkp = chunk;
    else
	free(chunk);
    return 1;
}

static void write_final_chunk(void *fptr)
{
    int magic = CP_CHUNK_MAGIC, type = CP_CHUNK_FINAL;
    write_bit(fptr, &magic, sizeof(int));
    write_bit(fptr, &type, sizeof(int));
}

void write_chunk(void *fptr, struct cp_chunk *chunk)
{
    int magic = CP_CHUNK_MAGIC;

    write_bit(fptr, &magic, sizeof(magic));
    write_bit(fptr, &chunk->type, sizeof(chunk->type));

    switch (chunk->type) {
	case CP_CHUNK_MISC:
	    write_chunk_misc(fptr, &chunk->misc);
	    break;
	case CP_CHUNK_REGS:
	    write_chunk_regs(fptr, &chunk->regs);
	    break;
	case CP_CHUNK_I387_DATA:
	    write_chunk_i387_data(fptr, &chunk->i387_data);
	    break;
	case CP_CHUNK_TLS:
	    write_chunk_tls(fptr, &chunk->tls);
	    break;
	case CP_CHUNK_FD:
	    write_chunk_fd(fptr, &chunk->fd);
	    break;
	case CP_CHUNK_VMA:
	    write_chunk_vma(fptr, &chunk->vma);
	    break;
	case CP_CHUNK_SIGHAND:
	    write_chunk_sighand(fptr, &chunk->sighand);
	    break;
	default:
	    bail("Unknown chunk type to write (0x%x)", chunk->type)
    }
}

void write_process(int fd, struct list l)
{
    void *fptr;
    struct item *i;

    fptr = stream_ops->init(fd, O_WRONLY);
    if (!fptr)
	bail("Unable to initialize writer.");

    for (i = l.head; i; i = i->next) {
	struct cp_chunk *cp = i->p;
	write_chunk(fptr, cp);
    }

    write_final_chunk(fptr);

    stream_ops->finish(fptr);
    debug("Written image.");
}

/* vim:set ts=8 sw=4 noet: */
