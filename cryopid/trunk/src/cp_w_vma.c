#include <linux/user.h>
#include <linux/kdev_t.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "cpimage.h"
#include "process.h"
#include "cryopid.h"

long scribble_zone = 0; /* somewhere to scribble on in child */

void write_chunk_vma(void *fptr, struct cp_vma *data)
{
    write_bit(fptr, &data->start, sizeof(int));
    write_bit(fptr, &data->length, sizeof(int));
    write_bit(fptr, &data->prot, sizeof(int));
    write_bit(fptr, &data->flags, sizeof(int));
    write_bit(fptr, &data->dev, sizeof(int));
    write_bit(fptr, &data->pg_off, sizeof(int));
    write_bit(fptr, &data->inode, sizeof(int));
    write_string(fptr, data->filename);
    write_bit(fptr, &data->have_data, sizeof(data->have_data));
    write_bit(fptr, &data->checksum, sizeof(data->checksum));
    write_bit(fptr, &data->is_heap, sizeof(data->is_heap));
    if (data->have_data)
	write_bit(fptr, data->data, data->length);
}

static int get_one_vma(pid_t pid, char* line, struct cp_vma *vma,
	int get_library_data, long *bin_offset)
{
    char *ptr1, *ptr2;
    int dminor, dmajor;
    int old_vma_prot = -1;
    int keep_vma_data;

    memset(vma, 0, sizeof(struct cp_vma));

    /* Parse a line that looks like one of the following: 
	08048000-080ab000 r-xp 00000000 03:03 1309106    /home/b/dev/sp/test
	080ab000-080ae000 rw-p 00062000 03:03 1309106    /home/b/dev/sp/test
	080ae000-080db000 rwxp 00000000 00:00 0 
	40000000-40203000 rw-p 00000000 00:00 0 
	bfffe000-c0000000 rwxp 00000000 00:00 0 
    */

    ptr1 = line;
    if ((ptr2 = strchr(ptr1, '-')) == NULL) {
	fprintf(stderr, "No - in map line!\n");
	return 0;
    }
    *ptr2 = '\0';
    vma->start = strtoul(ptr1, NULL, 16);

    if (vma->start >= TRAMPOLINE_ADDR && vma->start <= TRAMPOLINE_ADDR+PAGE_SIZE) {
	fprintf(stderr, "     Ignoring map - looks like resumer.\n");
	return 0;
    }
    if (vma->start >= RESUMER_START && vma->start <= RESUMER_END) {
	fprintf(stderr, "     Ignoring map - looks like resumer.\n");
	return 0;
    }
    if (vma->start >= get_task_size()) {
	fprintf(stderr, "     Ignoring map - in kernel space.\n");
	return 0;
    }

    ptr1 = ptr2+1;
    if ((ptr2 = strchr(ptr1, ' ')) == NULL) {
	fprintf(stderr, "No end of end in map line!\n");
	return 0;
    }
    *ptr2 = '\0';
    vma->length = strtoul(ptr1, NULL, 16) - vma->start;

    vma->prot = 0;
    ptr1 = ptr2+1;

    if (ptr1[0] == 'r')
	vma->prot |= PROT_READ;
    else if (ptr1[0] != '-')
	fprintf(stderr, "Bad read flag: %c\n", ptr1[0]);

    if (ptr1[1] == 'w')
	vma->prot |= PROT_WRITE;
    else if (ptr1[1] != '-')
	fprintf(stderr, "Bad write flag: %c\n", ptr1[1]);

    if (ptr1[2] == 'x')
	vma->prot |= PROT_EXEC;
    else if (ptr1[2] != '-')
	fprintf(stderr, "Bad exec flag: %c\n", ptr1[2]);

    vma->flags = MAP_FIXED;
    if (ptr1[3] == 's')
	vma->flags |= MAP_SHARED;
    else if (ptr1[3] != 'p')
	fprintf(stderr, "Bad shared flag: %c\n", ptr1[3]);
    else
	vma->flags |= MAP_PRIVATE;

    ptr1 = ptr1+5; /* to pgoff */
    if ((ptr2 = strchr(ptr1, ' ')) == NULL) {
	fprintf(stderr, "No end of pgoff in map line!\n");
	return 0;
    }
    *ptr2 = '\0';
    vma->pg_off = strtoul(ptr1, NULL, 16);

    if ((signed long)vma->pg_off < 0) {
	vma->flags |= MAP_GROWSDOWN;
    }

    ptr1 = ptr2+1;
    if ((ptr2 = strchr(ptr1, ':')) == NULL) {
	fprintf(stderr, "No end of major dev in map line!\n");
	return 0;
    }
    *ptr2 = '\0';
    dmajor = strtoul(ptr1, NULL, 16);

    ptr1 = ptr2+1;
    if ((ptr2 = strchr(ptr1, ' ')) == NULL) {
	fprintf(stderr, "No end of minor dev in map line!\n");
	return 0;
    }
    *ptr2 = '\0';
    dminor = strtoul(ptr1, NULL, 16);
    
    vma->dev = MKDEV(dmajor, dminor);

    ptr1 = ptr2+1;
    if ((ptr2 = strchr(ptr1, ' ')) != NULL) {
	*ptr2 = '\0';
	vma->inode = strtoul(ptr1, NULL, 10);

	ptr1 = ptr2+1;
	while (*ptr1 == ' ') ptr1++;
	if (*ptr1 != '\n') { /* we have a filename too to grab */
	    ptr2 = strchr(ptr1, '\n');
	    if (ptr2) *ptr2 = '\0';
	    vma->filename = strdup(ptr1);
	    if (bin_offset && !*bin_offset && !strcmp(vma->filename, "[heap]")) {
		*bin_offset = vma->start;
		vma->flags |= MAP_ANONYMOUS;
		vma->is_heap = 1;
	    }
	} else {
	    if (bin_offset && !*bin_offset &&
		    ((vma->prot & (PROT_READ|PROT_WRITE)) ==
		     (PROT_READ|PROT_WRITE))) {
		/* First rw* anonymous segment off the rank - well it looks like
		 * a heap :) */
		*bin_offset = vma->start;
		vma->is_heap = 1;
	    }
	    vma->flags |= MAP_ANONYMOUS;
	}
    } else {
	vma->inode = strtoul(ptr1, NULL, 10);
    }

    /* we have all the info we need, regurgitate it for confirmation */
    fprintf(stderr, "Map: %08lx-%08lx %c%c%c%c %08lx %02x:%02x %-10ld %s\n",
	    vma->start, vma->start + vma->length,
	    (vma->prot & PROT_READ)?'r':'-',
	    (vma->prot & PROT_WRITE)?'w':'-',
	    (vma->prot & PROT_EXEC)?'x':'-',
	    (vma->flags & MAP_SHARED)?'s':'p',
	    vma->pg_off,
	    MAJOR(vma->dev), MINOR(vma->dev),
	    vma->inode,
	    vma->filename);

    if (!(vma->prot & PROT_READ)) {
	/* we need to modify it to be readable */
	old_vma_prot = vma->prot;
	r_mprotect(pid, (void*)vma->start, vma->length, PROT_READ);
    }

    /* Decide if it's scribble worthy - find a nice anonymous mapping */
    if (scribble_zone == 0 &&
	    !vma->filename &&
	    (vma->flags & MAP_PRIVATE) &&
	    !(vma->flags & MAP_SHARED) &&
	    ((vma->prot & (PROT_READ|PROT_WRITE)) == (PROT_READ|PROT_WRITE))) {
	scribble_zone = vma->start;
	debug("[+] Found scribble zone: 0x%lx", scribble_zone);
    }

    /* Fetch the data, at least for checksumming purposes. */
    vma->data = xmalloc(vma->length);
    memcpy_from_target(pid, vma->data, (void*)vma->start, vma->length);
    vma->checksum = checksum(vma->data, vma->length, 0);

    /* Cases where we want to keep the VMA in the image */
    keep_vma_data = (
	    get_library_data ||
	    ((vma->prot & PROT_WRITE) && (vma->flags & MAP_PRIVATE)) || 
	    (vma->flags & MAP_ANONYMOUS)
	    );

    /* If it's on disk and we're not saving libraries, checksum the source to
     * verify it really is the same.
     */
    if (!keep_vma_data && vma->filename) {
	int lfd;
	int remaining;
	unsigned int c;
	static char buf[4096];

	keep_vma_data = 1; /* Assume guiltly until proven innocent */

	if ((lfd = open(vma->filename, O_RDONLY)) == -1)
	    goto out;

	if (lseek(lfd, vma->pg_off, SEEK_SET) != vma->pg_off)
	    goto out_close;

	remaining = vma->length;
	c = 0;
	while (remaining > 0) {
	    int len = sizeof(buf), rlen;
	    if (len > remaining)
		len = remaining;
	    rlen = read(lfd, buf, len);
	    if (rlen == -1)
		goto out_close;
	    if (rlen == 0)
		break;
	    c = checksum(buf, rlen, c);
	    remaining -= rlen;
	}

	if (0 < remaining && remaining <= sizeof(buf)) {
	    /* padded out to a page, compute checksum anyway */
	    memset(buf, 0, sizeof(buf));
	    c = checksum(buf, remaining, c);
	    remaining = 0;
	}

	/* So did we have a good checksum after all that? */
	if (c == vma->checksum)
	    keep_vma_data = 0;

out_close:
	close(lfd);
    }
out:

    /* Figure out if we need to keep it */
    if (vma->data && keep_vma_data) {
	vma->have_data = 1;
    } else {
	free(vma->data);
	vma->data = NULL;
    }

    if (old_vma_prot != -1)
	r_mprotect(pid, (void*)vma->start, vma->length, old_vma_prot);

    return 1;
}

void fetch_chunks_vma(pid_t pid, int flags, struct list *l, long *bin_offset)
{
    struct cp_chunk *chunk = NULL;
    char tmp_fn[30];
    char map_line[128];
    FILE *f;

    snprintf(tmp_fn, 30, "/proc/%d/maps", pid);
    f = fopen(tmp_fn, "r");

    while (fgets(map_line, 128, f)) {
	if (!chunk)
	    chunk = xmalloc(sizeof(struct cp_chunk));
	chunk->type = CP_CHUNK_VMA;
	if (!get_one_vma(pid, map_line, &chunk->vma, flags & GET_LIBRARIES_TOO,
		    bin_offset)) {
	    debug("     Error parsing map: %s", map_line);
	    continue;
	}
	list_append(l, chunk);
	chunk = NULL;
    }
    if (chunk)
	free(chunk);

    fclose(f);
}

/* vim:set ts=8 sw=4 noet: */
