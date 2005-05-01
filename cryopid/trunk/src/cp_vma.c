#include <linux/user.h>
#include <linux/kdev_t.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "cpimage.h"
#include "cryopid.h"

int extra_prot_flags;
long scribble_zone = 0; /* somewhere to scribble on in child */

void read_chunk_vma(void *fptr, struct cp_vma *data, int load)
{
    struct cp_vma vma;
    int fd;

    if (!data)
	data = &vma;
    read_bit(fptr, &data->start, sizeof(int));
    read_bit(fptr, &data->length, sizeof(int));
    read_bit(fptr, &data->prot, sizeof(int));
    read_bit(fptr, &data->flags, sizeof(int));
    read_bit(fptr, &data->dev, sizeof(int));
    read_bit(fptr, &data->pg_off, sizeof(int));
    read_bit(fptr, &data->inode, sizeof(int));
    data->filename = read_string(fptr, NULL, 1024);
    /* fprintf(stderr, "Loading 0x%x of size %d\n", data->start, data->length); */
    read_bit(fptr, &data->have_data, sizeof(data->have_data));
    read_bit(fptr, &data->checksum, sizeof(data->checksum));
    read_bit(fptr, &data->is_heap, sizeof(data->is_heap));
    if (load) {
	fd = -1;
	data->data = (void*)data->start;
	int try_local_lib = !(data->prot & PROT_WRITE) && data->have_data && data->filename[0];
	int need_checksum = try_local_lib || (!data->have_data && data->filename[0]);
	if (need_checksum) {
	    int good_lib = 0;
	    static char buf[4096];
	    /* check if the checksum matches first, else we may as well use
	     * that. */
	    if ((fd = open(data->filename, O_RDONLY)) != -1 &&
		lseek(fd, data->pg_off, SEEK_SET) == data->pg_off) {
		unsigned int c = 0;
		int remaining = data->length;
		while (remaining > 0) {
		    int len = sizeof(buf), rlen;
		    if (len > remaining)
			len = remaining;
		    rlen = read(fd, buf, len);
		    if (rlen == 0)
			break;
		    c = checksum(buf, rlen, c);
		    remaining -= rlen;
		}
		if (remaining <= sizeof(buf)) {
		    /* padded out to a page, compute checksum anyway */
		    memset(buf, 0, sizeof(buf));
		    c = checksum(buf, remaining, c);
		    remaining = 0;
		}
		if (remaining == 0) {
		    if (c == data->checksum) {
			/* we can just load it from disk, save memory */
			if (data->have_data) {
			    data->have_data = 0;
			    discard_bit(fptr, data->length);
			}
			good_lib = 1;
		    } else {
			close(fd);
		    }
		} else {
		    close(fd);
		}
	    }
	    if (!data->have_data && data->filename[0] && !good_lib) {
		bail("Aborting: Local libraries have changed (%s).\n"
			"Resuming will almost certainly fail!",
			data->filename);
	    }
	}
	if (data->have_data) {
	    if (data->is_heap) {
		/* Set the heap appropriately */
		brk(data->data+data->length);
		/* assert(sbrk(0) == data->data+data->length); */
	    }
	    syscall_check((int)mmap((void*)data->data, data->length,
			PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_FIXED | data->flags, -1, 0),
		    0, "mmap(0x%lx, 0x%lx, 0x%x, 0x%x, -1, 0)",
		    data->data, data->length, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_FIXED | data->flags);
	    read_bit(fptr, data->data, data->length);
	    syscall_check(mprotect((void*)data->data, data->length,
			data->prot | extra_prot_flags), 0, "mprotect");
	} else if (data->filename[0]) {
	    if (fd == -1)
		syscall_check(fd = open(data->filename, O_RDONLY), 0,
			"open(%s)", data->filename);
	    syscall_check((int)mmap((void*)data->data, data->length,
			PROT_READ | PROT_WRITE,
			MAP_FIXED | data->flags, fd, data->pg_off),
		    0, "mmap(0x%lx, 0x%lx, 0x%x, 0x%x, %d, 0x%x)",
		    data->data, data->length, PROT_READ | PROT_WRITE,
		    MAP_FIXED | data->flags, fd, data->pg_off);
	    syscall_check(close(fd), 0, "close(%d)", fd);
	    syscall_check(mprotect((void*)data->data, data->length,
			data->prot | extra_prot_flags), 0, "mprotect");
	} else
	    bail("No source for map 0x%lx (size 0x%lx)", data->start, data->length);
    } else {
	/* FIXME */
	/* load = 0 is not yet used */
    }
}

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

static int do_mprotect(pid_t pid, long start, int len, int flags)
{
    struct user_regs_struct r;

    if (ptrace(PTRACE_GETREGS, pid, 0, &r) == -1)
	bail("ptrace(GETREGS): %s", strerror(errno));

    r.eax = __NR_mprotect;
    r.ebx = start;
    r.ecx = len;
    r.edx = flags;

    if (!do_syscall(pid, &r)) return 0;

    /* Error checking! */
    if (r.eax < 0) {
	errno = -r.eax;
	return -1;
    }

    return r.eax;
}

static int get_one_vma(pid_t pid, char* line, struct cp_vma *vma,
	int get_library_data, long *bin_offset)
{
    char *ptr1, *ptr2;
    int dminor, dmajor;
    int old_vma_prot = -1;

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

    if (vma->start >= TRAMPOLINE_ADDR && vma->start <= TRAMPOLINE_ADDR+PAGE_SIZE)
	fprintf(stderr, "     Ignoring map - looks like resumer.\n");
    else if (vma->start >= RESUMER_START && vma->start <= RESUMER_END)
	fprintf(stderr, "     Ignoring map - looks like resumer.\n");
    else if (vma->start > 0xC0000000) /* FIXME - use get_task_size() */
	fprintf(stderr, "     Ignoring map - in kernel space.\n");
    else
	goto keep_going;

    return 0;

keep_going:

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

    if (vma->prot == PROT_NONE) {
	/* we need to modify it to be readable */
	old_vma_prot = vma->prot;
	do_mprotect(pid, vma->start, vma->length, PROT_READ);
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

    /* Now to get data too */
    if (get_library_data ||
	    ((vma->prot & PROT_WRITE) && (vma->flags & MAP_PRIVATE))
	    || (vma->flags & MAP_ANONYMOUS)) {
	/* We have a memory segment. We should retrieve its data */
	long *pos, *end;
	long *datapos;
	/* fprintf(stderr, "Retrieving %ld bytes from segment 0x%lx... ",
		vma->length, vma->start); */
	vma->data = xmalloc(vma->length);
	datapos = vma->data;
	end = (long*)(vma->start + vma->length);

	for(pos = (long*)(vma->start); pos < end; pos++, datapos++) {
	    *datapos = 
		ptrace(PTRACE_PEEKDATA, pid, pos, NULL);
	    if (errno != 0)
		perror("ptrace(PTRACE_PEEKDATA)");
	}

	/* fprintf(stderr, "done.\n"); */
	vma->have_data = 1;

	/* and checksum it */
	vma->checksum = checksum(vma->data, vma->length, 0);
    } else {
	/* checksum the data anyway */
	long *pos, *end;
	unsigned int c = 0, x;
	end = (long*)(vma->start + vma->length);
	for(pos = (long*)(vma->start); pos < end; pos++) {
	    x = ptrace(PTRACE_PEEKDATA, pid, pos, NULL);
	    if (errno != 0)
		perror("ptrace(PTRACE_PEEKDATA)");
	    c = checksum((char*)(&x)+0, 1, c);
	    c = checksum((char*)(&x)+1, 1, c);
	    c = checksum((char*)(&x)+2, 1, c);
	    c = checksum((char*)(&x)+3, 1, c);
	}

	vma->data = NULL;
	vma->checksum = c;
    }

    if (old_vma_prot != -1) {
	do_mprotect(pid, vma->start, vma->length, old_vma_prot);
    }

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
