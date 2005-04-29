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
    read_bit(fptr, &data->have_data, sizeof(int));
    if (load) {
	data->data = (void*)data->start;
	if (data->have_data) {
	    syscall_check((int)mmap((void*)data->data, data->length,
			data->prot | extra_prot_flags,
			MAP_ANONYMOUS | MAP_FIXED | data->flags, -1, 0),
		    0, "mmap(0x%lx, 0x%lx, 0x%x, 0x%x, -1, 0)",
		    data->data, data->length, data->prot | extra_prot_flags,
		    MAP_ANONYMOUS | MAP_FIXED | data->flags);
	    read_bit(fptr, data->data, data->length);
	} else if (data->filename[0]) {
	    syscall_check(fd = open(data->filename, O_RDONLY), 0,
		    "open(%s)", data->filename);
	    syscall_check((int)mmap((void*)data->data, data->length,
			data->prot | extra_prot_flags,
			MAP_FIXED | data->flags, fd, data->pg_off),
		    0, "mmap(0x%lx, 0x%lx, 0x%x, 0x%x, %d, 0x%x)",
		    data->data, data->length, data->prot | extra_prot_flags,
		    MAP_FIXED | data->flags, fd, data->pg_off);
	    syscall_check(close(fd), 0, "close(%d)", fd);
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
    write_bit(fptr, &data->have_data, sizeof(int));
    if (data->have_data)
	write_bit(fptr, data->data, data->length);
}

static int do_mprotect(pid_t pid, long start, int len, int flags)
{
    struct user_regs_struct r;

    if (ptrace(PTRACE_GETREGS, pid, 0, &r) == -1)
	bail("ptrace(GETREGS): %s", strerror(errno));

    /* FIXME: large file support? llseek and offset to 64-bit? */
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
	int get_library_data, long *heap_start)
{
    char *ptr1, *ptr2;
    int dminor, dmajor;

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
	    if (heap_start && strcmp(vma->filename, "[heap]") == 0) {
		*heap_start = vma->start;
		vma->flags |= MAP_ANONYMOUS;
	    }
	} else {
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

    /* Decide if it's scribble worthy - find a nice anonymous mapping */
    if (scribble_zone == 0 &&
	    !vma->filename &&
	    (vma->flags & MAP_PRIVATE) &&
	    !(vma->flags & MAP_SHARED) &&
	    ((vma->prot & (PROT_READ|PROT_WRITE)) == (PROT_READ|PROT_WRITE))) {
	scribble_zone = vma->start;
	printf("[+] Found scribble zone: 0x%lx\n", scribble_zone);
    }

    if (get_library_data) {
	/* forget the fact it came from a file. Pretend it was just
	 * some arbitrary anonymous writeable VMA.
	 */
	free(vma->filename);
	vma->filename = NULL;
	vma->inode = 0;
	vma->prot |= PROT_WRITE;

	vma->flags &= ~MAP_SHARED;
	vma->flags |= MAP_PRIVATE | MAP_ANONYMOUS;
    }

    /* Now to get data too */
    if (((vma->prot & PROT_WRITE) && (vma->flags & MAP_PRIVATE))
	    || (vma->prot & MAP_ANONYMOUS)) {
	/* We have a memory segment. We should retrieve its data */
	long *pos, *end;
	long *datapos;
	/*fprintf(stderr, "Retrieving %ld bytes from segment 0x%lx... ",
		vma->length, vma->start); */
	vma->data = xmalloc(vma->length);
	datapos = vma->data;
	end = (long*)(vma->start + vma->length);

	for(pos = (long*)(vma->start); pos < end; pos++, datapos++) {
	    *datapos = 
		ptrace(PTRACE_PEEKDATA, pid, pos, datapos);
	    if (errno != 0)
		perror("ptrace(PTRACE_PEEKDATA)");
	}

	/*fprintf(stderr, "done.\n"); */
	vma->have_data = 1;
    } else {
	vma->data = NULL;
    }

    return 1;
}

void fetch_chunks_vma(pid_t pid, int flags, struct list *l, long *heap_start)
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
		    heap_start)) {
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
