#include <bits/types.h>
#include <linux/unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

#include <asm/atomic.h>
#include <asm/page.h>

#include "cryopid.h"
#include "cpimage.h"

void read_chunk_threads(void *fptr, int action)
{
    struct cp_threads t;
    read_bit(fptr, &t, sizeof(t));

    if (action & ACTION_PRINT)
	fprintf(stderr, "%d threads", t.num_threads);

    if (action & ACTION_LOAD) {
	/* Create memory for resumer trampolines */
	syscall_check(
	    (int)mmap((void*)TRAMPOLINES_START, PAGE_SIZE*(t.num_threads+2),
		      PROT_READ|PROT_WRITE|PROT_EXEC,
		      MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0), 0, "mmap");
	atomic_set(THREAD_COUNTER, t.num_threads);
    }
}

/* vim:set ts=8 sw=4 noet: */
