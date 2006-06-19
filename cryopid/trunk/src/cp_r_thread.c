#include <bits/types.h>
#include <linux/unistd.h>
#include <linux/user.h>
#include <errno.h>
#include <string.h>
#include <sched.h>

#include <asm/atomic.h>
#include <asm/ptrace.h>

#include "cryopid.h"
#include "cpimage.h"

#define THREAD_CLONE_FLAGS (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_DETACHED)

#if 1
#define __NR_xclone __NR_clone
static _syscall5(int, xclone, int, flags, void *, child_stack,
	int *, parent_tidptr, struct user_desc *, newtls,
	int *, child_tidptr);
#else
static int xclone(int flags, void *child_stack, int *parent_tidptr,
	struct user_desc *newtls, int *child_tidptr)
{
    struct pt_regs r;
    r.ebx = (long)flags;
    r.ecx = (long)child_stack;
    r.edx = (long)parent_tidptr;
    r.esi = (long)newtls;
    r.edi = (long)child_tidptr;
    return sys_clone(r);
}
#endif

void read_chunk_thread(void *fptr, int action)
{
    struct user_desc *ud;
    struct user *u;
    pid_t tid;

    read_bit(fptr, &tid, sizeof(tid));
    ud = read_chunk_tls_noload(fptr, action);
    u = read_chunk_regs_noload(fptr, action);

    if (action & ACTION_PRINT)
	fprintf(stderr, "tid %d ", tid);

    if (action & ACTION_LOAD) {
	extern void fork2_ready_pid(pid_t pid);
	int thread_index, wait_for;
	int p;

	thread_index = atomic_read(THREAD_COUNTER) - 1;
	wait_for     = thread_index - 1;

	//fork2_ready_pid(tid);
	p = xclone(THREAD_CLONE_FLAGS | CLONE_SETTLS,
		    (void*)(TRAMPOLINE_ADDR(thread_index+1)-8),
		    NULL, ud, NULL);
	
	switch (p) {
	    case -1:
		perror("clone");
		abort();
		break;
	    case 0:
		restore_registers_now(u, thread_index);
		break;
	    default:
		while (atomic_read(THREAD_COUNTER) > wait_for);
		break;
	}
    }
}

/* vim:set ts=8 sw=4 noet: */
