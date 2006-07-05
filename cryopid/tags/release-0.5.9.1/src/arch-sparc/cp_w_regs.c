#include <bits/types.h>
#include <linux/user.h>
#include <linux/unistd.h>
#include <sys/ptrace.h>

#include "cpimage.h"
#include "cryopid.h"
#include "process.h"

unsigned long mysp;

void fetch_chunks_regs(pid_t pid, int flags, struct list *l, int stopped)
{
    struct cp_chunk *chunk = NULL;
    struct user *user_data;
    long pos;
    long* user_data_ptr;
    struct cp_sparc_window_regs *or = xmalloc(sizeof(struct cp_sparc_window_regs));

    user_data = xmalloc(sizeof(struct user));
    user_data_ptr = (long*)user_data;

    /* Get the user struct of the process */
    for(pos = 0; pos < sizeof(struct user)/sizeof(long); pos++) {
	user_data_ptr[pos] = ptrace(PTRACE_PEEKUSER, pid, (void*)(pos*sizeof(long)), 0);
	if (errno != 0) {
	    perror("ptrace(PTRACE_PEEKUSER): ");
	}
    }

    debug("SP is 0x%lx\n", user_data->regs.regs[13]);

    debug("PC: 0x%08lx nPC: 0x%08lx PSR: 0x%08lx Y: 0x%08lx",
	    user_data->regs.pc, user_data->regs.npc,
	    user_data->regs.psr, user_data->regs.y);
    debug("G:            0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx",
	    user_data->regs.regs[0], user_data->regs.regs[1],
	    user_data->regs.regs[2], user_data->regs.regs[3],
	    user_data->regs.regs[4], user_data->regs.regs[5],
	    user_data->regs.regs[6]);

    debug("O: 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx",
	    user_data->regs.regs[7], user_data->regs.regs[8],
	    user_data->regs.regs[9], user_data->regs.regs[10],
	    user_data->regs.regs[11], user_data->regs.regs[12],
	    user_data->regs.regs[13], user_data->regs.regs[14]);

    /* Get the other regs off the stack */
    memcpy_from_target(pid, or, mysp, sizeof(or));

    /* Restart a syscall on the other side */
    if (is_in_syscall(pid, user_data)) {
	fprintf(stderr, "[+] Process is probably in syscall. Returning EINTR.\n");
	set_syscall_return(user_data, -EINTR);
    }

    chunk = xmalloc(sizeof(struct cp_chunk));
    chunk->type = CP_CHUNK_REGS;
    chunk->regs.user_data = user_data;
    chunk->regs.opaque = or;
    chunk->regs.stopped = stopped;
    list_append(l, chunk);
}

void write_chunk_regs(void *fptr, struct cp_regs *data)
{
    write_bit(fptr, data->user_data, sizeof(struct user));
    write_bit(fptr, &data->stopped, sizeof(int));
    write_bit(fptr, data->opaque, sizeof(struct cp_sparc_window_regs));
}

/* vim:set ts=8 sw=4 noet: */
