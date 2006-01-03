#include <bits/types.h>
#include <linux/unistd.h>
#include <sys/ptrace.h>
#include <asm/reg.h>

#include "cpimage.h"
#include "cryopid.h"
#include "process.h"

unsigned long mysp;

void fetch_chunks_regs(pid_t pid, int flags, struct list *l, int stopped)
{
    struct cp_chunk *chunk = NULL;
    struct regs *user_data;
    struct cp_sparc_window_regs *or = xmalloc(sizeof(struct cp_sparc_window_regs));

    user_data = xmalloc(sizeof(struct regs));

    /* Get the registers of the process */
    if (ptrace(PTRACE_GETREGS, pid, user_data, NULL) < 0) {
	perror("ptrace getregs");
	abort();
    }

    debug("SP is 0x%lx\n", user_data->r_o6);

    debug("PC: 0x%08lx nPC: 0x%08lx PSR: 0x%08lx Y: 0x%08lx",
	    user_data->r_pc,  user_data->r_npc,
	    user_data->r_psr, user_data->r_y);
    debug("G:            0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx",
	    user_data->r_g1, user_data->r_g2, user_data->r_g3, user_data->r_g4,
	    user_data->r_g5, user_data->r_g6, user_data->r_g7);

    debug("O: 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx",
	    user_data->r_o0, user_data->r_o1, user_data->r_o2, user_data->r_o3,
	    user_data->r_o4, user_data->r_o5, user_data->r_o6, user_data->r_o7);

    /* Get the other regs off the stack */
    memcpy_from_target(pid, or, user_data->r_o6, sizeof(*or));

    debug("L: 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx",
	    or->r_l0, or->r_l1, or->r_l2, or->r_l3,
	    or->r_l4, or->r_l5, or->r_l6, or->r_l7);

    debug("I: 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx",
	    or->r_i0, or->r_i1, or->r_i2, or->r_i3,
	    or->r_i4, or->r_i5, or->r_i6, or->r_i7);

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
    write_bit(fptr, data->user_data, sizeof(struct regs));
    write_bit(fptr, &data->stopped, sizeof(int));
    write_bit(fptr, data->opaque, sizeof(struct cp_sparc_window_regs));
}

/* vim:set ts=8 sw=4 noet: */
