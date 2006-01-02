#include <bits/types.h>
#include <linux/unistd.h>
#include <sys/ptrace.h>

#include "cpimage.h"
#include "cryopid.h"
#include "process.h"

void fetch_chunks_regs(pid_t pid, int flags, struct list *l, int stopped)
{
    struct cp_chunk *chunk = NULL;
    struct user *user_data;
    long pos;
    long* user_data_ptr;

    user_data = xmalloc(sizeof(struct user));
    user_data_ptr = (long*)user_data;

    /* Get the registers of the process */
    for(pos = 0; pos < sizeof(user_data->regs.regs)/sizeof(long); pos++) {
	user_data_ptr[pos] =
	    ptrace(PTRACE_PEEKUSER, pid, pos, NULL);
	if (errno != 0) {
	    perror("ptrace(PTRACE_PEEKUSER)");
	}
    }

#if 0
    for (pos = 0; pos < sizeof(user_data->regs.regs)/sizeof(user_data->regs.regs[0]);
	    pos++)
	printf("Reg %ld: 0x%lx\n", pos, user_data->regs.regs[pos]);
#endif

    /* Restart a syscall on the other side */
    if (is_in_syscall(pid, user_data)) {
	fprintf(stderr, "[+] Process is probably in syscall. Returning EINTR.\n");
	set_syscall_return(user_data, -EINTR);
    }

    chunk = xmalloc(sizeof(struct cp_chunk));
    chunk->type = CP_CHUNK_REGS;
    chunk->regs.user_data = user_data;
    chunk->regs.stopped = stopped;
    list_append(l, chunk);
}

void write_chunk_regs(void *fptr, struct cp_regs *data)
{
    write_bit(fptr, data->user_data, sizeof(struct user));
    write_bit(fptr, &data->stopped, sizeof(int));
}

/* vim:set ts=8 sw=4 noet: */
