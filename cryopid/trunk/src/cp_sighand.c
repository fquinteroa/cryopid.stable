#include <linux/user.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

#include "cryopid.h"
#include "cpimage.h"

static int get_signal_handler(pid_t pid, int sig, struct k_sigaction *ksa) {
    struct user_regs_struct r;

    if (ptrace(PTRACE_GETREGS, pid, 0, &r) == -1)
	bail("ptrace(GETREGS)");

    r.eax = __NR_rt_sigaction;
    r.ebx = sig;
    r.ecx = 0;
    r.edx = scribble_zone+0x100;
    r.esi = sizeof(ksa->sa_mask);

    if (!do_syscall(pid, &r)) return 0;

    /* Error checking! */
    if (r.eax < 0)
	bail("rt_sigaction on target: %s", strerror(-r.eax));

    memcpy_from_target(pid, ksa, (void*)(scribble_zone+0x100), sizeof(struct k_sigaction));

    //printf("sigaction %d was 0x%lx mask 0x%x flags 0x%x restorer 0x%x\n", sig, ksa->sa_hand, ksa->sa_mask.sig[0], ksa->sa_flags, ksa->sa_restorer);

    return 1;
}

void read_chunk_sighand(void *fptr, struct cp_sighand *data, int load) {
    if (!load) {
	read_bit(fptr, &data->sig_num, sizeof(int));
	data->ksa = xmalloc(sizeof(struct k_sigaction));
	read_bit(fptr, data->ksa, sizeof(struct k_sigaction));
	return;
    }
    int sig_num;
    struct k_sigaction ksa;
    read_bit(fptr, &sig_num, sizeof(int));
    read_bit(fptr, &ksa, sizeof(struct k_sigaction));
    syscall_check(set_rt_sigaction(sig_num, &ksa, NULL), 0,
	    "set_rt_action(%d, ksa, NULL)", sig_num);
}

void write_chunk_sighand(void *fptr, struct cp_sighand *data) {
    write_bit(fptr, &data->sig_num, sizeof(int));
    write_bit(fptr, data->ksa, sizeof(struct k_sigaction));
}

void fetch_chunks_sighand(pid_t pid, int flags, struct list *l) {
    struct cp_chunk *chunk;
    struct k_sigaction *ksa = NULL;
    int i;
    for (i = 1; i < MAX_SIGS; i++) {
	if (i == SIGKILL || i == SIGSTOP)
	    continue;

	if (!ksa)
	    ksa = xmalloc(sizeof(struct k_sigaction));
	if (!get_signal_handler(pid, i, ksa))
	    continue;
	chunk = xmalloc(sizeof(struct cp_chunk));
	chunk->type = CP_CHUNK_SIGHAND;
	chunk->sighand.sig_num = i;
	chunk->sighand.ksa = ksa;
	ksa = NULL;
	list_add(l, chunk);
    }
}

/* vim:set ts=8 sw=4 noet: */
