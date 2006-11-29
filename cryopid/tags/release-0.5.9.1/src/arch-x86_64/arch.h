#ifndef _ARCH_H_
#define _ARCH_H_

#include <sys/syscall.h>
#include <unistd.h>

/* Used to poison memory that shouldn't be used. */
#define ARCH_POISON		0xdeadbeef04c0ffee

#define _ARCH_NSIG       64
#define _ARCH_NSIG_BPW   64
#define _ARCH_NSIG_WORDS (_ARCH_NSIG / _ARCH_NSIG_BPW)

typedef struct { 
	unsigned long sig[_ARCH_NSIG_WORDS];
} arch_sigset_t;

struct k_sigaction {
    __sighandler_t sa_hand;
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    arch_sigset_t sa_mask;
};

static inline int rt_sigaction(int sig, const struct k_sigaction* ksa,
	struct k_sigaction* oksa, size_t sigsetsize) {
	return syscall(__NR_rt_sigaction, sig, ksa, oksa, sigsetsize);
}

extern int r_arch_prctl(pid_t pid, int code, unsigned long addr);

extern unsigned long get_task_size();

#define cp_sigaction rt_sigaction

#endif /* _ARCH_H_ */
