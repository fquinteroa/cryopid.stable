#ifndef _ARCH_H_
#define _ARCH_H_

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

static inline _syscall4(int, rt_sigaction, int, sig, const struct k_sigaction*, ksa,
	struct k_sigaction*, oksa, size_t, sigsetsize);

#endif /* _ARCH_H_ */
