#ifndef _ARCH_H_
#define _ARCH_H_

/* Used to poison memory that shouldn't be used. */
#define ARCH_POISON		0xdeadbeef

#define _ARCH_NSIG       64
#define _ARCH_NSIG_BPW   32
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

struct cp_sparc_window_regs {
    unsigned long r_l0, r_l1, r_l2, r_l3, r_l4, r_l5, r_l6, r_l7;
    unsigned long r_i0, r_i1, r_i2, r_i3, r_i4, r_i5, r_i6, r_i7;
};

static inline _syscall4(int, rt_sigaction, int, sig, const struct k_sigaction*, ksa,
	struct k_sigaction*, oksa, size_t, sigsetsize);

static inline unsigned long get_task_size() { return 0xf0000000; }

#define __NR_rt_sigaction_sparc __NR_rt_sigaction
static inline _syscall5(int, rt_sigaction_sparc, int, sig,
    const struct k_sigaction*, ksa, struct k_sigaction*, oksa,
    void*, restorer, size_t, masksz);
static inline int cp_sigaction(int sig, const struct k_sigaction* ksa,
		struct k_sigaction* oksa, size_t masksz)
{
    return rt_sigaction_sparc(sig, ksa, oksa, NULL, masksz);
}

#define HIB(x) (((x) >> 10) & 0x003fffff)
#define LOB(x) ((x) & 0x3ff)

#define ptrace __ptrace

#endif /* _ARCH_H_ */
