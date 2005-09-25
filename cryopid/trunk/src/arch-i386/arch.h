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

static inline int rt_sigaction(int sig, const struct k_sigaction* ksa,
		struct k_sigaction* oksa, size_t sigsetsize)
{
	int ret;
	asm (
		"mov %2,%%ebx\n"
		"int $0x80"
		: "=a"(ret)
		: "a"(__NR_rt_sigaction), "r"(sig),
		"c"(ksa), "d"(oksa), "S"(sigsetsize)
	);
	return ret;
}

#endif /* _ARCH_H_ */
