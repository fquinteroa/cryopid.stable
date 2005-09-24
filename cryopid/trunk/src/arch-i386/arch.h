#ifndef _ARCH_H_
#define _ARCH_H_

#define _ARCH_NSIG       64
#define _ARCH_NSIG_BPW   32
#define _ARCH_NSIG_WORDS (_ARCH_NSIG / _ARCH_NSIG_BPW)

typedef struct { 
	unsigned long sig[_ARCH_NSIG_WORDS];
} arch_sigset_t;

static inline int rt_sigaction(int sig, const struct k_sigaction* ksa,
		const struct k_sigaction* oksa, size_t sigsetsize)
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
