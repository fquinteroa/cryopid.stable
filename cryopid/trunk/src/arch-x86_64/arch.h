#ifndef _ARCH_H_
#define _ARCH_H_

#define _ARCH_NSIG       64
#define _ARCH_NSIG_BPW   64
#define _ARCH_NSIG_WORDS (_ARCH_NSIG / _ARCH_NSIG_BPW)

typedef struct { 
	unsigned long sig[_ARCH_NSIG_WORDS];
} arch_sigset_t;

_syscall4(int, rt_sigaction, int, sig, const struct k_sigaction*, ksa, 
	const struct k_sigaction*, oksa, size_t, sigsetsize);

#endif /* _ARCH_H_ */
