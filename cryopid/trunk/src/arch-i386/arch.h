#ifndef _ARCH_H_
#define _ARCH_H_

#define _ARCH_NSIG       64
#define _ARCH_NSIG_BPW   32
#define _ARCH_NSIG_WORDS (_ARCH_NSIG / _ARCH_NSIG_BPW)

typedef struct { 
	unsigned long sig[_ARCH_NSIG_WORDS];
} arch_sigset_t;


#endif /* _ARCH_H_ */
