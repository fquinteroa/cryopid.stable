#ifndef _ARCH_H_
#define _ARCH_H_

/* Used to poison memory that shouldn't be used. */
#define ARCH_POISON		0xdeadbeef

#define PAGE_SIZE	4096

#define GB		(1024*1024*1024)

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
	register unsigned long r0 asm ("r0") = (unsigned long)__NR_rt_sigaction;
	register unsigned long r3 asm ("r3") = (unsigned long)sig;
	register unsigned long r4 asm ("r4") = (unsigned long)ksa;
	register unsigned long r5 asm ("r5") = (unsigned long)oksa;
	register unsigned long r6 asm ("r6") = (unsigned long)sigsetsize;
	int ret, err;
	asm volatile (
		"sc\n"
		"mfcr %0"
		: "=&r"(r0), "=&r"(r3), "=&r"(r4), "=&r"(r5), "=&r"(r6)
		: "0"(r0), "1"(r3), "2"(r4), "3"(r5), "4"(r6)
		: "cr0", "ctr", "memory", "r9", "r10", "r11", "r12"
	);
	ret = r3;
	err = r0;
	if (err & 0x10000000)
		return -ret;
	return ret;
}

static inline unsigned long get_task_size()
{
    int stack_var;
    return (unsigned long)((((unsigned long)&stack_var + GB)/GB)*GB);
}

#define cp_sigaction rt_sigaction

#define __NR_sys_clone __NR_clone
static inline _syscall2(int, sys_clone, int, flags, void*, child_stack);

struct user {
	union {
		unsigned char raw[PT_FPSCR*4];
		struct pt_regs regs;
	};
};

#endif /* _ARCH_H_ */
