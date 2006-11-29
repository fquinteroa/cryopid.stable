#ifndef _ARCH_H_
#define _ARCH_H_

#include <sys/syscall.h>
#include <unistd.h>

#include <asm/reg.h>

/* Used to poison memory that shouldn't be used. */
#define ARCH_POISON		0xdeadc0debeefee11UL

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

struct user {
	unsigned long	regs[EF_SIZE/8+32];	/* integer and fp regs */
	size_t		u_tsize;		/* text size (pages) */
	size_t		u_dsize;		/* data size (pages) */
	size_t		u_ssize;		/* stack size (pages) */
	unsigned long	start_code;		/* text starting address */
	unsigned long	start_data;		/* data starting address */
	unsigned long	start_stack;		/* stack starting address */
	long int	signal;			/* signal causing core dump */
	struct regs *	u_ar0;			/* help gdb find registers */
	unsigned long	magic;			/* identifies a core file */
	char		u_comm[32];		/* user command name */
};

static inline int rt_sigaction(int sig, const struct k_sigaction* ksa,
	struct k_sigaction* oksa, size_t sigsetsize) {
	return syscall(__NR_rt_sigaction, sig, ksa, oksa, sigsetsize);
}

static inline unsigned long get_task_size() { return 0x40000000000UL; }

#define cp_sigaction rt_sigaction

#endif /* _ARCH_H_ */
