#ifndef _ARCH_H_
#define _ARCH_H_

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
    arch_sigset_t sa_mask;
    void (*sa_restorer)(void);
};

enum {
	REG_V0  = 0, REG_R0 = 0,
	REG_T0  = 1,
	REG_T1  = 2,
	REG_T2  = 3,
	REG_T3  = 4,
	REG_T4  = 5,
	REG_T5  = 6,
	REG_T6  = 7,
	REG_T7  = 8,
	REG_S0  = 9,
	REG_S1  = 10,
	REG_S2  = 11,
	REG_S3  = 12,
	REG_S4  = 13,
	REG_S5  = 14,
	REG_S6  = 15, REG_FP = 15,
	REG_A0  = 16,
	REG_A1  = 17,
	REG_A2  = 18,
	REG_A3  = 19,
	REG_A4  = 20,
	REG_A5  = 21,
	REG_T8  = 22,
	REG_T9  = 23,
	REG_T10 = 24,
	REG_T11 = 25,
	REG_RA  = 26,
	REG_T12 = 27, REG_PV = 27,
	REG_AT  = 28,
	REG_GP  = 29,
	REG_SP  = 30,
	REG_ZERO= 31,
	REG_F0  = 32,
	REG_FPCR= 63,
	REG_PC  = 64
};

struct registers {
	unsigned long regs[65];
};

struct user {
	struct registers regs;
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

static inline _syscall4(int, rt_sigaction, int, sig, const struct k_sigaction*, ksa,
	struct k_sigaction*, oksa, size_t, sigsetsize);

static inline unsigned long get_task_size() { return 0x40000000000UL; }

#define cp_sigaction rt_sigaction

#endif /* _ARCH_H_ */
