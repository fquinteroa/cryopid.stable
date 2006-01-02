#include <linux/unistd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <asm/reg.h>
#include <asm/page.h>

#include "cpimage.h"
#include "cryopid.h"

static void load_chunk_regs(struct user *user, int stopped)
{
    int *cp, *code = (int*)TRAMPOLINE_ADDR;
    long *data;

    /* Create region for mini-resumer process. */
    syscall_check(
	(long)mmap((void*)TRAMPOLINE_ADDR, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0), 0, "mmap");

    cp = code;
    data = (long*)(code + (PAGE_SIZE >> 4)); /* PAGE_SIZE/2 in longs */

    /* put return dest onto stack too */
    //r->r_o6-=8;
    //*(long*)r->r_o6 = r->r_pc;

    /* munmap our custom malloc space */
    *++data=__NR_munmap;             *cp++=0xa41f0000|(long)data; /* mov thing, $0 */
    *++data=MALLOC_START;            *cp++=0xa61f0000|(long)data; /* mov thing, $16 */
    *++data=MALLOC_END-MALLOC_START; *cp++=0xa63f0000|(long)data; /* mov thing, $17 */
    *cp++=0x83;

    /* munmap resumer code except for us */
    *++data=__NR_munmap;              *cp++=0xa41f0000|(long)data; /* mov thing, $0 */
    *++data=RESUMER_START;            *cp++=0xa61f0000|(long)data; /* mov thing, $16 */
    *++data=RESUMER_END-RESUMER_START;*cp++=0xa63f0000|(long)data; /* mov thing, $17 */
    *cp++=0x83;

    /* raise a SIGSTOP if we were stopped */
    if (stopped) {
	*++data=__NR_kill;    *cp++=0xa41f0000|(long)data; /* mov thing, $0 */
	*++data=0;            *cp++=0xa61f0000|(long)data; /* mov thing, $16 */
	*++data=SIGSTOP;      *cp++=0xa63f0000|(long)data; /* mov thing, $17 */
	*cp++=0x83;
    }

    /* restore registers */
    *++data=user->regs.regs[REG_V0]; *cp++=0xa41f0000|(long)data;
    *++data=user->regs.regs[REG_T0]; *cp++=0xa43f0000|(long)data;
    *++data=user->regs.regs[REG_T1]; *cp++=0xa45f0000|(long)data;
    *++data=user->regs.regs[REG_T2]; *cp++=0xa47f0000|(long)data;
    *++data=user->regs.regs[REG_T3]; *cp++=0xa49f0000|(long)data;
    *++data=user->regs.regs[REG_T4]; *cp++=0xa4bf0000|(long)data;
    *++data=user->regs.regs[REG_T5]; *cp++=0xa4df0000|(long)data;
    *++data=user->regs.regs[REG_T6]; *cp++=0xa4ff0000|(long)data;
    *++data=user->regs.regs[REG_T7]; *cp++=0xa51f0000|(long)data;
    *++data=user->regs.regs[REG_S0]; *cp++=0xa53f0000|(long)data;
    *++data=user->regs.regs[REG_S1]; *cp++=0xa55f0000|(long)data;
    *++data=user->regs.regs[REG_S2]; *cp++=0xa57f0000|(long)data;
    *++data=user->regs.regs[REG_S3]; *cp++=0xa59f0000|(long)data;
    *++data=user->regs.regs[REG_S4]; *cp++=0xa5bf0000|(long)data;
    *++data=user->regs.regs[REG_S5]; *cp++=0xa5df0000|(long)data;
    *++data=user->regs.regs[REG_S6]; *cp++=0xa5ff0000|(long)data;
    *++data=user->regs.regs[REG_A0]; *cp++=0xa61f0000|(long)data;
    *++data=user->regs.regs[REG_A1]; *cp++=0xa63f0000|(long)data;
    *++data=user->regs.regs[REG_A2]; *cp++=0xa65f0000|(long)data;
    *++data=user->regs.regs[REG_A3]; *cp++=0xa67f0000|(long)data;
    *++data=user->regs.regs[REG_A4]; *cp++=0xa69f0000|(long)data;
    *++data=user->regs.regs[REG_A5]; *cp++=0xa6bf0000|(long)data;
    *++data=user->regs.regs[REG_T8]; *cp++=0xa6df0000|(long)data;
    *++data=user->regs.regs[REG_T9]; *cp++=0xa6ff0000|(long)data;
    *++data=user->regs.regs[REG_T10];*cp++=0xa71f0000|(long)data;
    *++data=user->regs.regs[REG_T11];*cp++=0xa73f0000|(long)data;
    *++data=user->regs.regs[REG_RA]; *cp++=0xa75f0000|(long)data;
    *++data=user->regs.regs[REG_T12];*cp++=0xa77f0000|(long)data;
    *++data=user->regs.regs[REG_AT]; *cp++=0xa79f0000|(long)data;
    *++data=user->regs.regs[REG_GP]; *cp++=0xa7bf0000|(long)data;
    *++data=user->regs.regs[REG_SP]; *cp++=0xa7df0000|(long)data;

    /* jump back to where we were. */
    /* FIXME: We clobber T11 irrecovereably. Could cause apps to die */
    *++data=user->regs.regs[REG_PC];*cp++=0xa73f0000|(long)data;
    *cp++=0x6bf90000; /* jmp (t11) */
}

void read_chunk_regs(void *fptr, int action)
{
    struct user user;
    int stopped;
    read_bit(fptr, &user, sizeof(struct user));
    read_bit(fptr, &stopped, sizeof(int));
    /*
    if (action & ACTION_PRINT) {
	fprintf(stderr, "(registers): Process was %sstopped\n",
		stopped?"":"not ");
    }
    */
    if (action & ACTION_LOAD)
	load_chunk_regs(&user, stopped);
}

/* vim:set ts=8 sw=4 noet: */
