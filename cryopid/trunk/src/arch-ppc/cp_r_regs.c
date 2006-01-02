#include <linux/user.h>
#include <linux/unistd.h>
#include <sys/mman.h>
#include <asm/page.h>

#include "cpimage.h"
#include "cryopid.h"

static void load_chunk_regs(struct user *user, int stopped)
{
    long *cp, *code = (long*)TRAMPOLINE_ADDR, *data;

    /* Create region for mini-resumer process. */
    syscall_check(
	(int)mmap((void*)TRAMPOLINE_ADDR, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0), 0, "mmap");

    cp = code;
    data = code + (PAGE_SIZE >> 3); /* PAGE_SIZE/2 in longs */

    /* munmap our custom malloc space */
    *++data=__NR_munmap;             *code++=0x80000000|(long)data;
    *++data=MALLOC_START;            *code++=0x80600000|(long)data;
    *++data=MALLOC_END-MALLOC_START; *code++=0x80800000|(long)data;
    *code++=0x44000002;

    /* restore registers */
    *++data=user->regs.gpr[ 1]; *code++=0x80200000|(long)data;
    *++data=user->regs.gpr[ 2]; *code++=0x80400000|(long)data;
    *++data=user->regs.gpr[ 5]; *code++=0x80a00000|(long)data;
    *++data=user->regs.gpr[ 6]; *code++=0x80c00000|(long)data;
    *++data=user->regs.gpr[ 7]; *code++=0x80e00000|(long)data;
    *++data=user->regs.gpr[ 8]; *code++=0x81000000|(long)data;
    *++data=user->regs.gpr[ 9]; *code++=0x81200000|(long)data;
    *++data=user->regs.gpr[10]; *code++=0x81400000|(long)data;
    *++data=user->regs.gpr[11]; *code++=0x81600000|(long)data;
    *++data=user->regs.gpr[12]; *code++=0x81800000|(long)data;
    *++data=user->regs.gpr[13]; *code++=0x81a00000|(long)data;
    *++data=user->regs.gpr[14]; *code++=0x81c00000|(long)data;
    *++data=user->regs.gpr[15]; *code++=0x81e00000|(long)data;
    *++data=user->regs.gpr[16]; *code++=0x82000000|(long)data;
    *++data=user->regs.gpr[17]; *code++=0x82200000|(long)data;
    *++data=user->regs.gpr[18]; *code++=0x82400000|(long)data;
    *++data=user->regs.gpr[19]; *code++=0x82600000|(long)data;
    *++data=user->regs.gpr[20]; *code++=0x82800000|(long)data;
    *++data=user->regs.gpr[21]; *code++=0x82a00000|(long)data;
    *++data=user->regs.gpr[22]; *code++=0x82c00000|(long)data;
    *++data=user->regs.gpr[23]; *code++=0x82e00000|(long)data;
    *++data=user->regs.gpr[24]; *code++=0x83000000|(long)data;
    *++data=user->regs.gpr[25]; *code++=0x83200000|(long)data;
    *++data=user->regs.gpr[26]; *code++=0x83400000|(long)data;
    *++data=user->regs.gpr[27]; *code++=0x83600000|(long)data;
    *++data=user->regs.gpr[28]; *code++=0x83800000|(long)data;
    *++data=user->regs.gpr[29]; *code++=0x83a00000|(long)data;
    *++data=user->regs.gpr[30]; *code++=0x83c00000|(long)data;

    /* raise a SIGSTOP if we were stopped */
    if (stopped) {
	*++data=__NR_kill;             *code++=0x80000000|(long)data;
	*++data=0;                     *code++=0x80600000|(long)data;
	*++data=SIGSTOP;               *code++=0x80800000|(long)data;
	*code++=0x44000002;
    }

    /* raise a SIGWINCH */
    *++data=__NR_kill;             *code++=0x80000000|(long)data;
    *++data=0;                     *code++=0x80600000|(long)data;
    *++data=SIGWINCH;              *code++=0x80800000|(long)data;
    *code++=0x44000002;

    /* and the rest of the registers we might have just modified */
    /* FIXME: can we guarantee our syscall didn't touch anything else? */
    *++data=user->regs.gpr[ 0]; *code++=0x80000000|(long)data;
    *++data=user->regs.gpr[ 3]; *code++=0x80600000|(long)data;
    *++data=user->regs.gpr[ 4]; *code++=0x80800000|(long)data;

    /* Restore the special purpose registers that we can, via r31 */
    *++data=user->regs.ctr;  *code++=0x83e00000|(long)data; *code++=0x7fe903a6;
    *++data=user->regs.link; *code++=0x83e00000|(long)data; *code++=0x7fe803a6;
    *++data=user->regs.xer;  *code++=0x83e00000|(long)data; *code++=0x7fe103a6;
#if 0 /* "(not used at present)" */
    *++data=user->regs.mq;   *code++=0x83e00000|(long)data; *code++=0x7fe003a6;
#endif

    /* And restore r31 */
    *++data=user->regs.gpr[31]; *code++=0x83e00000|(long)data;

    /* We can use a direct jump back if our address is within 26-bits of 0. */
    if (user->regs.nip < 0x02000000 || user->regs.nip > 0xfe000000) {
	*code++=0x48000002|(user->regs.nip);
    } else {
	/* Otherwise, we're forced to clobber a register */
	fprintf(stderr,
		"Forced to clobber counter register. "
		"Resumed process may be inconsistent.\n");
	*++data=user->regs.nip; *code++=0x83e00000|(long)data; *code++=0x7fe903a6;
	*code++=0x4e800420; /* bctr */
    }

//     /* jump back to where we were. */
//     *cp++=0xea;
//     *(unsigned long*)(cp) = r->eip; cp+= 4;
//     asm("mov %%cs,%w0": "=q"(r->cs)); /* ensure we use the right CS for the current kernel */
//     *(unsigned short*)(cp) = r->cs; cp+= 2; /* jmp cs:foo */
//     syscall_check(
// 	(int)mprotect((void*)TRAMPOLINE_ADDR, PAGE_SIZE, PROT_READ|PROT_EXEC),
// 	    0, "mmap");
}

void read_chunk_regs(void *fptr, int action)
{
     struct user user;
     int stopped;
     read_bit(fptr, &user, sizeof(struct user));
     read_bit(fptr, &stopped, sizeof(int));
#if 0
     if (action & ACTION_PRINT) {
 	fprintf(stderr, "(registers): Process was %sstopped\n",
 		stopped?"":"not ");
 	fprintf(stderr, "\teax: 0x%08lx ebx: 0x%08lx ecx: 0x%08lx edx: 0x%08lx\n",
 		user.regs.eax, user.regs.ebx, user.regs.ecx, user.regs.edx);
 	fprintf(stderr, "\tesi: 0x%08lx edi: 0x%08lx ebp: 0x%08lx esp: 0x%08lx\n",
 		user.regs.esi, user.regs.edi, user.regs.ebp, user.regs.esp);
 	fprintf(stderr, "\t ds: 0x%08x  es: 0x%08x  fs: 0x%08x  gs: 0x%08x\n",
 		user.regs.ds, user.regs.es, user.regs.fs, user.regs.gs);
 	fprintf(stderr, "\teip: 0x%08lx eflags: 0x%08lx",
 		user.regs.eip, user.regs.eflags);
     }
#endif
     if (action & ACTION_LOAD)
 	load_chunk_regs(&user, stopped);
}

/* vim:set ts=8 sw=4 noet: */
