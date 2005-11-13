#include <linux/unistd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <asm/reg.h>
#include <asm/page.h>

#include "cpimage.h"
#include "cryopid.h"

static void load_chunk_regs(struct user *user, int stopped)
{
    char *cp, *code = (char*)TRAMPOLINE_ADDR;

    /* Create region for mini-resumer process. */
    syscall_check(
	(long)mmap((void*)TRAMPOLINE_ADDR, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0), 0, "mmap");

    cp = code;

    /* put return dest onto stack too */
    //r->r_o6-=8;
    //*(long*)r->r_o6 = r->r_pc;

    code[0xffc] = 'A';
    /* set up a temporary stack for use */
    *cp++=0x48; *cp++=0xc7; *cp++=0xc4;
    *(int*)(cp) = ((long)code&0xffffffff)+0x0ff0; cp+=4; /* mov 0x11000, %rsp */

    /* munmap our custom malloc space */
    *cp++=0x48; *cp++=0xc7; *cp++=0xc0;
    *(int*)(cp) = __NR_munmap; cp+=4; /* mov foo, %rax */
    *cp++=0x48; *cp++=0xbf;
    *(long*)(cp) = MALLOC_START; cp+=8; /* mov foo, %rdi  */
    *cp++=0x48; *cp++=0xbe;
    *(long*)(cp) = MALLOC_END-MALLOC_START; cp+=8; /* mov foo, %rsi  */
    *cp++=0x0f;*cp++=0x05; /* syscall */

    /* munmap resumer code except for us */
    *cp++=0x48; *cp++=0xc7; *cp++=0xc0;
    *(int*)(cp) = __NR_munmap; cp+=4; /* mov foo, %rax  */
    *cp++=0x48; *cp++=0xbf;
    *(long*)(cp) = RESUMER_START; cp+=8; /* mov foo, %rdi  */
    *cp++=0x48; *cp++=0xbe;
    *(long*)(cp) = RESUMER_END-RESUMER_START; cp+=8; /* mov foo, %rsi  */
    *cp++=0x0f;*cp++=0x05; /* syscall */

    /* raise a SIGSTOP if we were stopped */
    if (stopped) {
	*cp++=0x48; *cp++=0xc7; *cp++=0xc0;
	*(int*)(cp) = __NR_kill; cp+=4;     /* mov $37, %eax (kill)    */
	*cp++=0x48; *cp++=0x31; *cp++=0xff; /* xor %rdi, %rdi          */
	*cp++=0x48; *cp++=0xc7; *cp++=0xc6;
	*(int*)(cp) = SIGSTOP; cp+=4;       /* mov $19, %rsi (SIGSTOP) */
	*cp++=0x0f;*cp++=0x05;              /* syscall                 */
    }

    /* restore registers */
    /*
    *cp++=0x49; *cp++=0xbf; *(long*)(cp) = r->r15; cp+=8;
    *cp++=0x49; *cp++=0xbe; *(long*)(cp) = r->r14; cp+=8;
    *cp++=0x49; *cp++=0xbd; *(long*)(cp) = r->r13; cp+=8;
    *cp++=0x49; *cp++=0xbc; *(long*)(cp) = r->r12; cp+=8;
    *cp++=0x48; *cp++=0xbd; *(long*)(cp) = r->rbp; cp+=8;
    *cp++=0x48; *cp++=0xbb; *(long*)(cp) = r->rbx; cp+=8;
    *cp++=0x49; *cp++=0xbb; *(long*)(cp) = r->r11; cp+=8;
    *cp++=0x49; *cp++=0xba; *(long*)(cp) = r->r10; cp+=8;
    *cp++=0x49; *cp++=0xb9; *(long*)(cp) = r->r9;  cp+=8;
    *cp++=0x49; *cp++=0xb8; *(long*)(cp) = r->r8;  cp+=8;
    *cp++=0x48; *cp++=0xb8; *(long*)(cp) = r->rax; cp+=8;
    *cp++=0x48; *cp++=0xb9; *(long*)(cp) = r->rcx; cp+=8;
    *cp++=0x48; *cp++=0xba; *(long*)(cp) = r->rdx; cp+=8;
    *cp++=0x48; *cp++=0xbe; *(long*)(cp) = r->rsi; cp+=8;
    *cp++=0x48; *cp++=0xbf; *(long*)(cp) = r->rdi; cp+=8;
    *cp++=0x48; *cp++=0xbc; *(long*)(cp) = r->rsp; cp+=8;
    */

    /* jump back to where we were. */
    *cp++=0xc3;
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
