#include <linux/types.h>
#include <linux/unistd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <linux/user.h>
#include <asm/reg.h>
#include <asm/page.h>

#include "cpimage.h"
#include "cryopid.h"

static void load_chunk_regs(struct user *user, struct cp_sparc_window_regs *or, int stopped)
{
    long *p = (long*)TRAMPOLINE_ADDR;
    char *code = (char*)TRAMPOLINE_ADDR;
    struct regs *r = (struct regs*)&user->regs;

    /* Create region for mini-resumer process. */
    syscall_check(
	(long)mmap((void*)TRAMPOLINE_ADDR, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0), 0, "mmap");

    /* Flush windows */
    *p++=0x91d02003;                                      /* t 0x03           */

    /* munmap our custom malloc space */
    *p++=0x82102000 | __NR_munmap;                        /* mov foo, %g1     */
    *p++=0x11000000 | HIB(MALLOC_START);                  /* sethi foo, %o0   */
    *p++=0x90122000 | LOB(MALLOC_START);                  /* or %o0, foo, %o0 */
    *p++=0x13000000 | HIB(MALLOC_END-MALLOC_START);       /* sethi foo, %o1   */
    *p++=0x92126000 | LOB(MALLOC_END-MALLOC_START);       /* or %o1, foo, %o1 */
    *p++=0x91d02010;                                      /* t 0x10           */

    /* munmap resumer code except for us */
    *p++=0x82102000 | __NR_munmap;                        /* mov foo, %g1     */
    *p++=0x11000000 | HIB(RESUMER_START);                 /* sethi foo, %o0   */
    *p++=0x90122000 | LOB(RESUMER_START);                 /* or %o0, foo, %o0 */
    *p++=0x13000000 | HIB(RESUMER_END-RESUMER_START);     /* sethi foo, %o1   */
    *p++=0x92126000 | LOB(RESUMER_END-RESUMER_START);     /* or %o1, foo, %o1 */
    *p++=0x91d02010;                                      /* t 0x10           */

    /* raise a SIGSTOP if we were stopped */
    if (0 && stopped) {
	*p++=0x82102000 | __NR_kill;                      /* mov foo, %g1     */
	*p++=0x11000000 | HIB(0);                         /* sethi foo, %o0   */
	*p++=0x90122000 | LOB(0);                         /* or %o0, foo, %o0 */
	*p++=0x13000000 | HIB(SIGSTOP);                   /* sethi foo, %o1   */
	*p++=0x92126000 | LOB(SIGSTOP);                   /* or %o1, foo, %o1 */
	*p++=0x91d02010;                                  /* t 0x10           */
    }

    /* restore registers */
    *p++=0x03000000 | HIB(r->r_g1); *p++=0x82106000 | LOB(r->r_g1);
    *p++=0x05000000 | HIB(r->r_g2); *p++=0x8410a000 | LOB(r->r_g2);
    *p++=0x07000000 | HIB(r->r_g3); *p++=0x8610e000 | LOB(r->r_g3);
    *p++=0x09000000 | HIB(r->r_g4); *p++=0x88112000 | LOB(r->r_g4);
    *p++=0x0b000000 | HIB(r->r_g5); *p++=0x8a116000 | LOB(r->r_g5);
    *p++=0x0d000000 | HIB(r->r_g6); *p++=0x8c11a000 | LOB(r->r_g6);
    *p++=0x0f000000 | HIB(r->r_g7); *p++=0x8e11e000 | LOB(r->r_g7);

    *p++=0x11000000 | HIB(r->r_o0); *p++=0x90122000 | LOB(r->r_o0);
    *p++=0x13000000 | HIB(r->r_o1); *p++=0x92126000 | LOB(r->r_o1);
    *p++=0x15000000 | HIB(r->r_o2); *p++=0x9412a000 | LOB(r->r_o2);
    *p++=0x17000000 | HIB(r->r_o3); *p++=0x9612e000 | LOB(r->r_o3);
    *p++=0x19000000 | HIB(r->r_o4); *p++=0x98132000 | LOB(r->r_o4);
    *p++=0x1b000000 | HIB(r->r_o5); *p++=0x9a136000 | LOB(r->r_o5);
    /* SP must be loaded atomically */
    *(long*)(code+0xff8) = r->r_o6;
    *p++=0xdc002ff8; /* ld [ 0xff8 ], %o6 */
    //*p++=0x1d000000 | HIB(r->r_o6); *p++=0x9c13a000 | LOB(r->r_o6);
    *(long*)(code+0xffc) = r->r_o7; /* used for the jmp. save him for later. */
    *p++=0x1f000000 | HIB(r->r_npc); *p++=0x9e13e000 | LOB(r->r_npc);

    *p++=0x21000000 | HIB(or->r_l0); *p++=0xa0142000 | LOB(or->r_l0);
    *p++=0x23000000 | HIB(or->r_l1); *p++=0xa2146000 | LOB(or->r_l1);
    *p++=0x25000000 | HIB(or->r_l2); *p++=0xa414a000 | LOB(or->r_l2);
    *p++=0x27000000 | HIB(or->r_l3); *p++=0xa614e000 | LOB(or->r_l3);
    *p++=0x29000000 | HIB(or->r_l4); *p++=0xa8152000 | LOB(or->r_l4);
    *p++=0x2b000000 | HIB(or->r_l5); *p++=0xaa156000 | LOB(or->r_l5);
    *p++=0x2d000000 | HIB(or->r_l6); *p++=0xac15a000 | LOB(or->r_l6);
    *p++=0x2f000000 | HIB(or->r_l7); *p++=0xae15e000 | LOB(or->r_l7);

    *p++=0x31000000 | HIB(or->r_i0); *p++=0xb0162000 | LOB(or->r_i0);
    *p++=0x33000000 | HIB(or->r_i1); *p++=0xb2166000 | LOB(or->r_i1);
    *p++=0x35000000 | HIB(or->r_i2); *p++=0xb416a000 | LOB(or->r_i2);
    *p++=0x37000000 | HIB(or->r_i3); *p++=0xb616e000 | LOB(or->r_i3);
    *p++=0x39000000 | HIB(or->r_i4); *p++=0xb8172000 | LOB(or->r_i4);
    *p++=0x3b000000 | HIB(or->r_i5); *p++=0xba176000 | LOB(or->r_i5);
    *p++=0x3d000000 | HIB(or->r_i6); *p++=0xbc17a000 | LOB(or->r_i6);
    *p++=0x3f000000 | HIB(or->r_i7); *p++=0xbe17e000 | LOB(or->r_i7);

    /* jump back to where we were. */
    *p++=0x81c3c000; /* jmp %o7, %g0 */
    *p++=0xde002ffc; /* ld [ 0xffc ], %o7 ... Fits neatly in the delay slot. */
}

void read_chunk_regs(void *fptr, int action)
{
    struct user user;
    struct cp_sparc_window_regs or;
    int stopped;
    read_bit(fptr, &user, sizeof(struct user));
    read_bit(fptr, &stopped, sizeof(int));
    read_bit(fptr, &or, sizeof(struct cp_sparc_window_regs));
    /*
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
    */
    if (action & ACTION_LOAD)
	load_chunk_regs(&user, &or, stopped);
}

/* vim:set ts=8 sw=4 noet: */
