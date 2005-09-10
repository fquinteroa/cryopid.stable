#include <linux/user.h>
#include <linux/unistd.h>
#include <signal.h>
#include <asm/ldt.h>
#include <asm/ucontext.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <string.h>
#include <errno.h>

#include "cpimage.h"
#include "cryopid.h"

int emulate_tls = 0;

static int tls_base_address;
static void (*old_segvhandler)(int, siginfo_t*, void*);
#if !set_thread_area
extern int set_thread_area(struct user_desc *u_info);
#endif

void read_chunk_tls(void *fptr, int action)
{
    struct user_desc u;
    int ret;

    read_bit(fptr, &u, sizeof(struct user_desc));

    if (!u.base_addr)
	return;

    if (action & ACTION_PRINT)
	fprintf(stderr, "TLS entry (%d): base_addr = 0x%lx", 
		u.entry_number, u.base_addr);

    if (!(action & ACTION_LOAD))
	return;

    if (!emulate_tls) {
	ret = set_thread_area(NULL);
	if (ret == -1) /* some libcs return the actual errno instead of -1 */
	    ret = -errno;
	if (ret == -ENOSYS) {
	    /* We are not a TLS capable system. Turn on TLS emulation voodoo. */
	    emulate_tls = 1;

	    /* We'll need write access to the code segments to do this. */
	    extra_prot_flags |= PROT_WRITE;
	}
    }

    if (emulate_tls)
	tls_base_address = u.base_addr;
    else
	syscall_check(set_thread_area(&u), 0, "set_thread_area");
}

static void tls_segv_handler(int sig, siginfo_t *si, void *ucontext)
{
    static int rewrite_stage = 0;
    static unsigned char* rewrite_start = NULL;
    static unsigned char rewrite_backup[12];

    struct ucontext *uc = (struct ucontext*)ucontext;
    unsigned char *pt = (unsigned char*)uc->uc_mcontext.eip;

    fprintf(stderr, "Rewrite stage: %d\n", rewrite_stage);
    fflush(stderr);

    if (rewrite_stage == 1) {
	pt = rewrite_start;
	pt[0] = 0xa3;
	*(long*)(pt+1) = 0x00000000;
	pt[5] = 0x90;
	pt[6] = 0xeb;
	pt[7] = 0xf8;
	rewrite_stage++;
	return;
    } else if (rewrite_stage == 2) {
	*(long*)pt = 0x90909090;
	pt[4] = 0xa3;
	*(long*)(pt+5) = 0x00000000;
	rewrite_stage++;
	return;
    } else if (rewrite_stage == 3) {
	memcpy(rewrite_start, rewrite_backup, sizeof(rewrite_backup));
	rewrite_stage = 0;
	return;
    }
    if (!memcmp(pt, "\x65\x83\x3d", 3)) {
	/*
	 *  8048344:   65 83 3d 0c 00 00 00    cmpl   $0x0,%gs:0xc
	 *  804834b:   00 
	 *  804834c:   83 3d af be ad de 00    cmpl   $0x0,0xdeadbeaf
	 */
	pt[0] = 0x83;
	pt[1] = 0x3d;
	*(long*)(pt+2) = tls_base_address+*(char*)(pt+3);
	pt[6] = pt[7];
	pt[7] = 0x90;
	return;
    }
    if (!memcmp(pt, "\x65\x8b", 2) && (
	    pt[2] == 0x0d || /* ecx */
	    pt[2] == 0x35 || /* esi */
	    pt[2] == 0x15 || /* edx */
	    pt[2] == 0x2d || /* ebp */
	    pt[2] == 0x3d || /* edi */
	    0)) {
	/*
	 *  8048353:   65 8b 0d 00 00 00 00    mov    %gs:0x0,%ecx
	 *  804835a:   8b 0d af be ad de       mov    0xdeadbeaf,%ecx
	 */
	pt[0] = 0x8b;
	pt[1] = pt[2];
	*(long*)(pt+2) = tls_base_address+*(long*)(pt+3);
	pt[6] = 0x90;
	return;
    }
    if (!memcmp(pt, "\x65\x89\x3d", 3)) { /* XXX untested */
	/*
	 * 80483ab:   65 89 3d 50 00 00 00    mov    %edi,%gs:0x50
	 * 80483b2:   89 3d ef be ad de       mov    %edi,0xdeadbeef
	 */
	pt[0] = 0x89;
	pt[1] = 0x3d;
	*(long*)(pt+2) = tls_base_address+*(long*)(pt+3);
	pt[6] = 0x90;
	return;
    }
    if (!memcmp(pt, "\x65\xc7\x05", 3)) { /* XXX untested */
	/*
	 *  8048344:   65 c7 05 f0 01 00 00    movl   $0xffffffff,%gs:0x1f0
	 *  804834b:   ff ff ff ff
	 *  804834f:   c7 05 ef be ad de ff    movl   $0xfffffff,0xdeadbeef
	 *  8048356:   ff ff 0f
	 */
	pt[0] = pt[1];
	pt[1] = pt[2];
	*(long*)(pt+2) = tls_base_address+*(long*)(pt+3);
	*(long*)(pt+6) = *(long*)(pt+7);
	pt[10] = 0x90;
	return;
    }
    if (!memcmp(pt, "\xf0\x65\x0f\xb1\x0d", 5)) { /* XXX untested */
	/*
	 * 8048359:   f0 65 0f b1 0d 54 00    lock cmpxchg %ecx,%gs:0x54
	 * 8048360:   00 00
	 * 8048362:   f0 0f b1 0d ef be ad    lock cmpxchg %ecx,0xdeadbeef
	 * 8048369:   de
	 */
	pt[1] = 0x0f;
	pt[2] = pt[3];
	pt[3] = pt[4];
	*(long*)(pt+4) = tls_base_address+*(long*)(pt+5);
	pt[8] = 0x90;
	return;
    }
    if (!memcmp(pt, "\xf0\x65\x83\x0d", 4)) { /* XXX untested */
	/*
	 * 804836a:   f0 65 83 0d 54 00 00    lock orl $0x10,%gs:0x54
	 * 8048371:   00 10
	 * 8048373:   f0 83 0d ef be ad de    lock orl $0x10,0xdeadbeef
	 * 804837a:   10
	 */
	pt[1] = pt[2];
	pt[2] = pt[3];
	*(long*)(pt+3) = tls_base_address+*(long*)(pt+4);
	pt[7] = pt[8];
	pt[8] = 0x90;
	return;
    }
    if (pt[0] == 0x65 && (
		pt[1] == 0xa1 || /* mov    %gs:0x0,%eax  */
		pt[1] == 0xa3    /* mov    %eax,%gs:0x48 */
		)) {
	/*
	 * 804838c:   65 a1 00 00 00 00       mov    %gs:0x0,%eax
	 * 8048392:   a1 ef be ad de          mov    0xdeadbeef,%eax
	 *
	 * 80483c8:   65 a3 48 00 00 00       mov    %eax,%gs:0x48
	 * 80483ce:   a3 ef be ad de          mov    %eax,0xdeadbeef
	 */
	pt[0] = pt[1];
	*(long*)(pt+1) = tls_base_address+*(long*)(pt+2);
	pt[5] = 0x90;
	return;
    }
    if (!memcmp(pt, "\x65\x89\x51", 3)) {
	/*
	 * 80483b1:   65 89 51 00             mov    %edx,%gs:0x0(%ecx)
	 * 80483b5:   89 91 af be ad de       mov    %edx,0xdeadbeaf(%ecx)
	 *
	 * WARNING: XXX VOODOO HAPPENS HERE
	 */
	memcpy(rewrite_backup, pt, sizeof(rewrite_backup));
	pt[0] = 0x89;
	pt[1] = 0x91;
	*(long*)(pt+2) = tls_base_address+*(char*)(pt+3);
	pt[6] = 0xa3;
	*(long*)(pt+7) = 0x00000000; /* cause another segfault */
	rewrite_stage = 1;
	rewrite_start = pt;
	return;
    }
    if (old_segvhandler &&
	    old_segvhandler != (void*)SIG_IGN && old_segvhandler != (void*)SIG_DFL)
	old_segvhandler(sig, si, ucontext);
    printf("Unhandled segfault at 0x%08lx!\n", uc->uc_mcontext.eip);
    raise(SIGSEGV);
}

void install_tls_segv_handler()
{
    struct k_sigaction sa;
    struct k_sigaction old_sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_hand = (__sighandler_t)tls_segv_handler;
    sa.sa_flags = SA_SIGINFO;

    syscall_check(set_rt_sigaction(SIGSEGV, &sa, &old_sa), 0, "set_rt_sigaction");
}

/* vim:set ts=8 sw=4 noet: */
