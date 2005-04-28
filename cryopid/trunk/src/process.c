/*
 * Process state saver
 *   (C) 2004 Bernard Blackham <bernard@blackham.com.au>
 *
 * Licensed under a BSD-ish license.
 */

/* large file support */
//#define _FILE_OFFSET_BITS 64

#include <malloc.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/user.h>
#include <linux/kdev_t.h>
#include <asm/ldt.h>
#include <asm/unistd.h>
#include <asm/ptrace.h>
#include <assert.h>
#include <asm/termios.h>

#include "cryopid.h"
#include "cpimage.h"
#include "list.h"

char* backup_page(pid_t target, void* addr)
{
    long* page = xmalloc(PAGE_SIZE);
    int i;
    long ret;
    for(i = 0; i < PAGE_SIZE/sizeof(long); i++) {
	ret = ptrace(PTRACE_PEEKTEXT, target, (void*)((long)addr+(i*sizeof(long))), 0);
	if (errno) {
	    perror("ptrace(PTRACE_PEEKTEXT)");
	    free(page);
	    return NULL;
	}
	page[i] = ret;
	if (ptrace(PTRACE_POKETEXT, target, (void*)((long)addr+(i*sizeof(long))), 0xdeadbeef) == -1) {
	    perror("ptrace(PTRACE_POKETEXT)");
	    free(page);
	    return NULL;
	}
    }

    return (char*)page;
}

int restore_page(pid_t target, void* addr, char* page)
{
    long *p = (long*)page;
    int i;
    assert(page);
    for (i = 0; i < PAGE_SIZE/sizeof(long); i++) {
	if (ptrace(PTRACE_POKETEXT, target, (void*)((long)addr+(i*sizeof(long))), p[i]) == -1) {
	    perror("ptrace(PTRACE_POKETEXT)");
	    free(page);
	    return 0;
	}
    }
    free(page);
    return 1;
}

int memcpy_into_target(pid_t pid, void* dest, const void* src, size_t n)
{
    /* just like memcpy, but copies it into the space of the target pid */
    /* n must be a multiple of 4, or will otherwise be rounded down to be so */
    int i;
    long *d, *s;
    d = (long*) dest;
    s = (long*) src;
    for (i = 0; i < n / sizeof(long); i++) {
	if (ptrace(PTRACE_POKETEXT, pid, d+i, s[i]) == -1) {
	    perror("ptrace(PTRACE_POKETEXT)");
	    return 0;
	}
    }
    return 1;
}

int memcpy_from_target(pid_t pid, void* dest, const void* src, size_t n)
{
    /* just like memcpy, but copies it from the space of the target pid */
    /* n must be a multiple of 4, or will otherwise be rounded down to be so */
    int i;
    long *d, *s;
    d = (long*) dest;
    s = (long*) src;
    n /= sizeof(long);
    for (i = 0; i < n; i++) {
	d[i] = ptrace(PTRACE_PEEKTEXT, pid, s+i, 0);
	if (errno) {
	    perror("ptrace(PTRACE_PEEKTEXT)");
	    return 0;
	}
    }
    return 1;
}

int save_registers(pid_t pid, struct user_regs_struct *r)
{
    if (ptrace(PTRACE_GETREGS, pid, NULL, r) < 0) {
	perror("ptrace getregs");
	return errno;
    }
    return 0;
}

int restore_registers(pid_t pid, struct user_regs_struct *r)
{
    if (ptrace(PTRACE_SETREGS, pid, NULL, r) < 0) {
	perror("ptrace setregs");
	return errno;
    }
    return 0;
}

int do_syscall(pid_t pid, struct user_regs_struct *regs)
{
    long loc;
    struct user_regs_struct orig_regs;
    long old_insn;
    int status, ret;

    if (save_registers(pid, &orig_regs) < 0)
	return -EACCES;

    loc = scribble_zone+0x10;

    old_insn = ptrace(PTRACE_PEEKTEXT, pid, loc, 0);
    if (errno) {
	perror("ptrace peektext");
	return -EACCES;
    }
    //printf("original instruction at 0x%lx was 0x%lx\n", loc, old_insn);

    if (ptrace(PTRACE_POKETEXT, pid, loc, 0x80cd) < 0) {
	perror("ptrace poketext");
	return -EACCES;
    }

    /* Set up registers for ptrace syscall */
    regs->eip = loc;
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
	perror("ptrace setregs");
	return -EACCES;
    }

    /* Execute call */
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
	perror("ptrace singlestep");
	return -EACCES;
    }
    ret = waitpid(pid, &status, 0);
    if (ret == -1) {
	perror("Failed to wait for child");
	exit(1);
    }

    /* Get our new registers */
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
	perror("ptrace getregs");
	return -EACCES;
    }

    /* Return everything back to normal */
    if (restore_registers(pid, &orig_regs) < 0) {
	perror("ptrace getregs");
	return -EACCES;
    }

    if (ptrace(PTRACE_POKETEXT, pid, loc, old_insn) < 0) {
	perror("ptrace poketext");
	return -EACCES;
    }

    return 1;
}

int is_in_syscall(pid_t pid, void* eip)
{
    long inst;
    inst = ptrace(PTRACE_PEEKDATA, pid, eip-2, 0);
    if (errno) {
	perror("ptrace(PEEKDATA)");
	return 0;
    }
    return (inst&0xffff) == 0x80cd;
}

static int process_is_stopped(pid_t pid)
{
    char buf[30];
    char mode;
    FILE *f;
    snprintf(buf, 30, "/proc/%d/stat", pid);
    f = fopen(buf, "r");
    if (f == NULL) return -1;
    fscanf(f, "%*s %*s %c", &mode);
    fclose(f);
    return mode == 'T';
}

static void start_ptrace(pid_t pid)
{
    long ret;
    int status;
    int stopped;

    stopped = process_is_stopped(pid);

    ret = ptrace(PTRACE_ATTACH, pid, 0, 0);
    if (ret == -1) {
	perror("Failed to ptrace");
	exit(1);
    }

    if (stopped)
	return; /* don't bother waiting for it, we'll just hang */

    ret = waitpid(pid, &status, 0);
    if (ret == -1) {
	perror("Failed to wait for child");
	exit(1);
    }
    if (!WIFSTOPPED(status)) {
	fprintf(stderr, "Failed to get child stopped.\n");
    }
}

static void end_ptrace(pid_t pid)
{
    long ret;

    ret = ptrace(PTRACE_DETACH, pid, 0, 0);
    if (ret == -1) {
	perror("Failed to detach");
	exit(1);
    }
}

void get_process(pid_t pid, int flags, struct list *process_image, long *heap_start)
{
    int success = 0;
    char* pagebackup;
    struct user_regs_struct r;

    start_ptrace(pid);

    if (save_registers(pid, &r) < 0) {
	fprintf(stderr, "Unable to save process's registers!\n");
	goto out_ptrace;
    }

    /* The order below is very important. Do not change without good reason and
     * careful thought.
     */
    fetch_chunks_tls(pid, flags, process_image);

    /* this gives us a scribble zone: */
    fetch_chunks_vma(pid, flags, process_image, heap_start);

    if (!scribble_zone) {
	fprintf(stderr, "[-] No suitable scribble zone could be found. Aborting.\n");
	goto out_ptrace;
    }
    pagebackup = backup_page(pid, (void*)scribble_zone);

    fetch_chunks_fd(pid, flags, process_image);

    fetch_chunks_sighand(pid, flags, process_image);
    fetch_chunks_regs(pid, flags, process_image);

    success = 1;

    restore_page(pid, (void*)scribble_zone, pagebackup);
    restore_registers(pid, &r);
out_ptrace:
    end_ptrace(pid);
    
    if (!success)
	abort();
}

/* vim:set ts=8 sw=4 noet: */
