#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <assert.h>
#include <netinet/tcp.h>
#include <linux/net.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <asm/page.h>
#include <asm/reg.h>

#include "cryopid.h"
#include "cpimage.h"
#include "list.h"

struct registers {
    unsigned long regs[EF_SIZE/8+32];
};

static int process_was_stopped = 0;

char* backup_page(pid_t target, void* addr)
{
    long* page = xmalloc(PAGE_SIZE);
    int i;
    long ret;
    for(i = 0; i < PAGE_SIZE/sizeof(long); i++) {
	errno = 0;
	ret = ptrace(PTRACE_PEEKTEXT, target, (void*)((long)addr+(i*sizeof(long))), 0);
	if (errno) {
	    perror("ptrace(PTRACE_PEEKTEXT)");
	    free(page);
	    return NULL;
	}
	page[i] = ret;
	if (ptrace(PTRACE_POKETEXT, target, (void*)((long)addr+(i*sizeof(long))), ARCH_POISON) == -1) {
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
	errno = 0;
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
    /* n must be a multiple of word size, or will otherwise be rounded down to
     * be so */
    int i;
    long *d, *s;
    d = (long*) dest;
    s = (long*) src;
    n /= sizeof(long);
    for (i = 0; i < n; i++) {
	errno = 0;
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
    /* n must be a multiple of word size, or will otherwise be rounded down to
     * be so */
    int i;
    long *d, *s;
    d = (long*) dest;
    s = (long*) src;
    n /= sizeof(long);
    for (i = 0; i < n; i++) {
	errno = 0;
	d[i] = ptrace(PTRACE_PEEKTEXT, pid, s+i, 0);
	if (errno) {
	    printf("ptrace(PTRACE_PEEKTEXT, %d, 0x%lx): (%d) %m\n", pid, (long)(s+i), errno);
	    return 0;
	}
    }
    return 1;
}

static int save_registers(pid_t pid, struct registers *r)
{
    int i;
    long* l = r->regs;
    for (i = 0; i < sizeof(*r)/sizeof(long); i++) {
	errno = 0;
	l[i] = ptrace(PTRACE_PEEKUSER, pid, i, 0);
	printf("Reg %d: 0x%lx\n", i, l[i]);
	if (errno) {
	    perror("ptrace getregs");
	    return errno;
	}
    }
    return 0;
}

static int restore_registers(pid_t pid, struct registers *r)
{
    int i;
    long* l = (long*)r;
    for (i = 0; i < sizeof(*r)/sizeof(long); i++) {
	errno = 0;
	if (ptrace(PTRACE_POKEUSER, pid, i, l[i]) < 0) {
	    perror("ptrace setregs");
	    return errno;
	}
    }
    return 0;
}

int is_a_syscall(unsigned int inst, int canonical)
{
    if (inst == 0x00000083)
	return 1;
    return 0;
}

int is_in_syscall(pid_t pid, struct user *user)
{
    int inst;
    errno = 0;
    inst = ptrace(PTRACE_PEEKDATA, pid, user->regs[EF_PC], 0);
    if (errno) {
	perror("ptrace(PEEKDATA)");
	return 0;
    }
    return is_a_syscall(inst, 0);
}

void set_syscall_return(struct user* user, unsigned long val) {
    user->regs[EF_T8] = (val < 0);
    user->regs[EF_V0] = val;
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

    process_was_stopped = process_is_stopped(pid);

    ret = ptrace(PTRACE_ATTACH, pid, 0, 0);
    if (ret == -1) {
	perror("Failed to ptrace");
	exit(1);
    }

    if (process_was_stopped)
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

static void end_ptrace(pid_t pid, int flags)
{
    long ret;

    if (flags & FLAG_KILL_PROCESS) {
	ret = ptrace(PTRACE_KILL, pid, 0, 0);
	if (ret == -1)
	    perror("Failed to kill process.");
    } else {
	ret = ptrace(PTRACE_DETACH, pid, 0, 0);
	if (ret == -1)
	    perror("Failed to detach");
    }
}

void get_process(pid_t pid, int flags, struct list *process_image, long *bin_offset)
{
    int success = 0;
    char* pagebackup;
    struct registers r;

    start_ptrace(pid);

    if (save_registers(pid, &r) < 0) {
	fprintf(stderr, "Unable to save process's registers!\n");
	goto out_ptrace;
    }

    /* The order below is very important. Do not change without good reason and
     * careful thought.
     */

    /* this gives us a scribble zone: */
    fetch_chunks_vma(pid, flags, process_image, bin_offset);

    if (!scribble_zone) {
	fprintf(stderr, "[-] No suitable scribble zone could be found. Aborting.\n");
	goto out_ptrace;
    }
    pagebackup = backup_page(pid, (void*)scribble_zone);

    fetch_chunks_fd(pid, flags, process_image);

    fetch_chunks_sighand(pid, flags, process_image);
    fetch_chunks_regs(pid, flags, process_image, process_was_stopped);

    success = 1;

    restore_page(pid, (void*)scribble_zone, pagebackup);
    restore_registers(pid, &r);
out_ptrace:
    end_ptrace(pid, flags);
    
    if (!success)
	abort();
}

static inline unsigned long __remote_syscall(pid_t pid,
	int syscall_no, char *syscall_name,
	int use_o0, unsigned long o0,
	int use_o1, unsigned long o1,
	int use_o2, unsigned long o2,
	int use_o3, unsigned long o3,
	int use_o4 , unsigned long o4 )
{
#if 0
    struct registers orig_regs, regs;
    unsigned long ret;
    int status;

    if (!syscall_loc) {
	fprintf(stderr, "No syscall locations found! Cannot do remote syscall.\n");
	abort();
    }

    if (save_registers(pid, &orig_regs) < 0)
	abort();

    memcpy(&regs, &orig_regs, sizeof(regs));

    regs.u_regs[UREG_G1] = syscall_no;
    if (use_o0) regs.u_regs[UREG_I0] = o0;
    if (use_o1) regs.u_regs[UREG_I1] = o1;
    if (use_o2) regs.u_regs[UREG_I2] = o2;
    if (use_o3) regs.u_regs[UREG_I3] = o3;
    if (use_o4) regs.u_regs[UREG_I4] = o4;

    /* Set up registers for ptrace syscall */
    regs.pc = syscall_loc;
    if (restore_registers(pid, &regs) < 0)
	abort();

    /* Execute call */
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
	perror("ptrace singlestep");
	abort();
    }
    ret = waitpid(pid, &status, 0);
    if (ret == -1) {
	perror("Failed to wait for child");
	abort();
    }

    /* Get our new registers */
    if (save_registers(pid, &regs) < 0)
	abort();

    /* Return everything back to normal */
    if (restore_registers(pid, &orig_regs) < 0)
	abort();

    if ((signed long)regs.u_regs[UREG_I0] < 0) {
	errno = -regs.u_regs[UREG_I0];
	return -1;
    }

    return regs.u_regs[UREG_I0];
#endif
}

#define __rsyscall0(type,name) \
    type __r_##name(pid_t pid) { \
	return (type)__remote_syscall(pid, __NR_##name, #name, \
		0,0,0,0,0,0,0,0,0,0); \
    }

#define __rsyscall1(type,name,type1,arg1) \
    type __r_##name(pid_t pid, type1 arg1) { \
	return (type)__remote_syscall(pid, __NR_##name, #name, \
		1, (unsigned long)arg1, \
		0,0,0,0,0,0,0,0); \
    }

#define __rsyscall2(type,name,type1,arg1,type2,arg2) \
    type __r_##name(pid_t pid, type1 arg1, type2 arg2) { \
	return (type)__remote_syscall(pid, __NR_##name, #name, \
		1, (unsigned long)arg1, \
		1, (unsigned long)arg2, \
		0,0,0,0,0,0); \
    }

#define __rsyscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
    type __r_##name(pid_t pid, type1 arg1, type2 arg2, type3 arg3) { \
	return (type)__remote_syscall(pid, __NR_##name, #name, \
		1, (unsigned long)arg1, \
		1, (unsigned long)arg2, \
		1, (unsigned long)arg3, \
		0,0,0,0); \
    }

#define __rsyscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
    type __r_##name(pid_t pid, type1 arg1, type2 arg2, type3 arg3, type4 arg4) { \
	return (type)__remote_syscall(pid, __NR_##name, #name, \
		1, (unsigned long)arg1, \
		1, (unsigned long)arg2, \
		1, (unsigned long)arg3, \
		1, (unsigned long)arg4, \
		0,0); \
    }

#define __rsyscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,type5,arg5) \
    type __r_##name(pid_t pid, type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5) { \
	return (type)__remote_syscall(pid, __NR_##name, #name, \
		1, (unsigned long)arg1, \
		1, (unsigned long)arg2, \
		1, (unsigned long)arg3, \
		1, (unsigned long)arg4, \
		1, (unsigned long)arg5); \
    }

__rsyscall3(off_t, read, int, fd, void*, buf, size_t, count);
ssize_t r_read(pid_t pid, int fd, void* buf, size_t count)
{
    int off;
    off = 0;
    while (count > 0) {
	int amt = PAGE_SIZE; /* must be less than size of scribble zone */
	int err;
	if (count < amt)
	    amt = count;
	err = __r_read(pid, fd, (void*)scribble_zone, amt);
	if (err <= 0)
	    return err;
	memcpy_from_target(pid, (char*)buf + off, (void*)scribble_zone, err);
	off += err;
	count -= err;
    }
    return off;
}

__rsyscall3(off_t, lseek, int, fd, off_t, offset, int, whence);
off_t r_lseek(pid_t pid, int fd, off_t offset, int whence)
{
    return __r_lseek(pid, fd, offset, whence);
}

__rsyscall2(off_t, fcntl, int, fd, int, cmd);
int r_fcntl(pid_t pid, int fd, int cmd)
{
    return __r_fcntl(pid, fd, cmd);
}

__rsyscall3(int, mprotect, void*, start, size_t, len, int, flags);
int r_mprotect(pid_t pid, void* start, size_t len, int flags)
{
    return __r_mprotect(pid, start, len, flags);
}

__rsyscall4(int, rt_sigaction, int, sig, struct k_sigaction*, ksa, struct k_sigaction*, oksa, size_t, masksz);
int r_rt_sigaction(pid_t pid, int sig, struct k_sigaction *ksa, struct k_sigaction *oksa, size_t masksz)
{
    int ret;
    if (ksa)
	memcpy_into_target(pid, (void*)(scribble_zone+0x100), ksa, sizeof(*ksa));
    ret = __r_rt_sigaction(pid, sig, ksa?(void*)(scribble_zone+0x100):NULL,
	    oksa?(void*)(scribble_zone+0x100+sizeof(*ksa)):NULL, masksz);
    if (oksa)
	memcpy_from_target(pid, oksa, (void*)(scribble_zone+0x100+sizeof(*ksa)), sizeof(*oksa));

    return ret;
}

__rsyscall3(int, ioctl, int, fd, int, req, void*, val);
int r_ioctl(pid_t pid, int fd, int req, void* val)
{
    return __r_ioctl(pid, fd, req, val);
}

__rsyscall5(int, getsockopt, int, s, int, level, int, optname, void*, optval, socklen_t*, optlen);

__rsyscall3(int, getpeername, int, s, struct sockaddr*, name, socklen_t*, namelen);
int r_getpeername(pid_t pid, int s, struct sockaddr *name, socklen_t *namelen)
{
    int ret;

    memcpy_into_target(pid, (void*)(scribble_zone+0x10), namelen, sizeof(*namelen));
    memcpy_into_target(pid, (void*)(scribble_zone+0x20), name, *namelen);

    ret = __r_getpeername(pid, s,
	    (void*)(scribble_zone+0x10),
	    (void*)(scribble_zone+0x20));
    
    if (ret == -1)
	return -1;

    memcpy_from_target(pid, namelen, (void*)(scribble_zone+0x10), sizeof(*namelen));
    memcpy_from_target(pid, name, (void*)(scribble_zone+0x20), 1+*namelen);

    return ret;
}

__rsyscall3(int, getsockname, int, s, struct sockaddr*, name, socklen_t*, namelen);
int r_getsockname(pid_t pid, int s, struct sockaddr *name, socklen_t *namelen)
{
    int ret;

    memcpy_into_target(pid, (void*)(scribble_zone+0x10), namelen, sizeof(*namelen));
    memcpy_into_target(pid, (void*)(scribble_zone+0x20), name, *namelen);

    ret = __r_getsockname(pid, s,
	    (void*)(scribble_zone+0x10),
	    (void*)(scribble_zone+0x20));
    
    if (ret == -1)
	return -1;

    memcpy_from_target(pid, namelen, (void*)(scribble_zone+0x10), sizeof(*namelen));
    memcpy_from_target(pid, name, (void*)(scribble_zone+0x20), 1+*namelen);

    return ret;
}

/* vim:set ts=8 sw=4 noet: */
