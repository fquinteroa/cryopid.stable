#include <linux/user.h>
#include <linux/unistd.h>
#include <asm/ldt.h>
#include <sys/mman.h>
#include <sys/ptrace.h>

#include "cpimage.h"
#include "cryopid.h"

static void process_chunk_regs(struct user *user)
{
    char *cp, *code = (char*)TRAMPOLINE_ADDR;
    struct user_regs_struct *r = &user->regs;

    /* Create region for mini-resumer process. */
    syscall_check(
	(int)mmap((void*)TRAMPOLINE_ADDR, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0), 0, "mmap");

    cp = code;

    /* put eflags onto the process' stack so we can pop it off */
    r->esp-=4;
    *(long*)r->esp = r->eflags;
    
    code[0xffc] = 'A';
    /* set up a temporary stack for use */
    *cp++=0xbc;*(long*)(cp) = (long)code+0x0ff0; cp+=4; /* mov 0x11000, %esp */

    /* munmap our custom malloc space */
    *cp++=0xb8;*(long*)(cp) = __NR_munmap; cp+=4; /* mov foo, %eax  */
    *cp++=0xbb;*(long*)(cp) = MALLOC_START; cp+=4; /* mov foo, %ebx  */
    *cp++=0xb9;*(long*)(cp) = MALLOC_END-MALLOC_START; cp+=4; /* mov foo, %ecx  */
    *cp++=0xcd;*cp++=0x80; /* int $0x80 */

    /* munmap resumer code except for us - except when we're needed for our
     * segvhandler */
    if (!tls_hack) {
	*cp++=0xb8;*(long*)(cp) = __NR_munmap; cp+=4; /* mov foo, %eax  */
	*cp++=0xbb;*(long*)(cp) = RESUMER_START; cp+=4; /* mov foo, %ebx  */
	*cp++=0xb9;*(long*)(cp) = RESUMER_END-RESUMER_START; cp+=4; /* mov foo, %ecx  */
	*cp++=0xcd;*cp++=0x80; /* int $0x80 */
    }

    /* set up gs */
    if (!tls_hack && r->gs != 0) {
	*cp++=0x66;*cp++=0xb8; *(short*)(cp) = r->gs; cp+=2; /* mov foo, %eax  */
	*cp++=0x8e;*cp++=0xe8; /* mov %eax, %gs */
    }

    /* restore registers */
    *cp++=0xb8;*(long*)(cp) = r->eax; cp+=4; /* mov foo, %eax  */
    *cp++=0xbb;*(long*)(cp) = r->ebx; cp+=4; /* mov foo, %ebx  */
    *cp++=0xb9;*(long*)(cp) = r->ecx; cp+=4; /* mov foo, %ecx  */
    *cp++=0xba;*(long*)(cp) = r->edx; cp+=4; /* mov foo, %edx  */
    *cp++=0xbe;*(long*)(cp) = r->esi; cp+=4; /* mov foo, %esi  */
    *cp++=0xbf;*(long*)(cp) = r->edi; cp+=4; /* mov foo, %edi  */
    *cp++=0xbd;*(long*)(cp) = r->ebp; cp+=4; /* mov foo, %ebp  */
    *cp++=0xbc;*(long*)(cp) = r->esp; cp+=4; /* mov foo, %esp  */

    *cp++=0x9d; /* pop eflags */

    /* jump back to where we were. */
    *cp++=0xea;
    *(unsigned long*)(cp) = r->eip; cp+= 4;
    asm("mov %%cs,%w0": "=q"(r->cs)); /* ensure we use the right CS for the current kernel */
    *(unsigned short*)(cp) = r->cs; cp+= 2; /* jmp cs:foo */
}

void fetch_chunks_regs(pid_t pid, int flags, struct list *l)
{
    struct cp_chunk *chunk = NULL;
    struct user *user_data;
    long pos;
    int* user_data_ptr;

    user_data = xmalloc(sizeof(struct user));
    user_data_ptr = (int*)user_data;

    /* We have a memory segment. We should retrieve its data */
    for(pos = 0; pos < sizeof(struct user)/sizeof(int); pos++) {
	user_data_ptr[pos] =
	    ptrace(PTRACE_PEEKUSER, pid, (void*)(pos*4), NULL);
	if (errno != 0) {
	    perror("ptrace(PTRACE_PEEKDATA): ");
	}
    }

    /* Restart a syscall on the other side */
    if (is_in_syscall(pid, (void*)user_data->regs.eip)) {
	fprintf(stderr, "[+] Process is probably in syscall. Noting this fact.\n");
	user_data->regs.eip-=2;
	user_data->regs.eax = user_data->regs.orig_eax;
    }

    chunk = xmalloc(sizeof(struct cp_chunk));
    chunk->type = CP_CHUNK_REGS;
    chunk->regs.user_data = user_data;
    list_append(l, chunk);
}

void read_chunk_regs(void *fptr, struct cp_regs *data, int load)
{
    struct user user, *userp;
    if (data) {
	data->user_data = xmalloc(sizeof(struct user));
	userp = data->user_data;
    } else
	userp = &user;
    read_bit(fptr, userp, sizeof(struct user));
    if (load)
	process_chunk_regs(userp);
}

void write_chunk_regs(void *fptr, struct cp_regs *data)
{
    write_bit(fptr, data->user_data, sizeof(struct user));
}

/* vim:set ts=8 sw=4 noet: */
