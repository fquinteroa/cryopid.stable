#include <linux/unistd.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <asm/page.h>
#include "process.h"

extern char *stub_start;
extern long stub_size;

// #define RELOCATE_HEAP

#ifdef RELOCATE_HEAP
static void write_tramp_snippet(long** tramp, long mmap_addr, long mmap_len,
	int mmap_prot, long src, long dst, long length)
{
    long *p = *tramp;
    long mmap_flags = MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS;

//    *p++=0x82102000 | __NR_kill;                 /* mov foo, %g1     */
//    *p++=0x11000000 | (0);         /* sethi foo, %o0   */
//    *p++=0x90122000 | (0);       /* or %o0, foo, %o0 */
//    *p++=0x13000000 | (SIGSTOP >> 10);          /* sethi foo, %o1   */
//    *p++=0x92126000 | (SIGSTOP & 0x3ff);        /* or %o1, foo, %o1 */
//    *p++=0x91d02010;                             /* t 0x10           */

    /* mmap(new_start, length, PROT_READ|PROT_WRITE,
     *         MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0); */
    *p++=0x82102000 | __NR_mmap;                 /* mov foo, %g1     */
    *p++=0x11000000 | HIB(mmap_addr);            /* sethi foo, %o0   */
    *p++=0x90122000 | LOB(mmap_addr);            /* or %o0, foo, %o0 */
    *p++=0x13000000 | HIB(mmap_len);             /* sethi foo, %o1   */
    *p++=0x92126000 | LOB(mmap_len);             /* or %o1, foo, %o1 */
    *p++=0x15000000 | HIB(mmap_prot);            /* sethi foo, %o2   */
    *p++=0x9412a000 | LOB(mmap_prot);            /* or %o2, foo, %o2 */
    *p++=0x17000000 | HIB(mmap_flags);           /* sethi foo, %o3   */
    *p++=0x9612e000 | LOB(mmap_flags);           /* or %o3, foo, %o3 */
    *p++=0x91d02010;                             /* t 0x10           */
    *p++=0x01000000;                             /* nop              */

    /* now memcpy code */
    *p++=0x11000000 | HIB(dst);                  /* sethi foo, %o0   */
    *p++=0x90122000 | LOB(dst);                  /* or %o0, foo, %o0 */
    *p++=0x13000000 | HIB(src);                  /* sethi foo, %o1   */
    *p++=0x92126000 | LOB(src);                  /* or %o1, foo, %o1 */
    *p++=0x15000000 | HIB(length);               /* sethi foo, %o2   */
    *p++=0x9412a000 | LOB(length);               /* or %o2, foo, %o2 */

    /* memcpy function */
    *p++=0x96103fff;                /*  mov  -1, %o3              */
    *p++=0x94a2a001;                /*  deccc  %o2                */
    *p++=0x06800005;                /*  bl  1c <memcpy+0x1c>      */
    *p++=0x9602e001;                /*  inc  %o3                  */
    *p++=0xd80a400b;                /*  ldub  [ %o1 + %o3 ], %o4  */
    *p++=0x10bffffc;                /*  b  4 <memcpy+0x4>         */
    *p++=0xd82a000b;                /*  stb  %o4, [ %o0 + %o3 ]   */
    *p++=0x01000000;                /*  nop                       */

//    *p++=0x82102000 | __NR_kill;                 /* mov foo, %g1     */
//    *p++=0x11000000 | (0);         /* sethi foo, %o0   */
//    *p++=0x90122000 | (0);       /* or %o0, foo, %o0 */
//    *p++=0x13000000 | (SIGSTOP >> 10);          /* sethi foo, %o1   */
//    *p++=0x92126000 | (SIGSTOP & 0x3ff);        /* or %o1, foo, %o1 */
//    *p++=0x91d02010;                             /* t 0x10           */

    *tramp = p;
}

static void write_tramp_jump(long **tramp, long entry)
{
    long *p = *tramp;
    /* and go there! */
    *p++=0x03000000 | HIB(entry);                /* sethi foo, %g1   */
    *p++=0x82106000 | LOB(entry);                /* or %g1, foo, %g1 */
    *p++=0x9fc04000;                             /* call %g1         */
    *p++=0x01000000;                             /* nop              */
    *tramp = p;
}
#endif

void write_stub(int fd, long offset)
{
    Elf32_Ehdr *e;
    Elf32_Shdr *s;
    Elf32_Phdr *p;
    char* strtab;
    int i, j;
    int got_it;
#ifdef RELOCATE_HEAP
    unsigned long cur_brk = 0;

    /* offset is where we'd like the heap to begin.
     * We want to set offset to where the code must begin in order to get
     * the heap in the right place.
     * ie, offset = offset - round_to_page(code_len) - round_to_page(data_len)
     */
#endif

    e = (Elf32_Ehdr*)stub_start;

    assert(e->e_shoff != 0);
    assert(e->e_shentsize == sizeof(Elf32_Shdr));
    assert(e->e_shstrndx != SHN_UNDEF);

    s = (Elf32_Shdr*)(stub_start+(e->e_shoff+(e->e_shstrndx*e->e_shentsize)));
    strtab = stub_start+s->sh_offset;

#ifdef RELOCATE_HEAP
    /* Locate where this binary's brk would start */
    for (i = 0; i < e->e_phnum; i++) {
	p = (Elf32_Phdr*)(stub_start+e->e_phoff+(i*e->e_phentsize));
	if (p->p_type != PT_LOAD)
	    continue;
	if (p->p_vaddr + p->p_memsz > cur_brk);
	    cur_brk = p->p_vaddr + p->p_memsz;
    }

    fprintf(stderr, "Heap was at 0x%lx. Want to be at 0x%lx. offset = 0x%lx\n",
	    cur_brk, offset, offset - cur_brk);

    /* Set where we want it to start */
    offset -= cur_brk;
    offset &= ~(PAGE_SIZE - 1);
#else
    offset = 0;
#endif

    got_it = 0;
    for (i = 0; i < e->e_shnum; i++) {
	s = (Elf32_Shdr*)(stub_start+e->e_shoff+(i*e->e_shentsize));
	s->sh_addr += offset;

	if (s->sh_type != SHT_PROGBITS || s->sh_name == 0)
	    continue;

#ifdef RELOCATE_HEAP
	if (memcmp(strtab+s->sh_name, "cryopid.tramp", 13) == 0) {
	    char *tp = stub_start+s->sh_offset;

	    for (j = 0; j < e->e_phnum; j++) {
		unsigned long mmap_addr, mmap_len;
		int mmap_prot = 0;

		p = (Elf32_Phdr*)(stub_start+e->e_phoff+(j*e->e_phentsize));

		if (p->p_type != PT_LOAD)
		    continue;

		/* FIXME: Set these prot flags more exactly with mprotect later. */
		mmap_prot = PROT_READ | PROT_WRITE;
		if (p->p_flags & PF_X) mmap_prot |= PROT_EXEC;

		mmap_addr = p->p_vaddr & ~(PAGE_SIZE - 1);
		mmap_len = p->p_memsz + (p->p_vaddr - mmap_addr);
		mmap_len = (mmap_len + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

		write_tramp_snippet((long**)&tp, 
			mmap_addr, mmap_len, mmap_prot,
			p->p_vaddr + offset, p->p_vaddr, p->p_filesz);
	    }

	    write_tramp_jump((long**)&tp, e->e_entry);
	    e->e_entry = s->sh_addr;
	}
#endif

	if (memcmp(strtab+s->sh_name, "cryopid.image", 13) == 0) {
	    /* check the signature from the stub's linker script */
	    if (memcmp(stub_start+s->sh_offset, "CPIM", 4) != 0) {
		fprintf(stderr, "Found an invalid stub! Still trying...\n");
		continue;
	    }

	    s->sh_info = IMAGE_VERSION;
	    *(long*)(stub_start+s->sh_offset) = stub_size;
	    got_it = 1;
	}
    }

#ifdef RELOCATE_HEAP
    for (i = 0; i < e->e_phnum; i++) {
	p = (Elf32_Phdr*)(stub_start+e->e_phoff+(i*e->e_phentsize));
	p->p_vaddr += offset;
	p->p_paddr += offset;
    }
#endif

    if (!got_it) {
	fprintf(stderr, "Couldn't find a valid stub linked in! Bugger.\n");
	exit(1);
    }
    write(fd, stub_start, stub_size);
}

/* vim:set ts=8 sw=4 noet: */
