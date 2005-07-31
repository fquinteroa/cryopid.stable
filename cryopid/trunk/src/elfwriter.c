#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "process.h"

extern char *stub_start;
extern int stub_size;

void write_tramp(char* tramp, long old_data_start, long new_data_start,
	int data_len, long old_code_start, long new_code_start, int code_len,
	long entry)
{
    char *p = tramp;

    /*
     * 55                      push   %ebp
     * bd d2 04 00 00          mov    $0x4d2,%ebp
     * b8 39 30 00 00          mov    $0x3039,%eax
     * cd 80                   int    $0x80
     * 5d                      pop    %ebp
     */

    /* mmap(data_start, data_len, PROT_READ|PROT_WRITE|PROT_EXEC, 
     *         MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0); */
    *p++=0xb8;*(long*)(p)=__NR_mmap2; p+=4;      /* mov foo, %eax */
    *p++=0xbb;*(long*)(p)=new_data_start; p+=4;  /* mov foo, %ebx */
    *p++=0xb9;*(long*)(p)=data_len; p+=4;        /* mov foo, %ecx */
    *p++=0xba;*(long*)(p)=PROT_READ|PROT_WRITE; p+=4;
						 /* mov foo, %edx */
    *p++=0xbe;*(long*)(p)=MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS; p+=4;
						 /* mov foo, %esi */
    *p++=0xcd;*p++=0x80;			 /* int $0x80 */

    /* mmap(data_start, data_len, PROT_READ|PROT_WRITE|PROT_EXEC, 
     *         MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0); */
    *p++=0xb8;*(long*)(p)=__NR_mmap2; p+=4;      /* mov foo, %eax */
    *p++=0xbb;*(long*)(p)=new_code_start; p+=4;  /* mov foo, %ebx */
    *p++=0xb9;*(long*)(p)=code_len; p+=4;        /* mov foo, %ecx */
    *p++=0xba;*(long*)(p)=PROT_READ|PROT_WRITE|PROT_EXEC; p+=4;
						 /* mov foo, %edx */
    *p++=0xbe;*(long*)(p)=MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS; p+=4;
						 /* mov foo, %esi */
    *p++=0xcd;*p++=0x80;			 /* int $0x80 */

    /* now memcpy code */
    *p++=0xbe;*(long*)(p)=old_code_start; p+=4;  /* mov foo, %esi */
    *p++=0xbf;*(long*)(p)=new_code_start; p+=4;  /* mov foo, %edi */
    *p++=0xb9;*(long*)(p)=code_len>>2; p+=4;     /* mov foo, %ecx */
    *p++=0xf3;*p++=0xa5;                         /* rep movsl */

    /* now memcpy data */
    *p++=0xbe;*(long*)(p)=old_data_start; p+=4;  /* mov foo, %esi */
    *p++=0xbf;*(long*)(p)=new_data_start; p+=4;  /* mov foo, %edi */
    *p++=0xb9;*(long*)(p)=data_len>>2; p+=4;     /* mov foo, %ecx */
    *p++=0xf3;*p++=0xa5;                         /* rep movsl */

    /* and go there! */
    *p++=0xb8;*(long*)(p)=entry; p+=4;           /* mov foo, %eax */
    *p++=0xff;*p++=0xe0;                         /* jmp (%eax) */
}

void write_stub(int fd, long offset)
{
    Elf32_Ehdr *e;
    Elf32_Shdr *s;
    Elf32_Phdr *p, *data, *code;
    char* strtab;
    int i;
    int got_it;

    /* offset is where we'd like to position our heap.
     * We want to set offset to where the code must begin in order to get
     * the heap in the right place.
     * ie, offset = offset - round_to_page(code_len) - round_to_page(data_len)
     */

    e = (Elf32_Ehdr*)stub_start;

    assert(e->e_shoff != 0);
    assert(e->e_shentsize == sizeof(Elf32_Shdr));
    assert(e->e_shstrndx != SHN_UNDEF);

    code = (Elf32_Phdr*)(stub_start+e->e_phoff);
    data = (Elf32_Phdr*)(stub_start+e->e_phoff+sizeof(Elf32_Phdr));
    offset &= ~(PAGE_SIZE-1);
    offset -= (code->p_memsz+PAGE_SIZE-1)&~(PAGE_SIZE-1),
    offset -= (data->p_memsz+PAGE_SIZE-1)&~(PAGE_SIZE-1),

    s = (Elf32_Shdr*)(stub_start+(e->e_shoff+(e->e_shstrndx*e->e_shentsize)));
    strtab = stub_start+s->sh_offset;

    e->e_entry += offset;

    got_it = 0;
    for (i = 0; i < e->e_shnum; i++) {
	s = (Elf32_Shdr*)(stub_start+e->e_shoff+(i*e->e_shentsize));
	s->sh_addr += offset;

	if (s->sh_type != SHT_PROGBITS || s->sh_name == 0)
	    continue;

	if (memcmp(strtab+s->sh_name, "cryopid.tramp", 13) == 0) {
	    write_tramp(stub_start+s->sh_offset, 
		    (code->p_vaddr+offset) & ~(PAGE_SIZE-1),
		    code->p_vaddr & ~(PAGE_SIZE-1),
		    (code->p_memsz+PAGE_SIZE-1)&~(PAGE_SIZE-1),
		    (data->p_vaddr+offset) & ~(PAGE_SIZE-1),
		    data->p_vaddr & ~(PAGE_SIZE-1),
		    (data->p_memsz+PAGE_SIZE-1)&~(PAGE_SIZE-1),
		    e->e_entry);
	    e->e_entry = s->sh_addr;
	}

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

    for (i = 0; i < e->e_phnum; i++) {
	p = (Elf32_Phdr*)(stub_start+e->e_phoff+(i*e->e_phentsize));
	p->p_vaddr += offset;
	p->p_paddr += offset;
    }

    if (!got_it) {
	fprintf(stderr, "Couldn't find a valid stub linked in! Bugger.\n");
	exit(1);
    }
    write(fd, stub_start, stub_size);
}

/* vim:set ts=8 sw=4 noet: */
