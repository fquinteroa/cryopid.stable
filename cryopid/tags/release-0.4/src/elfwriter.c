#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "process.h"

char *stub_start;
int stub_size;

void write_stub(int fd, long heap_start) {
    Elf32_Ehdr *e;
    Elf32_Shdr *s;
    Elf32_Phdr *p;
    char* strtab;
    int i;

    e = (Elf32_Ehdr*)stub_start;

    assert(e->e_shoff != 0);
    assert(e->e_shentsize == sizeof(Elf32_Shdr));
    assert(e->e_shstrndx != SHN_UNDEF);

    s = (Elf32_Shdr*)(stub_start+(e->e_shoff+(e->e_shstrndx*e->e_shentsize)));
    strtab = stub_start+s->sh_offset;
    
    for (i = 0; i < e->e_phnum; i++) {
	p = (Elf32_Phdr*)(stub_start+e->e_phoff+(i*e->e_phentsize));
	if (p->p_vaddr != 0x41414141)
	    continue;

	p->p_vaddr = p->p_paddr = heap_start;
	p->p_memsz = 4;
	p->p_filesz = 0;
	p->p_offset = 0;
	printf("Heap tweakd\n");
    }

    for (i = 0; i < e->e_shnum; i++) {
	s = (Elf32_Shdr*)(stub_start+e->e_shoff+(i*e->e_shentsize));
	if (s->sh_type != SHT_PROGBITS || s->sh_name == 0)
	    continue;

	if (memcmp(strtab+s->sh_name, "cryopid.image", 13) != 0)
	    continue;

	/* check the signature from the stub's linker script */
	if (memcmp(stub_start+s->sh_offset, "CPIM", 4) != 0) {
	    fprintf(stderr, "Found an invalid stub! Keeping on trying...\n");
	    continue;
	}

	s->sh_info = IMAGE_VERSION;
	*(long*)(stub_start+s->sh_offset) = stub_size;

	write(fd, stub_start, stub_size);
	return;
    }
    fprintf(stderr, "Couldn't find a valid stub linked in! Bugger.\n");
    exit(1);
}

/* vim:set ts=8 sw=4 noet: */
