#include <getopt.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>
#include <linux/elf.h>
#include <string.h>
#include <unistd.h>

#include "cryopid.h"
#include "cpimage.h"
#include "process.h"

void jump_to_trampoline()
{
    asm("jmp *%%eax\n" : : "a"(TRAMPOLINE_ADDR));
}

static void* find_top_of_stack()
{
    unsigned int tmp;
    /* Return the top of the current stack page. */
    return (void*)(((long)&tmp + PAGE_SIZE - 1) & ~(PAGE_SIZE-1));
}

static void seek_to_image(int fd)
{
    Elf32_Ehdr e;
    Elf32_Shdr s;
    int i;
    char* strtab;

    syscall_check(lseek(fd, 0, SEEK_SET), 0, "lseek");
    safe_read(fd, &e, sizeof(e), "Elf32_Ehdr");
    if (e.e_shoff == 0) {
	fprintf(stderr, "No section header found in self! Bugger.\n");
	exit(1);
    }
    if (e.e_shentsize != sizeof(Elf32_Shdr)) {
	fprintf(stderr, "Section headers incorrect size. Bugger.\n");
	exit(1);
    }
    if (e.e_shstrndx == SHN_UNDEF) {
	fprintf(stderr, "String section missing. Bugger.\n");
	exit(1);
    }
    
    /* read the string table */
    syscall_check(lseek(fd, e.e_shoff+(e.e_shstrndx*sizeof(Elf32_Shdr)), SEEK_SET), 0, "lseek");
    safe_read(fd, &s, sizeof(s), "string table section header");
    syscall_check(lseek(fd, s.sh_offset, SEEK_SET), 0, "lseek");
    strtab = xmalloc(s.sh_size);
    safe_read(fd, strtab, s.sh_size, "string table");

    for (i=0; i < e.e_shnum; i++) {
	long offset;

	syscall_check(
		lseek(fd, e.e_shoff+(i*sizeof(Elf32_Shdr)), SEEK_SET), 0, "lseek");
	safe_read(fd, &s, sizeof(s), "Elf32_Shdr");
	if (s.sh_type != SHT_PROGBITS || s.sh_name == 0)
	    continue;

	/* We have potential data! Is it really ours? */
	if (memcmp(strtab+s.sh_name, "cryopid.image", 13) != 0)
	    continue;

	if (s.sh_info != IMAGE_VERSION) {
	    fprintf(stderr, "Incorrect image version found (%d)! Keeping on trying.\n", s.sh_info);
	    continue;
	}

	/* Woo! got it! */
	syscall_check(
		lseek(fd, s.sh_offset, SEEK_SET), 0, "lseek");

	safe_read(fd, &offset, 4, "offset");

	syscall_check(
		lseek(fd, offset, SEEK_SET), 0, "lseek");

	return;
    }
    fprintf(stderr, "Program image not found!\n");
    exit(1);
}

static inline void relocate_stack()
{
    void *top_of_old_stack;
    void *top_of_new_stack;
    void *top_of_our_memory = (void*)MALLOC_END;
    void *top_of_all_memory;
    long size_of_new_stack;

    /* Reposition the stack at top_of_old_stack */
    top_of_old_stack = find_top_of_stack();
    top_of_all_memory = (void*)get_task_size();

    top_of_new_stack = (void*)TOP_OF_STACK;
    size_of_new_stack = PAGE_SIZE;

    syscall_check( (int)
	mmap(top_of_new_stack - size_of_new_stack, size_of_new_stack,
	    PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANONYMOUS|MAP_FIXED|MAP_GROWSDOWN|MAP_PRIVATE, -1, 0),
	0, "mmap(newstack)");
    memset(top_of_new_stack - size_of_new_stack, 0, size_of_new_stack);
    memcpy(top_of_new_stack - size_of_new_stack,
	    top_of_old_stack - size_of_new_stack, /* FIX ME */
	    size_of_new_stack);
    __asm__ ("addl %0, %%esp" : : "a"(top_of_new_stack - top_of_old_stack));
    __asm__ ("addl %0, %%ebp" : : "a"(top_of_new_stack - top_of_old_stack));

    /* unmap absolutely everything above us! */
    syscall_check(
	    munmap(top_of_our_memory,
		(top_of_all_memory - top_of_our_memory)),
		0, "munmap(stack)");
}

/* vim:set ts=8 sw=4 noet: */
