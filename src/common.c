#include <errno.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/user.h>

#include "cryopid.h"

long syscall_check(int retval, int can_be_fake, char* desc, ...)
{
    va_list va_args;
    /* can_be_fake is true if the syscall might return -1 anyway, and
     * we should simply check errno.
     */
    if (can_be_fake && errno == 0) return retval;
    if (retval == -1) {
	char str[1024];
	snprintf(str, 1024, "Error in %s: %s\n", desc, strerror(errno));
	va_start(va_args, desc);
	vfprintf(stderr, str, va_args);
	va_end(va_args);
	exit(1);
    }
    return retval;
}

void safe_read(int fd, void* dest, size_t count, char* desc)
{
    int ret;
    ret = read(fd, dest, count);
    if (ret == -1) {
	fprintf(stderr, "Read error on %s: %s\n", desc, strerror(errno));
	exit(1);
    }
    if (ret < count) {
	fprintf(stderr, "Short read on %s\n", desc);
	exit(1);
    }
}

#ifdef COMPILING_STUB
/* If we're a stub, lets use a custom malloc implementation so that we don't
 * collide with pages potentially in use by the application. Here's a really
 * really stupid malloc.
 *
 * FIXME: do something smarter. Can we persuade malloc to stick to brk'ing and
 * not mmap()?
 */

#ifdef __i386__
/*
 * Consistent with arch-i386/cplayout.h design about malloc handling on i386.
 * areas[MAX_AREAS] is an array of struct "ele_area" that manage 32MB for custom
 * malloc.
*/
#define MB	(1024*1024)
#define MAX_AREAS	32  /* 32MB for custom malloc */

typedef struct {
    void *ptr_area;
    unsigned int size_left;
    unsigned int max;
} ele_area;

ele_area areas[MAX_AREAS];
static int actual_ptr_areas = -1;

static int init_ele_area(void)
{
    short int i;

    for (i = 0; i < MAX_AREAS; i++) {
	areas[i].ptr_area = NULL;
	areas[i].size_left = 0;
	areas[i].max = 0;
    }
    return EXIT_SUCCESS;
}

static int alloc_new_area(int index, size_t size)
{
    static long next_free_addr = MALLOC_START;
    void *tmp_ptr;
    unsigned int area_needed = MB;  /* min size to alloc */

    while (area_needed < size)	/* decide how many MB needed */
	area_needed <<= 1;
    //printf("[alloc_new_area] area_needed: %u, area terminate at: %ld\n", area_needed, next_free_addr + area_needed);

    if ((next_free_addr + area_needed) > MALLOC_END) {
        fprintf(stderr, "our custom area for malloc is full\n");
        return EXIT_FAILURE;
    }
    tmp_ptr = mmap((void*) next_free_addr, area_needed, 
	    PROT_READ|PROT_WRITE, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

    if (tmp_ptr == MAP_FAILED) {
        fprintf(stderr, "error in mmap call: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    else {
        areas[index].ptr_area = tmp_ptr;
        areas[index].max = area_needed;
	areas[index].size_left = area_needed;
	/* update the next mmap addr pointer rounded PAGE_SIZE */
	next_free_addr = ((next_free_addr + area_needed + (_getpagesize-1)) & ~(_getpagesize-1));
	//printf("[alloc_new_area] next_free_addr: %ld\n", next_free_addr);
    }
    return EXIT_SUCCESS;
}

static int index_area_to_use(size_t size)
{
    int i;
	
    if (actual_ptr_areas == -1) {   /* for the first time */
	init_ele_area();
	actual_ptr_areas = 0;
	if (alloc_new_area(actual_ptr_areas, size) == EXIT_FAILURE)
	    return MAX_AREAS;
	return actual_ptr_areas;
    }
    /* actual_ptr_areas must address the last areas in use */
    for (i = 0; i < MAX_AREAS; i++)
	if (areas[i].max == 0)
	    break;
    actual_ptr_areas = i;

    i = 0;
    /* understand which "areas" can contain the requested size */
    while (((areas[i].size_left < size) && (areas[i].size_left != 0))
	&& (i < MAX_AREAS))
	i++;

    if (i == MAX_AREAS)	/* all the "areas" are in use */
	return MAX_AREAS;
    else if (areas[i].size_left == 0) {	/* alloc a new area */
	actual_ptr_areas++;
	if (alloc_new_area(actual_ptr_areas, size) == EXIT_FAILURE)
	    return MAX_AREAS;
	return actual_ptr_areas;
    }
    else if (areas[i].max == 0)	{ /* "i" is the index of the new area to allocate */
	if (alloc_new_area(i, size) == EXIT_FAILURE)
	    return MAX_AREAS;
    }
    return i; /* "i" is the index of the area to use */
}

static void *cp_malloc_hook(size_t size, const void *caller)
{
    int index = 0;
    void *ptr_to_use = NULL;

    //printf("using custom malloc. request in size: %d\n", size);
    
    while ((size % sizeof(int)) != 0)
	size++;
    index = index_area_to_use(size);
    if (index == MAX_AREAS) {
	fprintf(stderr, "custom malloc memory full\n");
	return NULL;
    }
    /* calculate the real pointer to the area allocated and the size_left of the chose "areas" */
    ptr_to_use = areas[index].ptr_area + (areas[index].max - areas[index].size_left);
    areas[index].size_left -= size;
    /*printf("pointer value [dec]: %u, pointer value [x]: %x, index: %d, size_left: %d\n", 
	(unsigned int) ptr_to_use, (unsigned int) ptr_to_use, index, areas[index].size_left);*/
    if (memset(ptr_to_use, 0, size) != ptr_to_use)
	bail("[E] failed to reset memory area");

    return ptr_to_use;
}

#else
/*
 * The old style for arch not i386. It's less elegant and clean.
 * Here's a really really stupid malloc, that simply mmaps a new 
 * VMA for each request, and rounds up to the next multiple of PAGE_SIZE.
 */
static void *cp_malloc_hook(size_t size, const void *caller)
{
    static long next_free_addr = MALLOC_START;

    int full_len = (size + (_getpagesize-1)) & ~(_getpagesize-1);

    if (next_free_addr + full_len > MALLOC_END)
	return NULL; /* out of memory here */

    void *p = mmap((void*)next_free_addr, full_len, PROT_READ|PROT_WRITE,
	    MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
	    
    assert(p == (void*)next_free_addr);
    next_free_addr += full_len;
    return p;
}

#endif	/* __i386__ */

static void cp_free_hook(void *ptr, const void *caller)
{
    /* Don't worry about freeing it, because our memory segment will be munmap'd
     * before the real binary executes. However this does waste memory if we
     * do lots of mallocing and freeing. FIXME. fix this.
     */
}

#ifdef PROVIDE_MALLOC
/* We provide malloc() and free() */

void *malloc(size_t size) { return cp_malloc_hook(size, NULL); }
void free(void *mem) { return cp_free_hook(mem, NULL); }

#else
/* We're hooking into libc's malloc */

static void cp_malloc_init_hook();

static void* (*old_malloc_hook)(size_t, const void *);
void (*__malloc_initialize_hook) (void) = cp_malloc_init_hook;

static void cp_malloc_init_hook()
{
    old_malloc_hook = __malloc_hook;
    __malloc_hook = cp_malloc_hook;
    __free_hook = cp_free_hook;
}

#endif /* PROVIDE_MALLOC */

#endif /* COMPILING_STUB */

void *xmalloc(int len)
{
    void *p;
    p = malloc(len);
    if (!p)
	    bail("Out of memory!");
    return p;
}

void xfree(void *p)
{
    free(p);
}

unsigned int checksum(char *ptr, int len, unsigned int start)
{
    int sum = start, i;
    for (i = 0; i < len; i++)
	sum = ((sum << 5) + sum) ^ ptr[i];
    return sum;
}

/* vim:set ts=8 sw=4 noet: */
