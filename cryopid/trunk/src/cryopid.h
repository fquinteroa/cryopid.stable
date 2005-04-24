#ifndef _CRYOPID_H_
#define _CRYOPID_H_

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

#include "cpimage.h"

#define debug(s, x...) fprintf(stderr, s"\n", ##x)

#define bail(s, x...) \
	{ \
		fprintf(stderr, s"\n", ##x); \
		abort(); \
	}

#ifdef assert
#undef assert
#endif
#define assert(x) \
	if (!(x)) { \
	    fprintf(stderr, "Assertion failed in %s (%s:%d)\n", __FUNCTION__, \
		    __FILE__, __LINE__); \
	    abort(); \
	}

/* elfwriter.c */
void write_stub(int fd);

/* common.c */
int syscall_check(int retval, int can_be_fake, char* desc, ...);
void *xmalloc(int len);

/* writer_raw.c */
extern struct stream_ops raw_ops;

/* writer_buffered.c */
extern struct stream_ops buf_ops;

/* writer_lzo.c */
extern struct stream_ops lzo_ops;

/* process.c */
int do_syscall(pid_t pid, struct user_regs_struct *regs);
int memcpy_from_target(pid_t pid, void* dest, const void* src, size_t n);
int memcpy_into_target(pid_t pid, void* dest, const void* src, size_t n);

#define MAX_SIGS 31

#ifdef COMPILING_STUB
#define declare_writer(s, x, desc) struct stream_ops *stream_ops = &x
#else
extern char *stub_start;
extern int stub_size;

typedef int (*checker_f)(char*, int);
#define declare_writer(s, sops, desc) \
    static int check_writer(char *s, int force) { \
	extern char *_binary_stub_##s##_start; \
	extern int _binary_stub_##s##_size; \
	if (!force && strcmp(s, #s)) \
	    return 0; \
	stream_ops = &sops; \
	stub_start = (char*)&_binary_stub_##s##_start; \
	stub_size = (int)&_binary_stub_##s##_size; \
	return 1; \
    } \
    static checker_f f __attribute__((__section__(".stubs.list"))) = check_writer
#endif

#endif /* _CRYOPID_H_ */

/* vim:set ts=8 sw=4 noet: */
