#ifndef _CRYOPID_H_
#define _CRYOPID_H_

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

#include "cpimage.h"

#define debug(s, x...) fprintf(stderr, s"\n", ##x)

#define info(x...) fprintf(stderr, x)

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

#define GB		(1024*1024*1024)

/* elfwriter.c */
void write_stub(int fd, long offset);

/* common.c */
int syscall_check(int retval, int can_be_fake, char* desc, ...);
void safe_read(int fd, void* dest, size_t count, char* desc);
void *xmalloc(int len);
unsigned int checksum(char *ptr, int len, unsigned int start);
unsigned long get_task_size();

/* writer_raw.c */
extern struct stream_ops raw_ops;

/* writer_buffered.c */
extern struct stream_ops buf_ops;

/* writer_lzo.c */
extern struct stream_ops lzo_ops;

#define MAX_SIGS 31

#ifdef COMPILING_STUB
#define declare_writer(s, x, desc) struct stream_ops *stream_ops = &x
#else
#define declare_writer(s, x, desc) \
    extern char *_binary_stub_##s##_start; \
    extern int _binary_stub_##s##_size; \
    struct stream_ops *stream_ops = &x; \
    char *stub_start = (char*)&_binary_stub_##s##_start; \
    int stub_size = (int)&_binary_stub_##s##_size

#endif

#endif /* _CRYOPID_H_ */

/* vim:set ts=8 sw=4 noet: */
