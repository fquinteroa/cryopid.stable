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

static inline void *xmalloc(int len) {
	void *p;
	p = malloc(len);
	if (!p)
		bail("Out of memory!");
	return p;
}

/* elfwriter.c */
void write_stub(int fd);

/* common.c */
int syscall_check(int retval, int can_be_fake, char* desc, ...);

/* writer_raw.c */
extern struct stream_ops raw_ops;

/* writer_buffered.c */
extern struct stream_ops buf_ops;

/* process.c */
int do_syscall(pid_t pid, struct user_regs_struct *regs);
int memcpy_from_target(pid_t pid, void* dest, const void* src, size_t n);
int memcpy_into_target(pid_t pid, void* dest, const void* src, size_t n);

#define MAX_SIGS 31

#endif /* _CRYOPID_H_ */

/* vim:set ts=8 sw=4 noet: */
