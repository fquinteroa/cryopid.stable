#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int syscall_check(int retval, int can_be_fake, char* desc, ...) {
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

/* vim:set ts=8 sw=4 noet: */
