#ifndef _CPIMAGE_H_
#define _CPIMAGE_H_

#include <sys/socket.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <linux/un.h>
#include <linux/user.h>
#include <linux/unistd.h>
#include <asm/ldt.h>
#include <asm/termios.h>
#include <signal.h>

#include "list.h"

#define IMAGE_VERSION 0x03

#define TRAMPOLINE_ADDR		0x00800000   /* 8MB mark */
#define TRAMPOLINE_ADDR_S	"0x00800000" /* same as above, but as a string */

#define RESUMER_START	0x00000000 /* Lowest location resumer will be at */
#define RESUMER_END	0x00800000 /* Highest location resumer will be at */

#define TOP_OF_STACK	0x00800000

#define MALLOC_START	0x01000000 /* Here we store a pool of 32MB to use */
#define MALLOC_END	0x02000000

/* So with the above parameters, our memory map looks something like:
 *
 * RESUMER_START     code
 *                   data
 *
 *
 * TOP_OF_STACK      stack
 * RESUMER_END
 * TRAMPOLINE_ADDR
 *
 * MALLOC_START
 * MALLOC_END
 *
 * ... program stuff
 */

struct k_sigaction {
    __sighandler_t sa_hand;
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    struct {
	unsigned long sig[2];
    } sa_mask;       /* mask last for extensibility */
};

static inline int set_rt_sigaction(int sig, const struct k_sigaction* ksa,
	const struct k_sigaction* oksa)
{
    int ret;
    asm (
	    "mov %2,%%ebx\n"
	    "int $0x80"
	    : "=a"(ret)
	    : "a"(__NR_rt_sigaction), "r"(sig),
	      "c"(ksa), "d"(oksa), "S"(sizeof(ksa->sa_mask))
	);
    return ret;
}

#define GET_LIBRARIES_TOO          0x01
#define GET_OPEN_FILE_CONTENTS     0x02

/* Constants for cp_chunk.type */
#define CP_CHUNK_MISC		0x01
#define CP_CHUNK_REGS		0x02
#define CP_CHUNK_I387_DATA	0x03
#define CP_CHUNK_TLS		0x04
#define CP_CHUNK_FD		0x05
#define CP_CHUNK_VMA		0x06
#define CP_CHUNK_SIGHAND	0x07
#define CP_CHUNK_FINAL		0x08

#define CP_CHUNK_MAGIC		0xC0DE

/* Constants for cp_fd.type */
#define CP_CHUNK_FD_FILE	0x01
#define CP_CHUNK_FD_CONSOLE	0x02
#define CP_CHUNK_FD_SOCKET	0x03
#define CP_CHUNK_FD_MAXFD	0x04

struct cp_misc {
	char *cmdline;
	char *cwd;
	char *env;
};

struct cp_regs {
	struct user *user_data;
	int stopped;
};

struct cp_i387_data {
	struct user_i387_struct* i387_data;
};

struct cp_tls {
	struct user_desc* u;
};

struct cp_vma {
    long start, length;
    int prot;
    int flags;
    int dev;
    long pg_off;
    long inode;
    char *filename;
    char have_data;
    char is_heap;
    unsigned int checksum;
    void* data; /* length end-start */ /* in file, simply true if is data */
};

struct cp_sighand {
	int sig_num;
	struct k_sigaction *ksa;
};

struct cp_console {
    struct termios termios;
};

struct cp_file {
    char *filename;
    int mode;
    char *contents;
};

struct cp_socket_tcp {
	struct sockaddr_in sin;
	void *ici; /* If the system supports tcpcp. */
};

struct cp_socket_udp {
	struct sockaddr_in sin;
};

struct cp_socket_unix {
	struct sockaddr_un sun;
};

struct cp_socket {
	int proto;
	union {
		struct cp_socket_tcp s_tcp;
		struct cp_socket_udp s_udp;
		struct cp_socket_unix s_unix;
	};
};

struct cp_fd {
	int fd;
	int mode;
	int close_on_exec;
	int fcntl_status;
	off_t offset;
	int type;
	union {
		struct cp_console console;
		struct cp_file file;
		struct cp_socket socket;
	};
};

struct cp_chunk {
	int type;
	union {
		struct cp_misc misc;
		struct cp_regs regs;
		struct cp_i387_data i387_data;
		struct cp_tls tls;
		struct cp_fd fd;
		struct cp_vma vma;
		struct cp_sighand sighand;
	};
};

struct stream_ops {
    void *(*init)(int fd, int mode);
    void (*finish)(void *data);
    int (*read)(void *data, void *buf, int len);
    int (*write)(void *data, void *buf, int len);
    void (*dup2)(void *data, int newfd);
};
extern struct stream_ops *stream_ops;


/* cpimage.c */
void read_bit(void *fptr, void *buf, int len);
void write_bit(void *fptr, void *buf, int len);
char *read_string(void *fptr, char *buf, int maxlen);
void write_string(void *fptr, char *buf);
int read_chunk(void *fptr, struct cp_chunk **chunkp, int load);
void write_chunk(void *fptr, struct cp_chunk *chunk);
void write_process(int fd, struct list l);
void discard_bit(void *fptr, int length);
void get_process(pid_t pid, int flags, struct list *l, long *heap_start);
unsigned int checksum(char *ptr, int len, unsigned int start);

/* cp_misc.c */
void read_chunk_misc(void *fptr, struct cp_misc *data, int load);
void write_chunk_misc(void *fptr, struct cp_misc *data);
void process_chunk_misc(struct cp_misc *data);

/* cp_regs.c */
void read_chunk_regs(void *fptr, struct cp_regs *data, int load);
void write_chunk_regs(void *fptr, struct cp_regs *data);
void fetch_chunks_regs(pid_t pid, int flags, struct list *process_image, int stopped);

/* cp_i387.c */
void read_chunk_i387_data(void *fptr, struct cp_i387_data *data, int load);
void write_chunk_i387_data(void *fptr, struct cp_i387_data *data);
void process_chunk_i387_data(struct cp_i387_data *data);

/* cp_tls.c */
void read_chunk_tls(void *fptr, struct cp_tls *data, int load);
void write_chunk_tls(void *fptr, struct cp_tls *data);
void fetch_chunks_tls(pid_t pid, int flags, struct list *l);
void install_tls_segv_handler();
extern int tls_hack;

/* cp_fd.c */
void read_chunk_fd(void *fptr, struct cp_fd *data, int load);
void write_chunk_fd(void *fptr, struct cp_fd *data);
void fetch_chunks_fd(pid_t pid, int flags, struct list *l);
extern int console_fd;

/* cp_fd_console.c */
void read_chunk_fd_console(void *fptr, struct cp_console *console, int load, int fd);
void write_chunk_fd_console(void *fptr, struct cp_console *console);
void save_fd_console(pid_t pid, int flags, int fd, struct cp_console *console);

/* cp_fd_file.c */
void read_chunk_fd_file(void *fptr, struct cp_file *file, int load, int fd);
void write_chunk_fd_file(void *fptr, struct cp_file *file);
void save_fd_file(pid_t pid, int flags, int fd, int inode, struct cp_file *file);

/* cp_fd_socket.c */
void read_chunk_fd_socket(void *fptr, struct cp_socket *socket, int load, int fd);
void write_chunk_fd_socket(void *fptr, struct cp_socket *socket);
void save_fd_socket(pid_t pid, int flags, int fd, int inode, struct cp_socket *socket);

/* cp_vma.c */
void read_chunk_vma(void *fptr, struct cp_vma *data, int load);
void write_chunk_vma(void *fptr, struct cp_vma *data);
void fetch_chunks_vma(pid_t pid, int flags, struct list *l, long *bin_offset);
extern int extra_prot_flags;
extern long scribble_zone;

/* cp_sighand.c */
void read_chunk_sighand(void *fptr, struct cp_sighand *data, int load);
void write_chunk_sighand(void *fptr, struct cp_sighand *data);
void fetch_chunks_sighand(pid_t pid, int flags, struct list *l);

#endif /* _CPIMAGE_H_ */

/* vim:set ts=8 sw=4 noet: */
