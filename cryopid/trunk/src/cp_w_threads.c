#include <bits/types.h>
#include <linux/unistd.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>

#include "cryopid.h"
#include "process.h"
#include "cpimage.h"

void write_chunk_threads(void *fptr, struct cp_threads *data)
{
    write_bit(fptr, data, sizeof(*data));
}

void fetch_chunks_threads(pid_t pid, int flags, struct list *l, struct list *thread_list)
{
    DIR *dir;
    struct dirent *dirent;
    char dirname[80];
    struct cp_chunk *chunk;
    int num_threads = 0;

    snprintf(dirname, sizeof(dirname), "/proc/%d/task/", pid);
    dir = opendir(dirname);
    if (dir != NULL) {
	while ((dirent = readdir(dir)) != NULL) {
	    pid_t tid;
	    char *end;

	    if (strcmp(dirent->d_name, "." ) == 0 ||
		strcmp(dirent->d_name, "..") == 0)
		continue;

	    tid = strtol(dirent->d_name, &end, 10);
	    if (*end != '\0') {
		info("Skipping non-numeric task %s\n", dirent->d_name);
		continue;
	    }
	    if (tid != pid) {
		list_append(thread_list, (void*)tid);
		num_threads++;
	    }
	}
	closedir(dir);
    }
    chunk = xmalloc(sizeof(struct cp_chunk));
    chunk->type = CP_CHUNK_THREADS;
    chunk->threads.num_threads = num_threads;
    list_append(l, chunk);
    fprintf(stderr, "[+] Captured %d threads.\n", num_threads);
}

/* vim:set ts=8 sw=4 noet: */
