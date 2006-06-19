#include <bits/types.h>
#include <linux/unistd.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>

#include "cryopid.h"
#include "process.h"
#include "cpimage.h"

void write_chunk_thread(void *fptr, struct cp_thread *data)
{
    write_bit(fptr, &data->tid, sizeof(data->tid));
    write_chunk_tls(fptr, &data->tls->tls);
    write_chunk_regs(fptr, &data->regs->regs);
}

void fetch_chunks_thread(pid_t tid, pid_t pid, int flags, struct list *l)
{
    struct list tmp_list;
    struct cp_chunk *chunk;

    assert(pid != tid);

    /* If pid != tid, we need to trace it */
    start_ptrace(tid, NULL);

    chunk = xmalloc(sizeof(struct cp_chunk));
    chunk->type = CP_CHUNK_THREAD;
    chunk->thread.tid = tid;

    list_init(tmp_list);
    fetch_chunks_regs(tid, flags, &tmp_list, 0);
    chunk->thread.regs = (struct cp_chunk*)tmp_list.head->p;
    xfree(tmp_list.head);

    list_init(tmp_list); 
    fetch_chunks_tls(tid, flags, &tmp_list);
    chunk->thread.tls = (struct cp_chunk*)tmp_list.head->p;
    xfree(tmp_list.head);

    list_append(l, chunk);
    fprintf(stderr, "[+] Captured thread %d.\n", tid);
}

/* vim:set ts=8 sw=4 noet: */
