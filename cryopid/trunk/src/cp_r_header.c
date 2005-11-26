
#include "cryopid.h"
#include "cpimage.h"

void read_chunk_header(void *fptr, int action)
{
    struct cp_header header;
    int *children_offsets;
    read_bit(fptr, &header, sizeof(struct cp_header));
    while (header.n_children--) {
	struct cp_header child;
    }
}

/* vim:set ts=8 sw=4 noet: */
