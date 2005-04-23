#include "cryopid.h"
#include "list.h"

void list_add(struct list *l, void *p) {
	if (l->tail == NULL) {
		l->head = l->tail = xmalloc(sizeof(struct item));
		l->tail->next = NULL;
		l->tail->p = p;
	} else {
		l->tail->next = xmalloc(sizeof(struct item));
		l->tail->next->p = p;
		l->tail->next->next = NULL;
		l->tail = l->tail->next;
	}
}

/* vim:set ts=8 sw=4 noet: */
