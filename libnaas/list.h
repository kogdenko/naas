#ifndef NAAS_COMMON_LIST_H
#define NAAS_COMMON_LIST_H

#include "utils.h"

// Double linked list
struct naas_dlist {
	struct naas_dlist *dls_next;
	struct naas_dlist *dls_prev;
};

#define naas_dlist_entry_rcu(ptr, type, member) \
	naas_container_of(NAAS_READ_ONCE(ptr), type, member)

void naas_dlist_init(struct naas_dlist *);
void naas_dlist_init_rcu(struct naas_dlist *);
int naas_dlist_size(struct naas_dlist *);
int naas_dlist_is_empty(struct naas_dlist *);
struct naas_dlist *naas_dlist_first(struct naas_dlist *);
struct naas_dlist *naas_dlist_last(struct naas_dlist *l);
void naas_dlist_insert_head(struct naas_dlist *, struct naas_dlist *);
void naas_dlist_insert_tail(struct naas_dlist *, struct naas_dlist *);
void naas_dlist_insert_tail_rcu(struct naas_dlist *, struct naas_dlist *);
void naas_dlist_insert_before(struct naas_dlist *, struct naas_dlist *h);
void naas_dlist_insert_after(struct naas_dlist *, struct naas_dlist *);
void naas_dlist_remove(struct naas_dlist *);
void naas_dlist_remove_rcu(struct naas_dlist *);
void naas_dlist_replace(struct naas_dlist *, struct naas_dlist *);
void naas_dlist_replace_init(struct naas_dlist *, struct naas_dlist *);
void naas_dlist_splice_tail(struct naas_dlist *, struct naas_dlist *);
void naas_dlist_splice_tail_init(struct naas_dlist *, struct naas_dlist *);

#define NAAS_DLIST_HEAD_INIT(name) { &name, &name }

#define NAAS_DLIST_HEAD(name) struct naas_dlist name = NAAS_DLIST_HEAD_INIT(name)

#define NAAS_DLIST_FIRST(head, type, field) \
	naas_container_of((head)->dls_next, type, field)

#define NAAS_DLIST_LAST(head, type, field) \
	naas_container_of((head)->dls_prev, type, field)

#define NAAS_DLIST_PREV(var, field) \
	naas_container_of((var)->field.dls_prev, __typeof__(*(var)), field)

#define NAAS_DLIST_NEXT(var, field) \
	naas_container_of((var)->field.dls_next, __typeof__(*(var)), field)

#define NAAS_DLIST_INSERT_HEAD(head, var, field) \
	naas_dlist_insert_head(head, &((var)->field))

#define NAAS_DLIST_INSERT_TAIL(head, var, field) \
	naas_dlist_insert_tail(head, &((var)->field))

#define NAAS_DLIST_INSERT_BEFORE(var, bvar, field) \
	naas_dlist_insert_before(&((var)->field), &((bvar)->field))

#define NAAS_DLIST_INSERT_AFTER(avar, var, field) \
	naas_dlist_insert_after(&((avar)->field), &((var)->field))

#define NAAS_DLIST_REMOVE(var, field) \
	naas_dlist_remove(&(var)->field)

#define naas_dlist_foreach(var, head) \
	for (var = (head)->dls_next; var != (head); var = var->dls_next)

#define NAAS_DLIST_FOREACH(var, head, field) \
	for (var = NAAS_DLIST_FIRST(head, typeof(*(var)), field); \
	     &((var)->field) != (head); \
	     var = NAAS_DLIST_NEXT(var, field))

#define NAAS_DLIST_FOREACH_RCU(var, head, field) \
	for (var = naas_dlist_entry_rcu((head)->dls_next, typeof(*(var)), field); \
	     &var->field != (head); \
	     var = naas_dlist_entry_rcu(var->field.dls_next, typeof(*(var)), field))

#define NAAS_DLIST_FOREACH_CONTINUE(var, head, field) \
	for (; &((var)->field) != (head); var = NAAS_DLIST_NEXT(var, field))

#define NAAS_DLIST_FOREACH_SAFE(var, head, field, tvar) \
	for (var = NAAS_DLIST_FIRST(head, typeof(*(var)), field); \
	     (&((var)->field) != (head)) && \
	     ((tvar = NAAS_DLIST_NEXT(var, field)), 1); \
	     var = tvar)

#endif // NAAS_COMMON_LIST_H
