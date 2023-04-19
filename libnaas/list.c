#include <assert.h>
#include "list.h"

void
naas_dlist_init(struct naas_dlist *head)
{
	head->dls_next = head->dls_prev = head;
}

int
naas_dlist_size(struct naas_dlist *head)
{
	int size;
	struct naas_dlist *cur;

	size = 0;
	naas_dlist_foreach(cur, head) {
		size++;
	}
	return size;
}

int
naas_dlist_is_empty(struct naas_dlist *head)
{
	return head->dls_next == head;
}

struct naas_dlist *
naas_dlist_first(struct naas_dlist *head)
{
	return head->dls_next;
}

struct naas_dlist *
naas_dlist_last(struct naas_dlist *head)
{
	return head->dls_prev;
}

void
naas_dlist_insert_head(struct naas_dlist *head, struct naas_dlist *l)
{
	l->dls_next = head->dls_next;
	l->dls_prev = head;
	head->dls_next->dls_prev = l;
	head->dls_next = l;
}

void
naas_dlist_insert_tail(struct naas_dlist *head, struct naas_dlist *l)
{
	l->dls_next = head;
	l->dls_prev = head->dls_prev;
	head->dls_prev->dls_next = l;
	head->dls_prev = l;
}

void
naas_dlist_insert_tail_rcu(struct naas_dlist *head, struct naas_dlist *l)
{
	l->dls_next = head;
	l->dls_prev = head->dls_prev;
	naas_rcu_assign_pointer(head->dls_prev->dls_next, l);
	head->dls_prev = l;
}

void
naas_dlist_insert_before(struct naas_dlist *l, struct naas_dlist *b)
{
	l->dls_next = b;
	l->dls_prev = b->dls_prev;
	b->dls_prev->dls_next = l;
	b->dls_prev = l;
}

void
naas_dlist_insert_after(struct naas_dlist *a, struct naas_dlist *l)
{
	l->dls_prev = a;
	l->dls_next = a->dls_next;
	a->dls_next->dls_prev = l;
	a->dls_next = l;
}

void
naas_dlist_remove(struct naas_dlist *list)
{
	list->dls_next->dls_prev = list->dls_prev;
	list->dls_prev->dls_next = list->dls_next;
}

void
naas_dlist_remove_rcu(struct naas_dlist *list)
{
	list->dls_next->dls_prev = list->dls_prev;
	NAAS_WRITE_ONCE(list->dls_prev->dls_next, list->dls_next);
}

void
naas_dlist_replace(struct naas_dlist *new, struct naas_dlist *old)
{
	new->dls_next = old->dls_next;
	new->dls_next->dls_prev = new;
	new->dls_prev = old->dls_prev;
	new->dls_prev->dls_next = new;
}

void
naas_dlist_replace_init(struct naas_dlist *new, struct naas_dlist *old)
{
	naas_dlist_replace(new, old);
	naas_dlist_init(old);	
}

// prev <-> {list} <-> next
void
naas_dlist_splice(struct naas_dlist *prev, struct naas_dlist *next, struct naas_dlist *list)
{
	list->dls_next->dls_prev = prev;
	prev->dls_next = list->dls_next;
	list->dls_prev->dls_next = next;
	next->dls_prev = list->dls_prev;
}

void
naas_dlist_splice_tail_init(struct naas_dlist *dst, struct naas_dlist *src)
{
	assert(!naas_dlist_is_empty(src));
	naas_dlist_splice(dst->dls_prev, dst, src);
	naas_dlist_init(src);
}
