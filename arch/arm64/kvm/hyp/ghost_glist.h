/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _GHOST_GLIST_H
#define _GHOST_GLIST_H


/*
 * Simple singly linked list implementation, with heads that are structs pointing to first and last nodes (or both NULL for an empty list)
 */


struct glist_head {
	struct glist_node *first, *last; // invariant: equi-NULL,  if (last!=NULL) then last->next==NULL, acyclic
};

struct glist_node {
	struct glist_node *next;
};




/**
 * INIT_GLIST_HEAD - Initialize a list_ghead structure
 * @list: list_head structure to be initialized.
 *
 * Initializes the list_head to an empty list
 */
static inline void INIT_GLIST_HEAD(struct glist_head *list)
{
	WRITE_ONCE(list->first, NULL);
	list->last = NULL;
}


/**
 * glist_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int glist_empty(const struct glist_head *head)
{
	return READ_ONCE(head->first) == NULL;
}




/**
 * glist_add - add a new entry
 * @new: new entry to be added
 * @head: list
 *
 * Insert a new entry at the start of the specified list.
 */
static inline void glist_add(struct glist_node *node, struct glist_head *head)
{
	if (head->first == NULL) {
		node->next = NULL;
		head->first = node;
		head->last = node;
	} else {
		node->next = head->first;
		head->first = node;
	}
}

/**
 * glist_add_to_tail - add a new entry to the tail of a list
 * @new: new entry to be added
 * @head: list
 *
 * Insert a new entry at the end of the specified list.
 */
static inline void glist_add_to_tail(struct glist_node *node, struct glist_head *head)
{
	if (head->first == NULL) {
		node->next = NULL;
		head->first = node;
		head->last = node;
	} else {
		node->next = NULL;
		head->last->next = node;
		head->last = node;
	}
}

/**
 * glist_entry - get the struct for this entry
 * @ptr:	the &struct glist_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the glist_node within the struct.
 */
#define glist_entry(ptr, type, member) \
	container_of(ptr, type, member)

/**
 * glist_first_entry - get the first element of a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the glist_node within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define glist_first_entry(ptr, type, member) \
	glist_entry((ptr)->first, type, member)



/**
 * glist_del - deletes first entry from list (assumed to be non-empty)
 */
static inline void glist_del(struct glist_head *list)
{
	list->first = list->first;
	if (list->first == NULL)
		list->last = NULL;
}



/**
 * glist_move - delete the first node from one list (assumed to be non-empty) and add to another as its head
 * @src: the source list
 * @tgt: the target list
 */
static inline void glist_move(struct glist_head *src,
			      struct glist_head *tgt)
{
	struct glist_node *nxt;
	nxt = src->first->next;
	glist_add(src->first, tgt);
	src->first = nxt;
	if (nxt==NULL)
		src->last = NULL;
}


/**
 * glist_move_to_tail - delete the first node from one list (assumed to be non-empty) and add to another as its tail
 * @src: the source list
 * @tgt: the target list
 */
static inline void glist_move_head_to_tail(struct glist_head *src,
			                   struct glist_head *tgt)
{
	struct glist_node *src_nxt;
	src_nxt = src->first->next;
	glist_add_to_tail(src->first, tgt);
	src->first = src_nxt;
	if (src_nxt==NULL)
		src->last = NULL;
}




/**
 * glist_last_entry - get the last element from a list
 * @ptr:	the list to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the glist_node within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define glist_last_entry(ptr, type, member) \
	glist_entry((ptr)->last, type, member)



/* adapted from https://patchwork.ozlabs.org/project/linux-mtd/patch/5285A393.8000808@oracle.com/ */
/**
 * glist_last_entry_or_null - get the last element from a list
 * @ptr:	the list to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the glist_node within the struct.
 *
 * Note that if the list is empty, it returns NULL.
 */
#define glist_last_entry_or_null(ptr, type, member) \
	(!glist_empty(ptr) ? glist_last_entry(ptr, type, member) : NULL)



/**
 * glist_for_each	-	iterate over a list
 * @pos:	the &struct glist_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define glist_for_each(pos, head) \
	for (pos = (head)->first; pos != NULL; pos = pos->next)




#endif
