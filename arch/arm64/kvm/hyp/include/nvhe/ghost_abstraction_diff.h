#ifndef GHOST_ABSTRACTION_DIFF_H
#define GHOST_ABSTRACTION_DIFF_H

#include <nvhe/ghost_compute_abstraction.h>

/*
 * Ghost state diffs:
 * The whole ghost state is arranged as a tree
 * so we duplicate that tree structure with a set of diffs..
 */

#define DIFF_MAX_CHILDREN 16


enum ghost_diff_kind {
	GHOST_DIFF_CONTAINER,

	/**
	 * A pair that didn't match.
	 */
	GHOST_DIFF_PAIR,

	/**
	 * An element that was or wasn't there.
	 */
	GHOST_DIFF_PM,
};

/*
 * I Hate C, so let's just wrap up the common values (u64, bool, char* etc)
 * so can write some half-generic functions.
 */
enum ghost_diff_val_kind {
	Tbool,
	Tu64,
	Tstr,

	/* Plus some more */
	Tmaplet,
};

struct diff_val {
	enum ghost_diff_val_kind kind;
	union {
		bool b;
		u64 n;
		char *s;

		// this is okay to be a reference since the diff is only alive if the two diff'd objects are.
		struct maplet *m;
	};
};
#define TBOOL(value) (struct diff_val){.kind=Tbool, .b=(value)}
#define TU64(value) (struct diff_val){.kind=Tu64, .n=(value)}
#define TSTR(value) (struct diff_val){.kind=Tstr, .s=(value)}
#define TMAPLET(value) (struct diff_val){.kind=Tmaplet, .m=(value)}

struct ghost_diff {
	/**
	 * Invariant: key is either Tu64 (index) or Tstr (field)
	 */
	struct diff_val key;

	enum ghost_diff_kind kind;
	union {
		struct diff_container_data {
			u64 nr_children;
			struct ghost_diff *children[DIFF_MAX_CHILDREN];
		} container;

		struct diff_pair_data {
			struct diff_val lhs;
			struct diff_val rhs;
		} pair;

		struct diff_pm_data {
			/**
			 * whether this is an addition or deletion...
			 */
			bool add;
			struct diff_val val;
		} pm;
	};
};

/* Initialisation */
void ghost_init_diff_memory(void);

/* Creation */
struct ghost_diff *container(void);
struct ghost_diff *normalise(struct ghost_diff *node);

/* Clean up */
void free_diff(struct ghost_diff *node);


/* Attach data to containers */
void ghost_diff_field(struct ghost_diff *container, char *key, struct ghost_diff *child);
void ghost_diff_index(struct ghost_diff *container, u64 key, struct ghost_diff *child);
void ghost_diff_attach(struct ghost_diff *container, struct ghost_diff *child);

struct ghost_diff *diff_pair(struct diff_val lhs, struct diff_val rhs);
struct ghost_diff *diff_pm(bool add, struct diff_val val);

struct ghost_diff *ghost_diff_pgtable(abstract_pgtable *ap1, abstract_pgtable *ap2);

struct ghost_diff *ghost_diff_state(struct ghost_state *s1, struct ghost_state *s2);

/* Printing */
void ghost_print_diff(struct ghost_diff *diff);

#endif /* GHOST_ABSTRACTION_DIFF_H */