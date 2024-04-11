#ifndef GHOST_ABSTRACTION_DIFF_H
#define GHOST_ABSTRACTION_DIFF_H

#include <nvhe/ghost/ghost_types_aux.h>
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
#include <nvhe/ghost/ghost_simplified_model.h>
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */

/* Diffing */
void ghost_diff_and_print_pgtable(abstract_pgtable *ap1, abstract_pgtable *ap2);
void ghost_diff_and_print_state(struct ghost_state *s1, struct ghost_state *s2);
#ifdef CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL
void ghost_diff_and_print_sm_state(struct ghost_simplified_model_state *s1, struct ghost_simplified_model_state *s2);
#endif /* CONFIG_NVHE_GHOST_SIMPLIFIED_MODEL */

#endif /* GHOST_ABSTRACTION_DIFF_H */