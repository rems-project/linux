#ifndef GHOST_STATUS_H
#define GHOST_STATUS_H

#include <nvhe/ghost_printer.h>

/**
 * enum ghost_status - Status of an associated field (this is a three-valued generalisation
 *                     of "boot present" fields) in a ghost recorded/computed state
 * @GHOST_ABSENT: for fields which are not present in a recorded or computed state
 * @GHOST_PRESENT: for fields which are present in a recorded or computed state
 * @GHOST_NOT_CHECKED: for field which are not to be checked (this must ONLY be used for computed states)
 */
enum ghost_status {
	GHOST_ABSENT,
	GHOST_PRESENT,
	GHOST_NOT_CHECKED
};

#endif /* GHOST_STATUS_H */
