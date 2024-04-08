#include <nvhe/ghost/ghost_status.h>

int gp_put_status(gp_stream_t *out, enum ghost_status s)
{
	switch(s) {
	case GHOST_ABSENT:       return ghost_sprintf(out, "ABSENT");
	case GHOST_PRESENT:      return ghost_sprintf(out, "PRESENT");
	case GHOST_NOT_CHECKED:  return ghost_sprintf(out, "NOT_CHECKED");
	}
}
