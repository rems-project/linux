#ifndef _GHOST_CONTROL_H
#define _GHOST_CONTROL_H

#include <linux/types.h>


bool ghost_control_is_controlled(const char* context);
bool ghost_control_print_enabled(const char* context);
bool ghost_control_print_enabled_verbose(const char* context);
bool ghost_control_check_enabled(const char* context);

void init_ghost_control(void);

#define GHOST_EXEC_SPEC true

#endif // _GHOST_CONTROL_H
