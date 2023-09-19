#ifndef _GHOST_CONTROL_H
#define _GHOST_CONTROL_H

struct ghost_control {

	_Bool check_handle_host_mem_abort;
	_Bool check_host_stage2_idmap;
	_Bool check___pkvm_host_donate_guest;
	_Bool check___kvm_pgtable_walk;
	_Bool check__kvm_pgtable_walk;
	_Bool check_kvm_pgtable_stage2_map;
	_Bool dump_handle_trap;
	_Bool dump_handle_host_hcall;
	_Bool dump_handle_host_hcall_verbose;
};

extern struct ghost_control ghost_control;

void init_ghost_control(void);

#define GHOST_EXEC_SPEC false

#endif // _GHOST_CONTROL_H
