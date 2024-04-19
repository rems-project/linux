#ifndef GHOST_TRACING_H
#define GHOST_TRACING_H

enum ghost_trace_event {
  GHOST_TRACE_PRE,
  GHOST_TRACE_POST,
  GHOST_TRACE_POST_COMPUTE,
  GHOST_TRACE_POST_CHECK,

  /* top-level functions */
  GHOST_TRACE_record_and_check_abstraction_pkvm_pre,
  GHOST_TRACE_record_and_copy_abstraction_pkvm_post,
  GHOST_TRACE_record_and_check_abstraction_host_pre,
  GHOST_TRACE_record_and_copy_abstraction_host_post,
  GHOST_TRACE_record_abstraction_constants_pre,
  GHOST_TRACE_record_abstraction_constants_post,
  GHOST_TRACE_record_and_check_abstraction_vm_pre,
  GHOST_TRACE_record_and_copy_abstraction_vm_post,
  GHOST_TRACE_record_and_check_abstraction_vms_pre,
  GHOST_TRACE_record_and_copy_abstraction_vms_post,
  GHOST_TRACE_record_and_check_abstraction_local_state_pre,
  GHOST_TRACE_record_and_copy_abstraction_local_state_post,
  GHOST_TRACE_record_abstraction_loaded_vcpu_and_check_none,
};

/*
 * enter/exit of externally-called top-level ghost functions
 *
 * TODO: BS: replace this with for-upstream/pkvm-tracing machinery.
 */

void trace_ghost_enter(enum ghost_trace_event event);
void trace_ghost_exit(enum ghost_trace_event event);

#define GHOST_TRACE_STRING(x)	[GHOST_TRACE_##x] = #x
static const char *ghost_trace_event_names[] = {
  GHOST_TRACE_STRING(PRE),
  GHOST_TRACE_STRING(POST),
  GHOST_TRACE_STRING(POST_COMPUTE),
  GHOST_TRACE_STRING(POST_CHECK),
  GHOST_TRACE_STRING(record_and_check_abstraction_pkvm_pre),
  GHOST_TRACE_STRING(record_and_copy_abstraction_pkvm_post),
  GHOST_TRACE_STRING(record_and_check_abstraction_host_pre),
  GHOST_TRACE_STRING(record_and_copy_abstraction_host_post),
  GHOST_TRACE_STRING(record_abstraction_constants_pre),
  GHOST_TRACE_STRING(record_abstraction_constants_post),
  GHOST_TRACE_STRING(record_and_check_abstraction_vm_pre),
  GHOST_TRACE_STRING(record_and_copy_abstraction_vm_post),
  GHOST_TRACE_STRING(record_and_check_abstraction_vms_pre),
  GHOST_TRACE_STRING(record_and_copy_abstraction_vms_post),
  GHOST_TRACE_STRING(record_and_check_abstraction_local_state_pre),
  GHOST_TRACE_STRING(record_and_copy_abstraction_local_state_post),
  GHOST_TRACE_STRING(record_abstraction_loaded_vcpu_and_check_none),
};

#endif /* GHOST_TRACING_H */