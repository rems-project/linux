/*@

type_synonym phys = { u64 addr }
type_synonym host_ipa = { u64 addr }
type_synonym guest_ipa = { u64 addr }
type_synonym host_va = { u64 addr }
type_synonym hyp_va = { u64 addr }

datatype ghost_host_or_hyp {
	GHOST_HOST {},
	GHOST_HYP {}
}


function (ghost_state) add_return (ghost_state g, i32 ret) {
	let g' = ghost_write_gpr (g, 1, ret);
	copy_registers_to_host(g')
}

function (ghost_state) compute_new_abstract_state_handle___pkvm_host_share_hyp (
	ghost_state g0,
	ghost_call_data call
) {
	let pfn = ghost_read_gpr(g0, 1); // u64 pfn
	let phys = hyp_pfn_to_phys(pfn); // phys_addr_t phys
	let host_addr = host_ipa_of_phys(phys); // host_ipa
	let hyp_addr = hyp_va_of_phys(g0, phys); // hyp_va_t hyp_addr

        if (!is_owned_exclusively_by(g0, GHOST_HOST {}, phys)) {
		add_return(g0, -EPERM)
	}

}

@*/