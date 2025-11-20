extern void fulminate_assume_ownership(void* p, unsigned long size, const char* fun, _Bool wildcard);

void fulminate_spec_own_globals(void) {

	fulminate_assume_ownership((void *)(&hyp_nr_cpus), sizeof(unsigned long), __FUNCTION__, false);
	fulminate_assume_ownership((void *)(&hyp_allocator), sizeof(struct hyp_allocator), __FUNCTION__, false);
	fulminate_assume_ownership((void *)(&hyp_physvirt_offset), sizeof(hyp_physvirt_offset), __FUNCTION__, true);

	for (unsigned int i = 0; i < hyp_nr_cpus; i++) {
		unsigned long off = __hyp_per_cpu_offset(i);

		fulminate_assume_ownership(((void *) &hyp_allocator_mc) + off, sizeof(struct kvm_hyp_memcache), __FUNCTION__, true);
		fulminate_assume_ownership(((void *) &hyp_allocator_errno) + off, sizeof(signed int), __FUNCTION__, true);
		fulminate_assume_ownership(((void *) &hyp_allocator_missing_donations) + off, sizeof(u8), __FUNCTION__, true);
	}
}

void fulminate_spec_own_allocator_va(void) {
	struct hyp_allocator *allocator = &hyp_allocator;
	fulminate_assume_ownership((void *)(allocator->start), allocator->size, __FUNCTION__, false);
}
