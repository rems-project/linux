# Work-in-progress cut down version of pKVM

Current status:

1. Can build the kvm module (`make arch/arm64/kvm/`), but not a whole kernel (because we are missing some HYP setup symbols for now)
2. There is no setup code at all, so it wouldn't boot anyway
3. There are handlers for the following hcalls and aborts:
	* `host_share_hyp`
	* `host_unshare_hyp`
	* (SOON) `host_mem_abort`

4. The page manipulation code is not yet written.