# Work-in-progress cut-down version of pKVM

PicoVM currently provides:

- EL2 setup, including hypervisor stage-1 and host stage-2 page tables;
- handlers for initialization, protection finalization, host memory sharing and
  unsharing, and host memory aborts; and
- page-table mapping, unmapping, ownership, and page-state operations.

The KVM subtree can be built with `make arch/arm64/kvm/`. PicoVM remains a
work in progress: guest VM support is not implemented, and a complete kernel
build and boot should be tested separately for the intended configuration.
