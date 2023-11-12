ARCH = $(shell uname -p)

all: help
.PHONY: all

# path to Linux config script
CONFIG = ../scripts/config
CONFIG_FLAGS = --file ../.config

help:
	@echo "Targets:"
	@echo "	prepare			get and set toolchains"
	@echo "	  clang			get compatible clang, and set CC"
	@echo "	  qemu-host		get qemu images and firmware"
	@echo "	  configure		re-make .config"
	@echo "	 build			re-build pKVM Image"
	@echo "	 deep-clean		clean everything to a fresh start"
	@echo "	  clean-clang		clean downloaded clang (if any)"
	@echo "	  clean-pkvm		clean generated kernel files"
	@echo "	  clean-qemu		clean qemu images and firmware"
.PHONY: help

clang-x86_64: clang/linux-x86/
clang/linux-x86/:
	git clone --depth=1 https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86 clang/linux-x86
	echo '$(abspath ./clang/linux-x86/clang-r498229b/bin/clang)' > CC

clean-clang-x86_64:
	rm -rf clang/linux-x86
.PHONY: clean-clang-x86_64

clang-aarch64:
	echo 'clang-15' > CC

clean-clang-aarch64:

clang: clang-$(ARCH)

clean-clang: clean-clang-$(ARCH)
clean-clang:
	@rm -f CC

CC = $(shell cat CC)

prepare: clang qemu-host clean-pkvm configure
.PHONY: prepare

clean-qemu:
	$(MAKE) -C qemu-host clean
.PHONY: clean-qemu

qemu-host:
	$(MAKE) -C qemu-host
.PHONY: qemu-host

clean-pkvm:
	@echo ... cleaning old pkvm files
	$(MAKE) -C .. clean      # Delete most generated files
					      # but leave enough to build external modules
	$(MAKE) -C .. mrproper   # Delete configuration and all generated files
	$(MAKE) -C .. distclean  # Remove editor backup files, patch leftover files, etc.
.PHONY: clean-pkvm

prepare-container:
	@echo ... getting deps
	sudo sed -i 's/# deb-src/deb-src/' /etc/apt/sources.list
	sudo apt update
	sudo apt-get build-dep -y linux
	sudo apt install -y qemu-system-aarch64
.PHONY: prepare-container

configure:
	@echo ... now run configure
	$(MAKE) -C .. ARCH=arm64 CC=$(CC) CROSS_COMPILE=aarch64-linux-gnu- -j $$(nproc) defconfig

	@echo ... force DWARF4 output
	$(CONFIG) $(CONFIG_FLAGS) -d CONFIG_RANDOMIZE_BASE
	$(CONFIG) $(CONFIG_FLAGS) -e CONFIG_NVHE_EL2_DEBUG
	$(CONFIG) $(CONFIG_FLAGS) -e CONFIG_KVM_ARM_HYP_DEBUG_UART
	$(CONFIG) $(CONFIG_FLAGS) -d CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAUL
	$(CONFIG) $(CONFIG_FLAGS) -e CONFIG_DEBUG_INFO_DWARF4
	$(CONFIG) $(CONFIG_FLAGS) -e CONFIG_PROTECTED_NVHE_STACKTRACE
	$(CONFIG) $(CONFIG_FLAGS) -e CONFIG_KVM_ARM_HYP_DEBUG_UART
	$(CONFIG) $(CONFIG_FLAGS) -e CONFIG_NVHE_GHOST_SPEC
	$(CONFIG) $(CONFIG_FLAGS) --set-val CONFIG_KVM_ARM_HYP_DEBUG_UART_ADDR 0x09000000
	$(CONFIG) $(CONFIG_FLAGS) --set-val CONFIG_NVHE_EL2_STACKSIZE 4
	$(CONFIG) $(CONFIG_FLAGS) --set-val CONFIG_NVHE_GHOST_MEM_LOG2_MB 22
.PHONY: configure

menuconfig:
	$(MAKE) -C .. ARCH=arm64 CC=$(CC) CROSS_COMPILE=aarch64-linux-gnu- menuconfig
.PHONY: menuconfig

build:
	@echo ... building kernel image
	$(MAKE) -C $(abspath ..) ARCH=arm64 CC=$(CC) CROSS_COMPILE=aarch64-linux-gnu- -j $$(nproc) Image
.PHONY: build


# For DataAbort spec, WIP: generate an isla trace
# need isla installed and built.
# assumes it's in a sibling directory to linux-pkvm-verif-2.

ISLA_EXECUTE_FN = ../../isla/target/release/isla-execute-function
ISLA_CONFIG = ./pkvm_isla_config.toml
ISLA_SNAPSHOT = ../../isla-snapshots/armv9.ir
SAIL_SNAPSHOT_SRC = ../../sail-arm/armv9.3-a/src/


# Since ASL doesn't have tagged unions...
SAIL_EXC_RECORD_GPCF_NONE = \
	{ gpf = GPCF_None, \
		level = 0 }

SAIL_EXC_RECORD_ADDR = \
	{ paspace = PAS_NonSecure, \
		address = 0x0000000000000 }

SAIL_EXC_RECORD_GPCF_FIELDS = \
		gpcf = $(SAIL_EXC_RECORD_GPCF_NONE), \
		gpcfs2walk = false

# Construct a FaultRecord struct to pass
SAIL_FAULT_RECORD = \
	{	statuscode = Fault_Translation, \
		acctype = AccType_NORMAL, \
		ipaddress = $(SAIL_EXC_RECORD_ADDR), \
		paddress = $(SAIL_EXC_RECORD_ADDR), \
		$(SAIL_EXC_RECORD_GPCF_FIELDS), \
		s2fs1walk = false, \
		write = false, \
		level = 0, \
		extflag = 0b1, \
		secondstage = false, \
		domain = 0b0000, \
		errortype = 0b00, \
		debugmoe = 0b0000 \
	}

ISLA_FN = \
		AArch64_DataAbort \
		0x0000000000FF0000 \
		'$(SAIL_FAULT_RECORD)'

ISLA_EXECUTE_FN_EXTRA_ARGS =

generate-DataAbort-trace:
	$(ISLA_EXECUTE_FN) \
		-A $(ISLA_SNAPSHOT) \
		-S $(SAIL_SNAPSHOT_SRC) \
		-C $(ISLA_CONFIG) \
		-R "PSTATE.EL=0b01" \
		--simplify --simplify-registers --no-model-reg-init \
		$(ISLA_FN) --traces
.PHONY: generate-DataAbort-trace

deep-clean: clean-clang clean-pkvm clean-qemu