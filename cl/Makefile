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

build:
	@echo ... building kernel image
	$(MAKE) -C $(abspath ..) ARCH=arm64 CC=$(CC) CROSS_COMPILE=aarch64-linux-gnu- -j $$(nproc) Image
.PHONY: build

deep-clean: clean-clang clean-pkvm clean-qemu