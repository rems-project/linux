ARCH = $(shell uname -p)
include clang/Makefile-$(ARCH)

# path to Linux config script
CONFIG = ../scripts/config
CONFIG_FLAGS = --file ../.config

all:
.PHONY: all

prepare: clang qemu-host get-deps clean-pkvm configure
.PHONY: prepare

clean-qemu:
	$(MAKE) -C qemu-host clean
.PHONY: clean-qemu

clean: clean-qemu

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

get-deps:
	@echo ... getting deps
	sudo sed -i 's/# deb-src/deb-src/' /etc/apt/sources.list
	sudo apt update
	sudo apt-get build-dep -y linux
	sudo apt install -y qemu-system-aarch64
.PHONY: get-deps

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
	$(CONFIG) $(CONFIG_FLAGS) --set-val CONFIG_KVM_ARM_HYP_DEBUG_UART_ADDR 0x09000000
	$(CONFIG) $(CONFIG_FLAGS) --set-val CONFIG_NVHE_EL2_STACKSIZE 1000
.PHONY: configure

build:
	@echo ... building kernel
	$(MAKE) -C $(abspath ..) ARCH=arm64 CC=$(CC) CROSS_COMPILE=aarch64-linux-gnu- -j $$(nproc)
.PHONY: build
