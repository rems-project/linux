ARCH = $(shell uname -p)
include clang/Makefile-$(ARCH)

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
	sed -i 's/CONFIG_RANDOMIZE_BASE=y/# CONFIG_RANDOMIZE_BASE is not set/' ../.config
	sed -i 's/# CONFIG_NVHE_EL2_DEBUG is not set/CONFIG_NVHE_EL2_DEBUG=y/' ../.config
	sed -i 's/# CONFIG_KVM_ARM_HYP_DEBUG_UART is not set/CONFIG_KVM_ARM_HYP_DEBUG_UART=y/' ../.config
	sed -i 's/CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y/# CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT is not set/' ../.config
	sed -i 's/# CONFIG_DEBUG_INFO_DWARF4 is not set/CONFIG_DEBUG_INFO_DWARF4=y/' ../.config
	echo 'CONFIG_PROTECTED_NVHE_STACKTRACE=y' >> ../.config
#	echo 'CONFIG_KVM_ARM_HYP_DEBUG_UART=y' >> ../.config
#	echo 'CONFIG_KVM_ARM_HYP_DEBUG_UART_ADDR=0x09000000' >> ../.config
.PHONY: configure

build:
	@echo ... building kernel
	$(MAKE) -C $(abspath ..) ARCH=arm64 CC=$(CC) CROSS_COMPILE=aarch64-linux-gnu- -j $$(nproc)
.PHONY: build
