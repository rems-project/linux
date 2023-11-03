DEB_ISO = debian-12.2.0-arm64-netinst.iso
EFI_DEB = qemu-efi-aarch64_2023.08-1_all.deb
EFI_LOC = /usr/share/qemu-efi-aarch64/QEMU_EFI.fd

all: disk.img $(DEB_ISO) firmware/
.PHONY: all

clean: clean-firmware clean-install-media clean-disk
.PHONY: clean

clean-firmware:
	rm -rf firmware/
.PHONY: clean-firmware

clean-install-media:
	rm -rf $(DEB_ISO)
.PHONY: clean-install-media

clean-disk:
	rm -f disk.img
.PHONY: clean-disk

disk.img:
	qemu-img create -f qcow2 disk.img 16G

$(DEB_ISO):
	wget https://cdimage.debian.org/debian-cd/current/arm64/iso-cd/$(DEB_ISO)

firmware/:
	@mkdir firmware/
	cd firmware && { \
		wget http://ftp.de.debian.org/debian/pool/main/e/edk2/$(EFI_DEB); \
		ar -x $(EFI_DEB); \
		tar xf data.tar.xz; \
		truncate -s 64m varstore.img; \
		truncate -s 64m efi.img; \
		dd if=$(EFI_LOC) of=efi.img conv=notrunc; \
	}