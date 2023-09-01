###############################################################################
# Inputs
###############################################################################

# The architecture to build (default: x86_64)
ifeq (${ARCH},)
  ARCH=x86_64
endif

BOOT_EFI=bootx64.efi
ifeq (${ARCH},aarch64)
  BOOT_EFI=bootaa64.efi
endif

BUILD_DIR=build/${ARCH}

###############################################################################
# Utility
###############################################################################

.PHONY: clean
clean:
	rm -r build/${ARCH}

###############################################################################
# OVMF
###############################################################################

build/x86_64/ovmf/edk2.rpm:
	mkdir -p build/x86_64/ovmf
	curl https://www.kraxel.org/repos/jenkins/edk2/edk2.git-ovmf-x64-0-20220719.209.gf0064ac3af.EOL.no.nore.updates.noarch.rpm > build/x86_64/ovmf/edk2.rpm

build/x86_64/OVMF.fd: build/x86_64/ovmf/edk2.rpm
	tar -x --file build/x86_64/ovmf/edk2.rpm --cd build/x86_64/ovmf
	cp build/x86_64/ovmf/usr/share/edk2.git/ovmf-x64/OVMF-pure-efi.fd build/x86_64/OVMF.fd

build/aarch64/OVMF.fd:
	mkdir -p build/aarch64/ovmf
	cd build/aarch64/ovmf && \
		wget http://snapshots.linaro.org/components/kernel/leg-virt-tianocore-edk2-upstream/latest/QEMU-AARCH64/RELEASE_GCC5/QEMU_EFI.img.gz &&\
		gunzip QEMU_EFI.img.gz
	cp build/aarch64/ovmf/QEMU_EFI.img build/aarch64/OVMF.fd

.PHONY: install-ovmf
install-ovmf: build/${ARCH}/OVMF.fd

###############################################################################
# Bootloader
###############################################################################

target/${ARCH}-unknown-uefi/debug/bootloader.efi:
	cargo build --target ${ARCH}-unknown-uefi --package bootloader

build/${ARCH}/image/efi/boot/${BOOT_EFI}: target/${ARCH}-unknown-uefi/debug/bootloader.efi
	mkdir -p build/${ARCH}/image/efi/boot
	cp target/${ARCH}-unknown-uefi/debug/bootloader.efi build/${ARCH}/image/efi/boot/${BOOT_EFI}

.PHONY: bootloader
bootloader: build/${ARCH}/image/efi/boot/${BOOT_EFI}

###############################################################################
# Testing
###############################################################################

.PHONY: run-qemu-${ARCH} run-qemu
run-qemu-x86_64: bootloader build/x86_64/OVMF.fd
	qemu-system-x86_64                                                           \
		-bios build/x86_64/OVMF.fd                                                 \
		-machine accel=kvm:tcg                                                     \
		-net none                                                                  \
		-serial stdio                                                              \
		-m 1G                                                                      \
		-smp 8                                                                     \
		-drive format=raw,file=fat:rw:build/x86_64/image

build/aarch64/varstore.img:
	qemu-img create -f qcow2 build/aarch64/varstore.img 64M

run-qemu-aarch64: bootloader build/aarch64/OVMF.fd build/aarch64/varstore.img
	qemu-system-aarch64                                                          \
		-machine virt                                                              \
		-net none                                                                  \
		-cpu max                                                                   \
		-serial stdio                                                              \
		-m 1G                                                                      \
		-smp 8                                                                     \
		-drive if=pflash,id=drive0,format=raw,file=build/aarch64/OVMF.fd           \
		-drive if=pflash,id=drive1,file=build/aarch64/varstore.img                 \
		-drive if=virtio,id=drive2,format=raw,file=fat:rw:build/aarch64/image

run-qemu: run-qemu-${ARCH}
