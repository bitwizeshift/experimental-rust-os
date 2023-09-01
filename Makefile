###############################################################################
# Inputs
###############################################################################

# The architecture to build (default: x86_64)
ARCH=x86_64

# The location of OVMF (default: "~/VM/<arch>/OVMF.fd")
OVMF_FILE=${HOME}/VM/${ARCH}/OVMF.fd

.PHONY: bootloader run-qemu

bootloader:
	cargo build --target ${ARCH}-unknown-uefi --package bootloader
	mkdir -p build/image/efi/boot
	cp target/${ARCH}-unknown-uefi/debug/bootloader.efi build/image/efi/boot/bootx64.efi

run-qemu: bootloader
	qemu-system-${ARCH}                                                          \
		-drive if=pflash,format=raw,file=${OVMF_FILE}                              \
		-M accel=kvm:tcg                                                           \
		-net none                                                                  \
		-serial stdio                                                              \
		-drive format=raw,file=fat:rw:build/image
