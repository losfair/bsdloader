# bsdloader

Minimal (~103KB) x86_64 FreeBSD UEFI loader. Supports preloaded memory disk and UEFI
TPM2.0 measured boot.

## Usage

```bash
# Directory layout: /base /kernel /bsdloader
# 'base' contains extracted FreeBSD base.txz - ideally a minimal one like mfsBSD
# 'kernel' contains extracted FreeBSD kernel.txz

# Build bsdloader
mkdir -p esp/efi/boot
cd bsdloader
cargo build --release
cp ./target/x86_64-unknown-uefi/release/bsdloader.efi ../esp/efi/boot/bootx64.efi
cd ..

# Build UFS2 rootfs memory disk image
makefs -t ffs base.ufs base

# Write the rootfs memory disk image into the ".memdisk" section of `kernel.elf`.
#
# bsdloader reads this section and preloads the memory disk as `/dev/md0`. The FreeBSD
# kernel will automatically boot from it.
llvm-objcopy --add-section .memdisk=base.ufs kernel/boot/kernel/kernel esp/kernel.elf

# Optionally, add some kernel environment variables
echo -e 'hw.uart.console=io:0x3f8,br:115200\nconsole=efi comconsole' > ./esp/kenv

# Copy the contents of `esp/` into a FAT32-formatted partition. It's now bootable!
```

## Measured boot

If TPM2 is present, bsdloader measures `kernel.elf` and `kenv` into PCR9 as
`EV_IPL` events, and mounts the TPM2 event log as the second memory disk
accessible at `/dev/md1`. Measurements and the event log can be accessed from
userspace:

```bash
kldload tpm

# Read PCRs
tpm2_pcrread

# Show the event log
tpm2_eventlog /dev/md1
```

Note: If `kenv` does not exist or is empty, the measurement is taken on the
string with a single newline: `\n`.
