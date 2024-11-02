# bsdloader

Minimal (~123KB), reproducible x86_64 FreeBSD UEFI loader. Supports preloaded
memory disk and UEFI TPM2.0 measured boot.

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

If TPM2 is present, bsdloader measures `kernel.elf` and `kenv` into **PCR9** as
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

## Signing `kernel.elf` and `kenv`

bsdloader supports verifying Ed25519 signatures on `kernel.elf` and `kenv` and
measuring the public key into **PCR14**. The public key and signature should be
hex-encoded and written to a file named `siginfo`. The first line of the file is
the 32-byte public key, and the second line is the 64-byte signature. An
example:

```
28ebc78dc763971bf56dde160f8e30f7e9e98ad358d9add73245f05d1b3337fc
6133c1fea385f900f5cf0835838665f616bb725090a93aa6276288319b8c2c43909b4acee0f8457351212d35c614d95d238a69ac5e5409ffa9e78067af0dc349
```

PCR14 is **always** extended. If the `siginfo` file does not exist, a fake
"public key" of 32 zeros is used.

To construct the payload for signing, use the following script as a reference:

```bash
sha256sum kernel.elf > payload
sha256sum kenv >> payload
cat payload
```

The payload should look like:

```
1f825899d834c8132c05a95d70e1544367a35208c275f4af608fd633d9cf0b31  kernel.elf
f87dd3bf8425f28aa1b17888c67d64314cd0609dd39ecdef83fcbcc3c53abf76  kenv
```

Note that there is a `\n` character at the end of each line.
