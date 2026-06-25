# bsdloader

Minimal, reproducible x86_64 UEFI loader for **FreeBSD** and **OpenBSD**, with
optional UEFI TPM2.0 measured boot and Ed25519 signature verification.

bsdloader has two mutually-exclusive backends, selected at build time by a
Cargo feature. There is **no default feature** — you must pick one:

| Feature   | Boots                          | Handoff                              |
| --------- | ------------------------------ | ------------------------------------ |
| `openbsd` | `bsd.rd` / `bsd` (OpenBSD)     | OpenBSD `bootarg32` + `run_i386`     |
| `freebsd` | `kernel.elf` + memdisk         | FreeBSD `modinfo` trampoline         |

```bash
# Build the OpenBSD backend
cargo build --release --no-default-features --features openbsd

# Build the FreeBSD backend
cargo build --release --no-default-features --features freebsd

# Reproducible build of BOTH variants into dist/
#   dist/bsdloader-openbsd.efi
#   dist/bsdloader-freebsd.efi
./build.sh
```

The output is `target/x86_64-unknown-uefi/release/bsdloader.efi`; rename it to
`EFI/BOOT/BOOTX64.EFI` on a FAT32 EFI System Partition to make it bootable.

---

## OpenBSD backend

The OpenBSD backend loads an OpenBSD/amd64 kernel the way OpenBSD's native EFI
`boot(8)` does:

- reads `bsd.rd` (or `bsd`) from the ESP — plain ELF **or** gzip-compressed;
- places it in a 64 MiB EFI staging region below 256 MiB using OpenBSD
  `LOADADDR()` semantics, handling `PT_LOAD`, BSS, `PT_OPENBSD_RANDOMIZE`
  (filled via **RDRAND**), symbols and section headers (`LOAD_ALL`);
- builds the OpenBSD 32-bit bootarg vector: `BOOTARG_MEMMAP` (BIOS-style memory
  map derived from the EFI map), `BOOTARG_EFIINFO` (ACPI/SMBIOS/system table /
  GOP framebuffer / EFI memory map, `BEI_64BIT`), `BOOTARG_CONSDEV` and
  `BOOTARG_BOOTDUID`;
- exits boot services, moves the kernel to its final low physical address, and
  enters it through a `run_i386`-style trampoline that drops out of long mode
  into a 32-bit environment and calls the kernel `start()`.

### ESP layout

```text
EFI/BOOT/BOOTX64.EFI    # bsdloader (openbsd feature)
bsd.rd                  # OpenBSD ramdisk kernel (gzip or plain ELF)
siginfo                 # optional Ed25519 public key + signature (see below)
```

The console is the serial port **com0 @ 115200** (`BOOTARG_CONSDEV`), so the
kernel and installer come up on the first UART.

### Booting under QEMU/OVMF

```bash
# Place BOOTX64.EFI and bsd.rd on a FAT image, then:
qemu-system-x86_64 -enable-kvm -m 1024 -cpu host \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/edk2/ovmf/OVMF_CODE.fd \
    -drive if=pflash,format=raw,file=OVMF_VARS.fd \
    -drive format=raw,file=esp.img \
    -nographic
```

This reaches the OpenBSD installer prompt
(`(I)nstall, (U)pgrade, (A)utoinstall or (S)hell?`) over serial.

> Note: `RDRAND` is required (used to seed `PT_OPENBSD_RANDOMIZE`). Use
> `-cpu host` (or any model that exposes `rdrand`).

---

## FreeBSD backend

```bash
# Directory layout: /base /kernel /bsdloader
# 'base' contains extracted FreeBSD base.txz - ideally a minimal one like mfsBSD
# 'kernel' contains extracted FreeBSD kernel.txz

mkdir -p esp/efi/boot
cargo build --release --no-default-features --features freebsd
cp ./target/x86_64-unknown-uefi/release/bsdloader.efi ./esp/efi/boot/bootx64.efi

# Build UFS2 rootfs memory disk image
makefs -t ffs base.ufs base

# Embed the rootfs into the ".memdisk" section of kernel.elf; bsdloader
# preloads it as /dev/md0 and the FreeBSD kernel boots from it.
llvm-objcopy --add-section .memdisk=base.ufs kernel/boot/kernel/kernel esp/kernel.elf

# Optionally, add some kernel environment variables
echo -e 'hw.uart.console=io:0x3f8,br:115200\nconsole=efi comconsole' > ./esp/kenv

# Copy the contents of esp/ into a FAT32 partition. It's now bootable!
```

---

## Measured boot

If a UEFI TPM2 is present, bsdloader extends measurements **before**
ExitBootServices. If no TPM is present the measurements are silently skipped and
boot proceeds.

### OpenBSD backend — what is measured

| PCR    | Event                | Contents                                                        |
| ------ | -------------------- | --------------------------------------------------------------- |
| **9**  | `EV_IPL` (`bsd.rd`)  | the `bsd.rd` file **exactly as stored on the ESP** (pre-gunzip) |
| **14** | `EV_IPL`             | `ed25519-<hex public key>` (the signing-key policy in use)      |

PCR 14 is **always** extended. If no `siginfo` file is present, a "public key"
of 32 zero bytes is used, so the PCR value distinguishes "unsigned" from a
specific key.

### FreeBSD backend — what is measured

| PCR    | Event               | Contents                              |
| ------ | ------------------- | ------------------------------------- |
| **9**  | `EV_IPL`            | `kernel.elf`, then `kenv`             |
| **14** | `EV_IPL`            | `ed25519-<hex public key>`            |

The FreeBSD backend additionally exposes the TPM2 event log as a memory disk at
`/dev/md1`:

```bash
kldload tpm
tpm2_pcrread             # read PCRs
tpm2_eventlog /dev/md1   # show the event log
```

If `kenv` does not exist or is empty, the measurement is taken on a single
newline (`\n`).

## Signature verification

Both backends verify an Ed25519 signature over a `sha256sum`-style manifest of
the kernel image, read from a file named `siginfo` on the ESP. The first line is
the hex-encoded 32-byte public key; the second is the hex-encoded 64-byte
signature. If `siginfo` is present and verification fails, boot is aborted.

The signed manifest differs per backend:

```text
# openbsd
<sha256(bsd.rd)>  bsd.rd

# freebsd
<sha256(kernel.elf)>  kernel.elf
<sha256(kenv)>  kenv
```

(each line is newline-terminated). Example signing flow for the OpenBSD backend:

```bash
printf '%s  bsd.rd\n' "$(sha256sum bsd.rd | head -c 64)" > manifest
sk="$(openssl genpkey -algorithm Ed25519)"
openssl pkey -in <(echo "$sk") -pubout -outform DER | tail -c 32 | xxd -p | tr -d '\n' > siginfo
echo >> siginfo
openssl pkeyutl -sign -inkey <(echo "$sk") -rawin -in manifest | xxd -p | tr -d '\n' >> siginfo
echo >> siginfo
```

A resulting `siginfo` looks like:

```text
28ebc78dc763971bf56dde160f8e30f7e9e98ad358d9add73245f05d1b3337fc
6133c1fea385f900f5cf0835838665f616bb725090a93aa6276288319b8c2c43909b4acee0f8457351212d35c614d95d238a69ac5e5409ffa9e78067af0dc349
```
