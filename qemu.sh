#!/bin/bash

set -e

cd "$(dirname $0)"

cp -f target/x86_64-unknown-uefi/release/bsdloader.efi ./esp/efi/boot/bootx64.efi
cp -f kernel.elf ./esp/kernel.elf
echo -e 'hw.uart.console=io:0x3f8,br:115200\nconsole=efi comconsole' > ./esp/kenv

swtpm socket --tpmstate dir=/tmp/mytpm1 \
  --ctrl type=unixio,path=/tmp/mytpm1/swtpm-sock \
  --tpm2 \
  --log level=1 &

qemu-system-x86_64 -enable-kvm \
    -m 1024 \
    -smp 2 \
    -cpu host \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_VARS.fd \
    -drive format=raw,file=fat:rw:esp \
    -chardev socket,id=chrtpm,path=/tmp/mytpm1/swtpm-sock \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    -netdev user,id=hn0,net=192.168.76.0/24,dhcpstart=192.168.76.10 \
    -device virtio-net-pci,netdev=hn0,id=nic1,romfile="" \
    -serial mon:stdio \
    -display none -vnc :0
    # -nographic
