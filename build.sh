#!/bin/bash

set -e

cd "$(dirname $0)"

rustflags="build.rustflags=[\"--remap-path-prefix\", \"$HOME/.cargo=.cargo\", \"--remap-path-prefix\", \"$PWD=project\"]"
out="target/x86_64-unknown-uefi/release/bsdloader.efi"

mkdir -p dist

# OpenBSD/amd64 backend
cargo build --release --locked --no-default-features --features openbsd --config "$rustflags"
cp -f "$out" dist/bsdloader-openbsd.efi

# FreeBSD/amd64 backend
cargo build --release --locked --no-default-features --features freebsd --config "$rustflags"
cp -f "$out" dist/bsdloader-freebsd.efi

ls -l dist/
