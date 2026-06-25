#!/bin/bash

set -e

cd "$(dirname $0)"

# When the `rust-src` component is installed, rustc embeds std/core source
# paths as "<sysroot>/lib/rustlib/src/rust/..." instead of the virtual
# "/rustc/<commit>/..." used by the precompiled std. Remap it back to that
# virtual path so the build is byte-identical whether or not rust-src is present
# (and regardless of $HOME).
rust_src="$(rustc --print sysroot)/lib/rustlib/src/rust"
rust_commit="$(rustc --version --verbose | sed -n 's/^commit-hash: //p')"

rustflags="build.rustflags=[\"--remap-path-prefix\", \"$HOME/.cargo=.cargo\", \"--remap-path-prefix\", \"$PWD=project\", \"--remap-path-prefix\", \"$rust_src=/rustc/$rust_commit\"]"
out="target/x86_64-unknown-uefi/release/bsdloader.efi"

mkdir -p dist

# OpenBSD/amd64 backend
cargo build --release --locked --no-default-features --features openbsd --config "$rustflags"
cp -f "$out" dist/bsdloader-openbsd.efi

# FreeBSD/amd64 backend
cargo build --release --locked --no-default-features --features freebsd --config "$rustflags"
cp -f "$out" dist/bsdloader-freebsd.efi

ls -l dist/
