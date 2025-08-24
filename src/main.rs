#![no_main]
#![no_std]

extern crate alloc;

mod boot;
mod image_loader;
mod modinfo;
mod staging;
mod tpm;
mod util;

use alloc::{borrow::Cow, collections::btree_map::BTreeMap};
use alloc::{format, vec};
use boot::{boot_kernel, load_elf};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use image_loader::{load_image_from_disk, OwnedBuffer};
use sha2::{Digest, Sha256};
use staging::StagingRegion;
use tpm::measure_image;
use uefi::boot::AllocateType;
use uefi::{prelude::*, proto::tcg::PcrIndex};

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();

    log::info!("Starting...");

    let mut staging = StagingRegion::new();

    let mut kernel_load_region = staging.allocate(50 * 1048576);

    let kernel_buffer = staging.size() - 70 * 1048576;
    let mut kernel_buffer = staging.allocate(kernel_buffer);
    let kernel_buffer_len =
        load_image_from_disk("kernel.elf", &mut kernel_buffer[..]).expect("kernel.elf not found");
    let mut kernel_buffer = staging.shrink(kernel_buffer, kernel_buffer_len);
    measure_image(&kernel_buffer[..], PcrIndex(9), b"kernel.elf\0");
    let kernel_sha256 = Sha256::digest(&kernel_buffer[..]);

    let kenv_sha256;
    let kenv = {
        let kenv_buffer =
            OwnedBuffer::new(AllocateType::MaxAddress(0x1_0000_0000u64), 16384).leak();
        let kenv_buffer_len =
            load_image_from_disk("kenv", &mut kenv_buffer[..]).unwrap_or_default();
        let kenv_buffer_len = if kenv_buffer_len == 0 {
            kenv_buffer[0] = b'\n';
            1
        } else {
            kenv_buffer_len
        };
        let kenv_buffer = &kenv_buffer[..kenv_buffer_len];
        kenv_sha256 = Sha256::digest(kenv_buffer);
        measure_image(&kenv_buffer[..], PcrIndex(9), b"kenv\0");
        parse_kenv(&kenv_buffer[..])
    };

    let mut siginfo = vec![0u8; 256];
    let public_key: [u8; 32] = if let Some(n) = load_image_from_disk("siginfo", &mut siginfo) {
        let mut kernel_sha256_str = [0u8; 64];
        hex::encode_to_slice(&kernel_sha256, &mut kernel_sha256_str).unwrap();
        let kernel_sha256_str = core::str::from_utf8(&kernel_sha256_str).unwrap();

        let mut kenv_sha256_str = [0u8; 64];
        hex::encode_to_slice(&kenv_sha256, &mut kenv_sha256_str).unwrap();
        let kenv_sha256_str = core::str::from_utf8(&kenv_sha256_str).unwrap();

        let manifest = format!(
            "{}  kernel.elf\n{}  kenv\n",
            kernel_sha256_str, kenv_sha256_str
        );

        let mut siginfo = core::str::from_utf8(&siginfo[..n])
            .expect("siginfo is not valid utf-8")
            .split('\n');
        let mut public_key = [0u8; 32];
        let mut signature = [0u8; 64];
        hex::decode_to_slice(
            siginfo.next().expect("missing public key").as_bytes(),
            &mut public_key,
        )
        .expect("invalid public key");
        hex::decode_to_slice(
            siginfo.next().expect("missing signature").as_bytes(),
            &mut signature,
        )
        .expect("invalid signature");
        VerifyingKey::from_bytes(&public_key)
            .expect("public key is not valid ed25519 point")
            .verify(manifest.as_bytes(), &Signature::from_bytes(&signature))
            .expect("signature verification failed");
        public_key
    } else {
        [0u8; 32]
    };

    let mut public_key_hex = [0u8; 64];
    hex::encode_to_slice(&public_key, &mut public_key_hex).unwrap();
    let public_key_hex = core::str::from_utf8(&public_key_hex).unwrap();
    let public_key_desc = format!("ed25519-{}", public_key_hex).into_bytes();
    measure_image(&public_key_desc, PcrIndex(14), &public_key_desc);

    let kernel_elf = load_elf(&mut kernel_load_region, &kernel_buffer);
    let memdisk = if let Some((offset, size)) = kernel_elf.memdisk_file_range {
        kernel_buffer.copy_within(offset as usize..(offset + size) as usize, 0);
        Some(staging.shrink(kernel_buffer, size as usize))
    } else {
        staging.shrink(kernel_buffer, 0);
        None
    };

    match boot_kernel(staging, kernel_elf, memdisk, kenv) {
        Ok(x) => match x {},
        Err(e) => {
            log::error!("Failed to boot kernel: {}", e);
            return Status::ABORTED;
        }
    }
}

fn parse_kenv(raw: &'static [u8]) -> BTreeMap<Cow<'static, str>, Cow<'static, str>> {
    let raw = core::str::from_utf8(raw).unwrap_or_default();
    let mut out: BTreeMap<Cow<str>, Cow<str>> = BTreeMap::new();

    for line in raw.lines().map(|x| x.trim()).filter(|x| !x.is_empty()) {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        out.insert(Cow::Borrowed(k), Cow::Borrowed(v));
    }

    out
}
