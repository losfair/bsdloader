use alloc::format;
use alloc::vec;
use alloc::{borrow::Cow, collections::btree_map::BTreeMap};
use sha2::{Digest, Sha256};
use uefi::{prelude::*, proto::tcg::PcrIndex};

use crate::boot::{boot_kernel, load_elf, loaded_size, memdisk_range};
use crate::image_loader::read_file;
use crate::staging::StagingRegion;
use crate::tpm::measure_image;
use crate::util::round_up;

/// Headroom in the staging region beyond the loaded kernel and memory disk, for
/// the environment, modinfo records, TPM event log and the 8 MiB the kernel
/// reserves past `kernend`.
const STAGING_RESERVE: usize = 24 * 1024 * 1024;

pub fn run() -> Status {
    // ---- Read kernel.elf into its own buffer (freed after loading) ----
    let kernel = read_file("kernel.elf").expect("kernel.elf not found");
    measure_image(&kernel, PcrIndex(9), b"kernel.elf\0");
    let kernel_sha256 = Sha256::digest(&kernel);

    // ---- kenv (optional; measured as a single newline when absent/empty) ----
    let kenv_buf = read_file("kenv").unwrap_or_default();
    let kenv_buf: &'static [u8] = if kenv_buf.is_empty() {
        vec![b'\n'].leak()
    } else {
        kenv_buf.leak()
    };
    let kenv_sha256 = Sha256::digest(kenv_buf);
    measure_image(kenv_buf, PcrIndex(9), b"kenv\0");
    let kenv = parse_kenv(kenv_buf);

    // ---- Signature verification + PCR14 key measurement ----
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
    crate::sig::verify_and_measure_key(manifest.as_bytes());

    // ---- Size the staging region to the loaded kernel + memory disk ----
    let kern_size = loaded_size(&kernel);
    let memdisk = memdisk_range(&kernel);
    let memdisk_size = memdisk.map(|(_, s)| s).unwrap_or(0);
    let staging_size = round_up(kern_size, 1048576 * 2)
        + round_up(memdisk_size, 1048576 * 2)
        + STAGING_RESERVE;
    log::info!(
        "staging: {} MiB (kernel {} MiB + memdisk {} MiB + reserve {} MiB)",
        staging_size / 1048576,
        kern_size / 1048576,
        memdisk_size / 1048576,
        STAGING_RESERVE / 1048576
    );
    let mut staging = StagingRegion::with_size(staging_size);

    // ---- Load the kernel and stage the memory disk ----
    let mut kernel_load_region = staging.allocate(kern_size);
    let kernel_elf = load_elf(&mut kernel_load_region, &kernel);
    let memdisk = memdisk.map(|(offset, size)| {
        let mut h = staging.allocate(size);
        h.copy_from_slice(&kernel[offset..offset + size]);
        h
    });
    drop(kernel);

    match boot_kernel(staging, kernel_elf, memdisk, kenv) {
        Ok(x) => match x {},
        Err(e) => {
            log::error!("Failed to boot kernel: {}", e);
            Status::ABORTED
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
