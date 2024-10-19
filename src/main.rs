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
use boot::{boot_kernel, load_elf};
use image_loader::{load_image_from_disk, OwnedBuffer};
use staging::StagingRegion;
use tpm::measure_image;
use uefi::boot::AllocateType;
use uefi::{prelude::*, proto::tcg::PcrIndex};

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();

    log::info!("Starting...");

    let mut staging = StagingRegion::new(300 * 1048576);

    let mut kernel_load_region = staging.allocate(50 * 1048576);

    let mut kernel_buffer = staging.allocate(200 * 1048576);
    let kernel_buffer_len =
        load_image_from_disk("kernel.elf", &mut kernel_buffer[..]).expect("kernel.elf not found");
    let mut kernel_buffer = staging.shrink(kernel_buffer, kernel_buffer_len);
    measure_image(&kernel_buffer[..], PcrIndex(9), "kernel.elf");

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
        measure_image(&kenv_buffer[..], PcrIndex(9), "kenv");
        parse_kenv(&kenv_buffer[..])
    };

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
