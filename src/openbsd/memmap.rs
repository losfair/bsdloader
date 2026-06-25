//! EFI memory map -> OpenBSD BIOS-style memory map conversion.
//!
//! Faithful port of `efi_update_bios_memmap()` in
//! `sys/arch/amd64/stand/efiboot/efiboot.c`.  Runs *after* ExitBootServices,
//! so it must not allocate or call UEFI; it writes into caller-provided scratch.

use uefi::mem::memory_map::{MemoryMap, MemoryMapOwned};

// OpenBSD BIOS memory map types (machine/biosvar.h)
#[allow(dead_code)]
pub const BIOS_MAP_END: u32 = 0x00;
pub const BIOS_MAP_FREE: u32 = 0x01;
pub const BIOS_MAP_RES: u32 = 0x02;
pub const BIOS_MAP_ACPI: u32 = 0x03;
pub const BIOS_MAP_NVS: u32 = 0x04;

const IOM_BEGIN: u64 = 0x0a_0000;
const IOM_END: u64 = 0x10_0000;

// EFI memory types
const EFI_RESERVED: u32 = 0;
const EFI_LOADER_CODE: u32 = 1;
const EFI_LOADER_DATA: u32 = 2;
const EFI_BS_CODE: u32 = 3;
const EFI_BS_DATA: u32 = 4;
const EFI_RT_CODE: u32 = 5;
const EFI_RT_DATA: u32 = 6;
const EFI_CONVENTIONAL: u32 = 7;
const EFI_UNUSABLE: u32 = 8;
const EFI_ACPI_RECLAIM: u32 = 9;
const EFI_ACPI_NVS: u32 = 10;

#[derive(Clone, Copy)]
pub struct MemEntry {
    pub addr: u64,
    pub size: u64,
    pub ty: u32,
}

pub struct Converted {
    pub count: usize,
    pub cnvmem: u32,
    pub extmem: u32,
}

fn classify(efi_ty: u32) -> u32 {
    match efi_ty {
        EFI_RESERVED | EFI_UNUSABLE | EFI_RT_CODE | EFI_RT_DATA => BIOS_MAP_RES,
        EFI_LOADER_CODE | EFI_LOADER_DATA | EFI_BS_CODE | EFI_BS_DATA | EFI_CONVENTIONAL => {
            BIOS_MAP_FREE
        }
        EFI_ACPI_RECLAIM => BIOS_MAP_ACPI,
        EFI_ACPI_NVS => BIOS_MAP_NVS,
        _ => BIOS_MAP_RES,
    }
}

/// Convert `mm` into `out` (BIOS memory map entries, no END terminator) and
/// compute cnvmem/extmem (in KiB) exactly like `efi_update_bios_memmap()`.
pub fn convert(mm: &MemoryMapOwned, out: &mut [MemEntry]) -> Converted {
    let mut n: usize = 0;

    for d in mm.entries() {
        let a0 = d.phys_start;
        let s0 = d.page_count * 4096;
        let t0 = classify(d.ty.0);

        // Try to merge with an existing entry of the same type (first match).
        let mut merged = false;
        for bm in out[..n].iter_mut() {
            if bm.ty != t0 {
                continue;
            }
            if bm.addr <= a0 && a0 <= bm.addr + bm.size {
                bm.size = a0 + s0 - bm.addr;
                merged = true;
                break;
            } else if a0 <= bm.addr && bm.addr <= a0 + s0 {
                bm.size = bm.addr + bm.size - a0;
                bm.addr = a0;
                merged = true;
                break;
            }
        }
        if !merged {
            if n >= out.len() {
                break; // E2BIG
            }
            out[n] = MemEntry {
                addr: a0,
                size: s0,
                ty: t0,
            };
            n += 1;
        }
    }

    let mut cnvmem: u64 = 0;
    let mut extmem: u64 = 0;
    for bm in out[..n].iter() {
        if bm.addr < IOM_BEGIN {
            cnvmem = cnvmem.max((bm.addr + bm.size) / 1024);
        }
        if bm.addr >= IOM_END && bm.addr / 1024 == extmem + 1024 {
            extmem += bm.size / 1024;
        }
    }

    Converted {
        count: n,
        cnvmem: cnvmem as u32,
        extmem: extmem as u32,
    }
}
