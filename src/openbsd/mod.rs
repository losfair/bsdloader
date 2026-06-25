//! OpenBSD/amd64 UEFI boot backend.
//!
//! Loads `bsd.rd` (optionally gzip-compressed) from the ESP, places it into a
//! low (<256MB) EFI staging region using OpenBSD `LOADADDR()` semantics, builds
//! the OpenBSD 32-bit bootarg vector (memory map + EFI info + console + boot
//! DUID), exits boot services, moves the kernel to its final low physical
//! address and enters it through a `run_i386`-style trampoline.

mod bootargs;
mod elf;
mod memmap;

use core::arch::global_asm;
use core::ptr::NonNull;

use alloc::format;
use sha2::{Digest, Sha256};
use uefi::boot::{AllocateType, MemoryType, PAGE_SIZE};
use uefi::mem::memory_map::{MemoryMap, MemoryMapOwned};
use uefi::prelude::*;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
use uefi::proto::tcg::PcrIndex;
use uefi::table::cfg::{ACPI2_GUID, ACPI_GUID, SMBIOS_GUID};

use crate::image_loader::read_file;
use crate::tpm::measure_image;
use crate::util::round_up;
use bootargs::{serial, BiosConsdev, BiosEfiInfo, BootArgs};

global_asm!(include_str!("trampoline.S"), options(att_syntax));

extern "C" {
    fn obsd_tramp();
    fn obsd_tramp_end();
}

type Trampoline = unsafe extern "sysv64" fn(params: u64) -> !;

/// Size of the OpenBSD kernel staging region (must stay below 256MB).
const KERN_LOADSPACE_SIZE: usize = 64 * 1024 * 1024;

/// Kernel image filename on the ESP.
const KERNEL_NAME: &str = "bsd.rd";

#[repr(C)]
struct TrampParams {
    src: u64,
    dst: u64,
    len: u64,
    entry: u64,
    howto: u32,
    bootdev: u32,
    apiver: u32,
    markend: u32,
    extmem: u32,
    cnvmem: u32,
    ac: u32,
    av: u32,
}

pub fn run() -> Status {
    // ---- Read the kernel image from the ESP ----
    let file_buf = read_file(KERNEL_NAME)
        .unwrap_or_else(|| panic!("{} not found on ESP", KERNEL_NAME));
    log::info!("Loaded {} ({} bytes)", KERNEL_NAME, file_buf.len());

    // ---- Measured boot: measure the on-disk kernel image and verify it ----
    measure_and_verify(&file_buf);

    // ---- Decompress if gzip-compressed ----
    let kernel: alloc::vec::Vec<u8> = if file_buf.len() > 2 && file_buf[0] == 0x1f && file_buf[1] == 0x8b {
        let elf = gunzip(&file_buf);
        log::info!("Decompressed kernel ({} bytes)", elf.len());
        elf
    } else {
        file_buf
    };

    // ---- Allocate the low staging region (efi_loadaddr) ----
    let staging_ptr = uefi::boot::allocate_pages(
        AllocateType::MaxAddress(0x1000_0000u64),
        MemoryType::LOADER_DATA,
        KERN_LOADSPACE_SIZE / PAGE_SIZE,
    )
    .expect("failed to allocate kernel load space below 256MB");
    let efi_loadaddr = staging_ptr.as_ptr() as u64;
    log::info!("efi_loadaddr = 0x{:x}", efi_loadaddr);
    let staging = unsafe {
        core::slice::from_raw_parts_mut(staging_ptr.as_ptr(), KERN_LOADSPACE_SIZE)
    };

    // ---- Load the ELF (OpenBSD LOAD_ALL semantics) ----
    let loaded = elf::load(&kernel, staging, efi_loadaddr);
    drop(kernel);
    let marks = loaded.marks;
    log::info!(
        "marks: start=0x{:x} entry=0x{:x} sym=0x{:x} end=0x{:x}",
        marks[elf::MARK_START],
        marks[elf::MARK_ENTRY],
        marks[elf::MARK_SYM],
        marks[elf::MARK_END]
    );
    log::info!("kernel e_entry = 0x{:x}", loaded.e_entry);

    // ---- Final placement (computed now so we can guard allocations) ----
    // After ExitBootServices the kernel is moved from the staging region down to
    // its final low physical address; `delta = -efi_loadaddr` maps the marks.
    let delta = 0u64.wrapping_sub(efi_loadaddr);
    let src = marks[elf::MARK_START];
    let dst = marks[elf::MARK_START].wrapping_add(delta);
    let kern_len = marks[elf::MARK_END] - marks[elf::MARK_START];
    let dst_end = dst + kern_len;
    let entry = (marks[elf::MARK_ENTRY] & 0x0fff_ffff).wrapping_add(delta);
    let markend = marks[elf::MARK_END].wrapping_add(delta);
    log::info!("kernel dst=0x{:x}..0x{:x} entry=0x{:x}", dst, dst_end, entry);

    // The kernel destination range is overwritten by the post-ExitBootServices
    // memmove, so any buffer the trampoline still needs (itself, the bootarg
    // vector, the params block) must live entirely outside [dst, dst_end).
    let assert_clear = |name: &str, base: u64, size: usize| {
        let end = base + size as u64;
        assert!(
            end <= dst || base >= dst_end,
            "{} [0x{:x},0x{:x}) overlaps the kernel destination [0x{:x},0x{:x})",
            name,
            base,
            end,
            dst,
            dst_end
        );
    };

    // ---- Gather firmware info (ACPI/SMBIOS/system table/framebuffer) ----
    let (config_acpi, config_smbios) = find_acpi_smbios();
    let system_table = uefi::table::system_table_raw()
        .expect("missing system table")
        .as_ptr() as u64;
    let fb = load_efifb();

    let mut ei = BiosEfiInfo {
        config_acpi,
        config_smbios,
        system_table,
        flags: bootargs::BEI_64BIT,
        ..Default::default()
    };
    if let Some(fb) = &fb {
        ei.fb_addr = fb.addr;
        ei.fb_size = fb.size;
        ei.fb_height = fb.height;
        ei.fb_width = fb.width;
        ei.fb_pixpsl = fb.pixpsl;
        ei.fb_red_mask = fb.red;
        ei.fb_green_mask = fb.green;
        ei.fb_blue_mask = fb.blue;
        ei.fb_reserved_mask = fb.reserved;
    }
    let fb_addr = ei.fb_addr;
    log::info!(
        "ACPI=0x{:x} SMBIOS=0x{:x} ST=0x{:x} fb=0x{:x}",
        config_acpi,
        config_smbios,
        system_table,
        fb_addr
    );

    // ---- Console device: serial COM1 ----
    let consdev = BiosConsdev {
        consdev: bootargs::makedev(8, 0), // com0
        conspeed: 115200,
        consaddr: 0xffff_ffff_ffff_ffffu64, // -1: use legacy port for com0
        ..Default::default()
    };

    // ---- Pre-allocate buffers used after ExitBootServices (<4GB) ----
    let av_pages = 2;
    let av_ptr = uefi::boot::allocate_pages(
        AllocateType::MaxAddress(0x1_0000_0000u64),
        MemoryType::LOADER_DATA,
        av_pages,
    )
    .expect("failed to allocate bootarg buffer");
    assert_clear("bootarg buffer", av_ptr.as_ptr() as u64, av_pages * PAGE_SIZE);
    unsafe { av_ptr.write_bytes(0u8, av_pages * PAGE_SIZE) };
    let av = unsafe { core::slice::from_raw_parts_mut(av_ptr.as_ptr(), av_pages * PAGE_SIZE) };

    let tramp_size = obsd_tramp_end as usize - obsd_tramp as usize;
    let tramp_pages = round_up(tramp_size, PAGE_SIZE) / PAGE_SIZE;
    let tramp_ptr = uefi::boot::allocate_pages(
        AllocateType::MaxAddress(0x1_0000_0000u64),
        MemoryType::LOADER_CODE,
        tramp_pages,
    )
    .expect("failed to allocate trampoline");
    assert_clear("trampoline", tramp_ptr.as_ptr() as u64, tramp_pages * PAGE_SIZE);
    unsafe {
        tramp_ptr.write_bytes(0u8, tramp_pages * PAGE_SIZE);
        tramp_ptr.copy_from_nonoverlapping(
            NonNull::new(obsd_tramp as usize as *mut u8).unwrap(),
            tramp_size,
        );
    }
    log::info!(
        "trampoline: {} bytes at 0x{:x}",
        tramp_size,
        tramp_ptr.as_ptr() as u64
    );

    let params_ptr = uefi::boot::allocate_pages(
        AllocateType::MaxAddress(0x1_0000_0000u64),
        MemoryType::LOADER_DATA,
        1,
    )
    .expect("failed to allocate trampoline params")
    .cast::<TrampParams>();
    assert_clear(
        "trampoline params",
        params_ptr.as_ptr() as u64,
        core::mem::size_of::<TrampParams>(),
    );

    log::info!("Exiting boot services and entering kernel...");

    unsafe {
        // ---- Exit boot services ----
        let mm: MemoryMapOwned = uefi::boot::exit_boot_services(MemoryType::LOADER_DATA);

        // From here on: NO UEFI calls, NO heap allocation, NO logging.
        serial::puts("\r\n[bsdloader] exited boot services\r\n");

        // ---- Convert the EFI memory map to OpenBSD bios_memmap ----
        let mut scratch = [memmap::MemEntry {
            addr: 0,
            size: 0,
            ty: 0,
        }; 160];
        let conv = memmap::convert(&mm, &mut scratch);

        // EFI info: point at the (post-exit, still-mapped) EFI memory map.
        ei.mmap_start = mm.buffer().as_ptr() as u64;
        ei.mmap_size = mm.meta().map_size as u32;
        ei.mmap_desc_size = mm.meta().desc_size as u32;
        ei.mmap_desc_ver = mm.meta().desc_version;

        // ---- Serialize bios_memmap (entries + BIOS_MAP_END terminator) ----
        let mut mmbuf = [0u8; (160 + 1) * 20];
        let mut off = 0usize;
        for e in &scratch[..conv.count] {
            mmbuf[off..off + 8].copy_from_slice(&e.addr.to_le_bytes());
            mmbuf[off + 8..off + 16].copy_from_slice(&e.size.to_le_bytes());
            mmbuf[off + 16..off + 20].copy_from_slice(&e.ty.to_le_bytes());
            off += 20;
        }
        // terminator entry {0, 0, BIOS_MAP_END}
        off += 20;

        // ---- Build the bootarg vector ----
        let mut ba = BootArgs::new(av);
        ba.push(bootargs::BOOTARG_MEMMAP, &mmbuf[..off]);
        ba.push_struct(bootargs::BOOTARG_EFIINFO, &ei);
        ba.push_struct(bootargs::BOOTARG_CONSDEV, &consdev);
        ba.push(bootargs::BOOTARG_BOOTDUID, &[0u8; 8]);
        let ac = ba.finish();

        // Final placement (`delta`/`src`/`dst`/`kern_len`/`entry`/`markend`)
        // was computed before ExitBootServices.
        serial::puts("[bsdloader] entry=");
        serial::puthex(entry);
        serial::puts(" dst=");
        serial::puthex(dst);
        serial::puts(" len=");
        serial::puthex(kern_len);
        serial::puts(" ac=");
        serial::puthex(ac as u64);
        serial::puts("\r\n");

        params_ptr.write(TrampParams {
            src,
            dst,
            len: kern_len,
            entry,
            howto: 0,
            bootdev: 0,
            apiver: bootargs::BOOTARG_APIVER,
            markend: markend as u32,
            extmem: conv.extmem,
            cnvmem: conv.cnvmem,
            ac: ac as u32,
            av: av_ptr.as_ptr() as u32,
        });

        serial::puts("[bsdloader] jumping to kernel via trampoline\r\n");

        let tramp: Trampoline = core::mem::transmute(tramp_ptr.as_ptr() as usize);
        tramp(params_ptr.as_ptr() as u64);
    }
}

struct Fb {
    addr: u64,
    size: u64,
    width: u32,
    height: u32,
    pixpsl: u32,
    red: u32,
    green: u32,
    blue: u32,
    reserved: u32,
}

fn load_efifb() -> Option<Fb> {
    use uefi::boot::{open_protocol, OpenProtocolAttributes, OpenProtocolParams, SearchType};
    use uefi::Identify;

    let handle = uefi::boot::locate_handle_buffer(SearchType::ByProtocol(&GraphicsOutput::GUID))
        .ok()
        .and_then(|h| h.first().copied())?;
    let mut gop = unsafe {
        open_protocol::<GraphicsOutput>(
            OpenProtocolParams {
                handle,
                agent: uefi::boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()?;

    let mode = gop.current_mode_info();
    let (w, h) = mode.resolution();
    let mut rawfb = gop.frame_buffer();
    let (red, green, blue, reserved) = match mode.pixel_format() {
        PixelFormat::Rgb | PixelFormat::BltOnly => (0x0000_00ff, 0x0000_ff00, 0x00ff_0000, 0xff00_0000),
        PixelFormat::Bgr => (0x00ff_0000, 0x0000_ff00, 0x0000_00ff, 0xff00_0000),
        PixelFormat::Bitmask => {
            let m = mode.pixel_bitmask().unwrap_or(uefi::proto::console::gop::PixelBitmask {
                red: 0,
                green: 0,
                blue: 0,
                reserved: 0,
            });
            (m.red, m.green, m.blue, m.reserved)
        }
    };

    Some(Fb {
        addr: rawfb.as_mut_ptr() as u64,
        size: rawfb.size() as u64,
        width: w as u32,
        height: h as u32,
        pixpsl: mode.stride() as u32,
        red,
        green,
        blue,
        reserved,
    })
}

/// Measured boot for the OpenBSD backend.
///
/// * The on-disk kernel image (`bsd.rd`, exactly as stored on the ESP) is
///   measured into **PCR 9** as an `EV_IPL` event.
/// * If a `siginfo` file is present, its Ed25519 signature is verified over a
///   `sha256sum`-style manifest of the kernel; verification failure aborts boot.
/// * The Ed25519 public key (or 32 zero bytes when no `siginfo` is present) is
///   **always** measured into **PCR 14**, binding the booted kernel to the key
///   policy in use.
fn measure_and_verify(kernel: &[u8]) {
    measure_image(kernel, PcrIndex(9), b"bsd.rd\0");

    let mut kernel_sha256_str = [0u8; 64];
    hex::encode_to_slice(&Sha256::digest(kernel), &mut kernel_sha256_str).unwrap();
    let kernel_sha256_str = core::str::from_utf8(&kernel_sha256_str).unwrap();
    let manifest = format!("{}  bsd.rd\n", kernel_sha256_str);

    crate::sig::verify_and_measure_key(manifest.as_bytes());
}

fn find_acpi_smbios() -> (u64, u64) {
    uefi::system::with_config_table(|entries| {
        let acpi = entries
            .iter()
            .find(|x| x.guid == ACPI2_GUID)
            .or_else(|| entries.iter().find(|x| x.guid == ACPI_GUID))
            .map(|x| x.address as u64)
            .unwrap_or(0);
        let smbios = entries
            .iter()
            .find(|x| x.guid == SMBIOS_GUID)
            .map(|x| x.address as u64)
            .unwrap_or(0);
        (acpi, smbios)
    })
}

fn gunzip(data: &[u8]) -> alloc::vec::Vec<u8> {
    // Parse the gzip header (RFC 1952) and raw-inflate the deflate stream.
    assert!(data.len() > 18, "gzip stream too short");
    assert!(data[0] == 0x1f && data[1] == 0x8b && data[2] == 0x08, "bad gzip header");
    let flg = data[3];
    let mut pos = 10usize;
    if flg & 0x04 != 0 {
        // FEXTRA
        let xlen = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + xlen;
    }
    if flg & 0x08 != 0 {
        // FNAME
        while data[pos] != 0 {
            pos += 1;
        }
        pos += 1;
    }
    if flg & 0x10 != 0 {
        // FCOMMENT
        while data[pos] != 0 {
            pos += 1;
        }
        pos += 1;
    }
    if flg & 0x02 != 0 {
        // FHCRC
        pos += 2;
    }
    miniz_oxide::inflate::decompress_to_vec(&data[pos..])
        .expect("gzip inflate failed")
}
