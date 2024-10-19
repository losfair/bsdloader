use core::{arch::global_asm, convert::Infallible, iter::once, ptr::NonNull};

use alloc::{borrow::Cow, collections::btree_map::BTreeMap, format};
use object::{
    read::elf::{FileHeader, ProgramHeader},
    Endianness, Object, ObjectSection,
};
use uefi::{
    boot::{
        AllocateType, MemoryAttribute, MemoryDescriptor, MemoryType, OpenProtocolAttributes,
        OpenProtocolParams, PAGE_SIZE,
    },
    mem::memory_map::{MemoryMap, MemoryMapMut},
    proto::console::gop::{GraphicsOutput, PixelFormat},
    table::cfg::{ACPI2_GUID, ACPI_GUID},
    Identify,
};

use crate::{
    modinfo,
    staging::{StagingRegion, StagingRegionHandle, STAGING_ALIGNMENT},
    tpm::read_tpm_event_log,
    util::{any_to_bytes, round_up},
};

global_asm!(include_str!("trampoline.S"));

extern "C" {
    fn amd64_tramp(stack: u64) -> !;
    fn amd64_tramp_end(_: Infallible) -> !;
}

type Trampoline = unsafe extern "C" fn(stack: u64) -> !;

const NPML4EPG: usize = PAGE_SIZE / core::mem::size_of::<usize>();
const NPDEPG: usize = PAGE_SIZE / core::mem::size_of::<usize>();
const NPDPEPG: usize = PAGE_SIZE / core::mem::size_of::<usize>();

const PDRSHIFT: usize = 21;

const PG_V: usize = 0x001usize;
const PG_RW: usize = 0x002usize;
const PG_PS: usize = 0x080usize;

const LOAD_START: u64 = 0xffff_ffff_8020_0000u64;

#[derive(Default, Debug)]
#[repr(C)]
struct EfiFb {
    fb_addr: u64,
    fb_size: u64,
    fb_height: u32,
    fb_width: u32,
    fb_stride: u32,
    fb_mask_red: u32,
    fb_mask_green: u32,
    fb_mask_blue: u32,
    fb_mask_reserved: u32,
}

#[derive(Clone, Debug)]
pub struct ElfInfo {
    pub entry: u64,
    pub memdisk_file_range: Option<(u64, u64)>,
}

pub fn boot_kernel(
    mut staging: StagingRegion,
    elf_info: ElfInfo,
    memdisk: Option<StagingRegionHandle>,
    mut env: BTreeMap<Cow<str>, Cow<str>>,
) -> Result<Infallible, &'static str> {
    log::info!("Loading kernel...");

    // Build env

    let rsdp = uefi::system::with_config_table(|entries| {
        entries
            .iter()
            .find(|x| x.guid == ACPI2_GUID)
            .or_else(|| entries.iter().find(|x| x.guid == ACPI_GUID))
            .map(|x| x.address)
    });

    if let Some(rsdp) = rsdp {
        env.insert(
            "acpi.rsdp".into(),
            format!("0x{:016x}", rsdp as usize).into(),
        );
    }

    log::info!("Kernel env: {:?}", env);
    log::info!("Kernel entrypoint: 0x{:016x}", elf_info.entry);
    if let Some(memdisk) = &memdisk {
        log::info!("Memdisk: {} bytes", memdisk.len());
    }

    // write env
    let envdata = || {
        env.iter()
            .flat_map(|x| {
                x.0.as_bytes()
                    .iter()
                    .copied()
                    .chain(once(b'='))
                    .chain(x.1.as_bytes().iter().copied())
                    .chain(once(0u8))
            })
            .chain(once(0u8))
    };
    let mut envmem = staging.allocate(envdata().count());
    envmem.iter_mut().zip(envdata()).for_each(|x| *x.0 = x.1);

    let tpm_event_log = read_tpm_event_log(&mut staging);

    // prepare framebuffer
    let fb = load_efifb();

    // start to write modinfo
    staging.align(PAGE_SIZE);
    let modulep = staging.current_vm_offset_from_base();

    let uefi_system_table = uefi::table::system_table_raw().expect("missing system table");

    if let Some(memdisk) = memdisk {
        log::info!("Unpacked memdisk ({} bytes)", memdisk.len());
        modinfo::push(&mut staging, modinfo::MODINFO_NAME, b"memdisk.img\0");
        modinfo::push(&mut staging, modinfo::MODINFO_TYPE, b"md_image\0");
        modinfo::push(
            &mut staging,
            modinfo::MODINFO_ADDR,
            &memdisk.vm_offset_from_base().to_le_bytes(),
        );
        modinfo::push(
            &mut staging,
            modinfo::MODINFO_SIZE,
            &memdisk.len().to_le_bytes(),
        );
    }

    if let Some(tpm_event_log) = tpm_event_log {
        log::info!("Loaded TPM event log ({} bytes)", tpm_event_log.len());
        modinfo::push(&mut staging, modinfo::MODINFO_NAME, b"tpmlog.img\0");
        modinfo::push(&mut staging, modinfo::MODINFO_TYPE, b"md_image\0");
        modinfo::push(
            &mut staging,
            modinfo::MODINFO_ADDR,
            &tpm_event_log.vm_offset_from_base().to_le_bytes(),
        );
        modinfo::push(
            &mut staging,
            modinfo::MODINFO_SIZE,
            &tpm_event_log.len().to_le_bytes(),
        );
    }

    modinfo::push(&mut staging, modinfo::MODINFO_NAME, b"freebsd\0");
    modinfo::push(&mut staging, modinfo::MODINFO_TYPE, b"elf64 kernel\0");

    modinfo::push(
        &mut staging,
        modinfo::MODINFO_METADATA | modinfo::MODINFOMD_HOWTO,
        &modinfo::RB_MULTIPLE.to_le_bytes(),
    );

    modinfo::push(
        &mut staging,
        modinfo::MODINFO_METADATA | modinfo::MODINFOMD_ENVP,
        &(envmem.vm_offset_from_base() as u64).to_le_bytes(),
    );

    modinfo::push(
        &mut staging,
        modinfo::MODINFO_METADATA | modinfo::MODINFOMD_FW_HANDLE,
        &(uefi_system_table.as_ptr() as u64).to_le_bytes(),
    );

    if let Some(fb) = &fb {
        modinfo::push(
            &mut staging,
            modinfo::MODINFO_METADATA | modinfo::MODINFOMD_EFI_FB,
            any_to_bytes(fb),
        );
    }

    let mut reserved = staging.allocate(65536);

    if staging.remaining() < 8 * 1048576 {
        panic!(
            "not enough staging space for reserved kernend (8MiB): {}",
            staging.remaining()
        );
    }
    staging.align(PAGE_SIZE);
    let kernend = staging.current_vm_offset_from_start();

    // Build kernel page tables
    let pt4 = unsafe { build_page_tables(&mut staging) };

    let trampcode = uefi::boot::allocate_pages(
        AllocateType::MaxAddress(0x1_0000_0000u64),
        MemoryType::LOADER_CODE,
        1,
    )
    .map_err(|e| {
        log::error!("Failed to allocate memory for trampoline: {:?}", e);
        "failed to allocate memory for trampoline"
    })?;

    let trampcode_size = amd64_tramp_end as usize - amd64_tramp as usize;
    assert!(trampcode_size <= PAGE_SIZE - 128);

    unsafe {
        trampcode.write_bytes(0u8, PAGE_SIZE);
        trampcode.copy_from_nonoverlapping(
            NonNull::new(amd64_tramp as usize as *mut u8).expect("bad amd64_tramp"),
            trampcode_size,
        );
    }

    log::info!(
        "Copied {} bytes of trampoline to {:p}",
        trampcode_size,
        trampcode
    );

    unsafe {
        log::info!(
            "Jumping to trampoline after 5s, PT4={:p}, kernend=0x{:08x}",
            pt4,
            kernend
        );

        uefi::boot::stall(5_000_000);

        // Reserve memory for 1024 memory descriptors
        let max_num_descriptors = 1024usize;
        let descriptors = uefi::boot::allocate_pages(
            AllocateType::MaxAddress(0x1_0000_0000u64),
            MemoryType::LOADER_DATA,
            round_up(
                max_num_descriptors * core::mem::size_of::<MemoryDescriptor>(),
                PAGE_SIZE,
            ) / PAGE_SIZE,
        )
        .expect("failed to allocate descriptors");
        let descriptors = core::slice::from_raw_parts_mut(
            descriptors.cast::<MemoryDescriptor>().as_ptr(),
            max_num_descriptors,
        );

        let mut mm = uefi::boot::exit_boot_services(MemoryType::LOADER_DATA);

        let mut num_descriptors = 0usize;
        for i in 0..mm.len() {
            let entry = mm.get_mut(i).expect("failed to get entry");
            if entry.att.contains(MemoryAttribute::RUNTIME) {
                entry.virt_start = entry.phys_start;
                descriptors[num_descriptors] = *entry;
                num_descriptors += 1;
            }
        }

        let descriptors = &mut descriptors[..num_descriptors];

        uefi::runtime::set_virtual_address_map(descriptors, uefi_system_table.as_ptr())
            .expect("failed to set virtual address map");

        // write efimap
        let efimap_size = mm.buffer().len() + 32;
        reserved[0..4].copy_from_slice(
            &(modinfo::MODINFO_METADATA | modinfo::MODINFOMD_EFI_MAP).to_le_bytes(),
        );
        reserved[4..8].copy_from_slice(&(efimap_size as u32).to_le_bytes());
        let reserved = &mut reserved[8..];
        let (efimap, reserved) = reserved.split_at_mut(efimap_size);

        efimap[..8].copy_from_slice(&(mm.meta().map_size as u64).to_le_bytes());
        efimap[8..16].copy_from_slice(&(mm.meta().desc_size as u64).to_le_bytes());
        efimap[16..20].copy_from_slice(&(mm.meta().desc_version as u32).to_le_bytes());
        efimap[32..].copy_from_slice(mm.buffer());

        // End of module info: [0u32, 0u32]
        // No need to explicitly fill - zeroed by default
        assert!(reserved.len() >= 8);

        let trampstack: NonNull<usize> = trampcode.add(PAGE_SIZE - 64).cast();
        trampstack.add(0).write(pt4.as_ptr() as usize);
        trampstack.add(1).write(elf_info.entry as usize);
        trampstack.add(2).write(modulep << 32);
        trampstack.add(3).write(kernend);
        let trampoline = core::mem::transmute::<usize, Trampoline>(trampcode.as_ptr() as usize);
        trampoline(trampstack.as_ptr() as u64);
    }
}

pub fn load_elf(region: &mut [u8], image: &[u8]) -> ElfInfo {
    let elf = object::File::parse(image).expect("failed to parse ELF");
    let object::File::Elf64(elf) = elf else {
        panic!("not elf64")
    };

    let load_phdrs = || {
        elf.elf_program_headers()
            .iter()
            .filter(|x| x.p_type(Endianness::Little) == object::elf::PT_LOAD)
    };

    let max_offset_from_start = load_phdrs()
        .map(|x| x.p_vaddr(Endianness::Little) + x.p_memsz(Endianness::Little))
        .max()
        .unwrap_or_default()
        .checked_sub(LOAD_START)
        .expect("cannot determine elf max offset") as usize;
    assert!(max_offset_from_start != 0);
    assert!(max_offset_from_start <= region.len());

    for phdr in load_phdrs() {
        let p_filesz = phdr.p_filesz.get(Endianness::Little);
        let p_offset = phdr.p_offset.get(Endianness::Little);
        let p_vaddr = phdr.p_vaddr.get(Endianness::Little);
        let p_memsz = phdr.p_memsz.get(Endianness::Little);

        log::info!(
            "Segment: 0x{:08x}@0x{:08x} -> 0x{:016x}-0x{:016x}",
            p_filesz,
            p_offset,
            p_vaddr,
            p_vaddr + p_memsz,
        );

        let Some(staging_offset) = p_vaddr.checked_sub(LOAD_START) else {
            panic!("p_vaddr out of range");
        };

        let Ok(data) = phdr.data(Endianness::Little, image) else {
            panic!("failed to dereference segment data");
        };
        assert_eq!(data.len(), p_filesz as usize);

        if p_filesz > p_memsz {
            panic!("p_filesz > p_memsz");
        }

        region[staging_offset as usize..(staging_offset + p_filesz) as usize].copy_from_slice(data);

        if p_memsz > p_filesz {
            log::info!(" [bss 0x{:08x}]", p_memsz - p_filesz);
            region[(staging_offset + p_filesz) as usize..(staging_offset + p_memsz) as usize]
                .fill(0);
        }
    }

    let memdisk_file_range = if let Some(x) = elf.section_by_name(".memdisk") {
        x.file_range()
    } else {
        None
    };

    let entry = elf.elf_header().e_entry(Endianness::Little);
    ElfInfo {
        entry,
        memdisk_file_range,
    }
}

unsafe fn build_page_tables(staging: &mut StagingRegion) -> NonNull<usize> {
    let pt4 = uefi::boot::allocate_pages(
        AllocateType::MaxAddress(0x1_0000_0000u64),
        MemoryType::LOADER_DATA,
        9,
    )
    .expect("failed to allocate memory for page tables");
    pt4.write_bytes(0u8, 9 * PAGE_SIZE);
    let pt4: NonNull<usize> = pt4.cast();

    let pt3_1 = pt4.add(NPML4EPG * 1);
    let pt3_u = pt4.add(NPML4EPG * 2);
    let pt2_10 = pt4.add(NPML4EPG * 3);
    let pt2_11 = pt4.add(NPML4EPG * 4);
    let pt2_12 = pt4.add(NPML4EPG * 5);
    let pt2_13 = pt4.add(NPML4EPG * 6);
    let pt2_u0 = pt4.add(NPML4EPG * 7);
    let pt2_u1 = pt4.add(NPML4EPG * 8);

    // 1:1 mapping of lower 4G
    pt4.add(0).write(pt3_1.as_ptr() as usize | PG_V | PG_RW);
    pt3_1.add(0).write(pt2_10.as_ptr() as usize | PG_V | PG_RW);
    pt3_1.add(1).write(pt2_11.as_ptr() as usize | PG_V | PG_RW);
    pt3_1.add(2).write(pt2_12.as_ptr() as usize | PG_V | PG_RW);
    pt3_1.add(3).write(pt2_13.as_ptr() as usize | PG_V | PG_RW);
    for i in 0..4 * NPDEPG {
        pt2_10.add(i).write((i << PDRSHIFT) | PG_V | PG_RW | PG_PS);
    }

    // mapping of kernel 2G below top
    pt4.add(NPML4EPG - 1)
        .write(pt3_u.as_ptr() as usize | PG_V | PG_RW);
    pt3_u
        .add(NPDPEPG - 2)
        .write(pt2_u0.as_ptr() as usize | PG_V | PG_RW);
    pt3_u
        .add(NPDPEPG - 1)
        .write(pt2_u1.as_ptr() as usize | PG_V | PG_RW);

    // compat mapping of phys @0
    pt2_u0.add(0).write(PG_PS | PG_V | PG_RW);

    // map staging
    for i in 0..(staging.size() / STAGING_ALIGNMENT) {
        pt2_u0.add(i + 1).write(
            staging.ptr().add(i * STAGING_ALIGNMENT).as_ptr() as usize | PG_V | PG_RW | PG_PS,
        )
    }
    log::info!("Created kernel page tables");
    pt4
}

fn load_efifb() -> Option<EfiFb> {
    let protocol =
        uefi::boot::locate_handle_buffer(uefi::boot::SearchType::ByProtocol(&GraphicsOutput::GUID))
            .ok()
            .and_then(|x| x.get(0).copied())?;
    let mut protocol = match unsafe {
        uefi::boot::open_protocol::<GraphicsOutput>(
            OpenProtocolParams {
                handle: protocol,
                agent: uefi::boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    } {
        Ok(x) => x,
        Err(e) => {
            log::error!("failed to open GOP protocol: {:?}", e);
            return None;
        }
    };
    let mut fb = EfiFb::default();
    let mode = protocol.current_mode_info();
    let mut rawfb = protocol.frame_buffer();
    fb.fb_addr = rawfb.as_mut_ptr() as u64;
    fb.fb_size = rawfb.size() as u64;
    let (w, h) = mode.resolution();
    fb.fb_width = w as u32;
    fb.fb_height = h as u32;
    fb.fb_stride = mode.stride() as u32;
    match mode.pixel_format() {
        PixelFormat::BltOnly | PixelFormat::Rgb => {
            fb.fb_mask_red = 0x000000ff;
            fb.fb_mask_green = 0x0000ff00;
            fb.fb_mask_blue = 0x00ff0000;
            fb.fb_mask_reserved = 0xff000000;
        }
        PixelFormat::Bgr => {
            fb.fb_mask_red = 0x00ff0000;
            fb.fb_mask_green = 0x0000ff00;
            fb.fb_mask_blue = 0x000000ff;
            fb.fb_mask_reserved = 0xff000000;
        }
        PixelFormat::Bitmask => {
            if let Some(bitmask) = mode.pixel_bitmask() {
                fb.fb_mask_red = bitmask.red;
                fb.fb_mask_green = bitmask.green;
                fb.fb_mask_blue = bitmask.blue;
                fb.fb_mask_reserved = bitmask.reserved;
            }
        }
    }

    log::info!("Framebuffer: {:?}", fb);
    Some(fb)
}
