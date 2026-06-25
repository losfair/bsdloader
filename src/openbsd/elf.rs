//! OpenBSD/amd64 standalone ELF loader.
//!
//! Faithful port of OpenBSD `sys/lib/libsa/loadfile_elf.c` (the `LOAD_ALL`
//! path) together with the amd64 `LOADADDR()` macro from
//! `sys/arch/amd64/include/loadfile_machdep.h`:
//!
//! ```c
//! #define LOADADDR(a) (((((u_long)(a)) + offset) & 0xfffffff) + efi_loadaddr)
//! ```
//!
//! The kernel is loaded into the EFI staging region (`efi_loadaddr`), and the
//! returned `marks[]` are absolute addresses inside that region.  After
//! ExitBootServices the caller moves the image down to its final low physical
//! address (`marks[MARK_*] - efi_loadaddr`).

use rand_chacha::rand_core::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::elf64::{
    rd_u64, Elf, EHDR_SIZE, PF_R, PF_W, PF_X, PT_LOAD, PT_OPENBSD_RANDOMIZE, SHDR_SIZE, SHF_ALLOC,
    SHT_SYMTAB,
};
use crate::util::round_up;

// marks[] indices (sys/lib/libsa/loadfile.h)
pub const MARK_START: usize = 0;
pub const MARK_ENTRY: usize = 1;
pub const MARK_NSYM: usize = 2;
pub const MARK_SYM: usize = 3;
pub const MARK_END: usize = 4;
pub const MARK_RANDOM: usize = 5;
pub const MARK_ERANDOM: usize = 6;
pub const MARK_VENTRY: usize = 7;
pub const MARK_MAX: usize = 8;

const ELF_CTF: &[u8] = b".SUNW_ctf";
const DEBUG_LINE: &[u8] = b".debug_line";

/// True if section `i` is one whose contents OpenBSD's `LOAD_ALL` copies after
/// the kernel image (symbols, string tables, CTF, debug line info).
fn is_loaded_section(elf: &Elf, i: usize) -> bool {
    let sh = elf.shdr(i);
    let name = elf.section_name(&sh);
    sh.sh_type == crate::elf64::SHT_SYMTAB
        || sh.sh_type == crate::elf64::SHT_STRTAB
        || name == DEBUG_LINE
        || name == ELF_CTF
}

/// Compute the raw (paddr-based) end address of the loaded image, matching the
/// accounting in [`load`]: all `PT_LOAD` extents + BSS, then the appended ELF
/// header, section-header table and symbol/string sections.
///
/// The required staging size is `measure(image)` (a `paddr & 0x0fffffff`
/// offset, since the amd64 kernel's physical addresses are below 256 MiB).
pub fn measure(image: &[u8]) -> usize {
    let elf = Elf::parse(image);

    let mut maxp: u64 = 0;
    for i in 0..elf.e_phnum() {
        let ph = elf.phdr(i);
        if ph.p_type != PT_LOAD || (ph.p_flags & (PF_W | PF_R | PF_X)) == 0 {
            continue;
        }
        maxp = maxp.max(ph.p_paddr + ph.p_memsz);
    }

    let elfp = round_up(maxp as usize, 8) as u64;
    let mut maxp = elfp + EHDR_SIZE as u64; // ELF header
    maxp += round_up(elf.e_shnum() * SHDR_SIZE, 8) as u64; // section header table

    for i in 0..elf.e_shnum() {
        if is_loaded_section(&elf, i) {
            maxp += round_up(elf.shdr(i).sh_size as usize, 8) as u64;
        }
    }

    maxp as usize
}

pub struct LoadedKernel {
    pub marks: [u64; MARK_MAX],
    pub e_entry: u64,
}

/// Load `image` (a decompressed ELF64) into `staging` (the EFI load space whose
/// base physical address is `efi_loadaddr`).  Returns the OpenBSD `marks[]`.
pub fn load(image: &[u8], staging: &mut [u8], efi_loadaddr: u64) -> LoadedKernel {
    let elf = Elf::parse(image);
    let e_entry = elf.e_entry();
    let e_shnum = elf.e_shnum();

    // offset == marks[MARK_START] == 0 for the EFI boot path.
    let loadaddr = |a: u64| -> u64 { (a & 0x0fff_ffff) + efi_loadaddr };
    // Byte offset of an absolute load address within `staging`.
    let soff = |a: u64| -> usize { (a & 0x0fff_ffff) as usize };

    let mut marks = [0u64; MARK_MAX];

    let mut minp: u64 = !0;
    let mut maxp: u64 = 0;

    // ChaCha8 stream seeded once from the hardware RNG, used to fill any
    // PT_OPENBSD_RANDOMIZE segment(s). Seeded lazily so we only require RDRAND
    // when a randomize segment is actually present.
    let mut rng: Option<ChaCha8Rng> = None;

    // ---- Program headers: text/data/bss + randomize ----
    for i in 0..elf.e_phnum() {
        let ph = elf.phdr(i);

        if ph.p_type == PT_OPENBSD_RANDOMIZE {
            let dst = soff(ph.p_paddr);
            let bounds =
                check_bounds(staging.len(), dst, ph.p_filesz as usize, "PT_OPENBSD_RANDOMIZE");
            rng.get_or_insert_with(seed_chacha8)
                .fill_bytes(&mut staging[dst..bounds]);
            marks[MARK_RANDOM] = loadaddr(ph.p_paddr);
            marks[MARK_ERANDOM] = marks[MARK_RANDOM] + ph.p_filesz;
            continue;
        }

        if ph.p_type != PT_LOAD || (ph.p_flags & (PF_W | PF_R | PF_X)) == 0 {
            continue;
        }

        // Read in segment (LOAD_TEXT | LOAD_DATA).
        let fstart = ph.p_offset as usize;
        let fsz = ph.p_filesz as usize;
        let dst = soff(ph.p_paddr);
        write_at(staging, dst, &image[fstart..fstart + fsz], "PT_LOAD segment");

        // Track loaded range (COUNT_TEXT | COUNT_DATA).
        let mut pos = ph.p_paddr;
        if minp > pos {
            minp = pos;
        }
        pos += ph.p_filesz;
        if maxp < pos {
            maxp = pos;
        }

        // Zero BSS (LOAD_BSS) and extend range.
        if ph.p_filesz < ph.p_memsz {
            let bss = soff(ph.p_paddr + ph.p_filesz);
            let bsz = (ph.p_memsz - ph.p_filesz) as usize;
            let end = check_bounds(staging.len(), bss, bsz, "PT_LOAD bss");
            staging[bss..end].fill(0);
            pos += ph.p_memsz - ph.p_filesz;
            if maxp < pos {
                maxp = pos;
            }
        }
    }

    // ---- ELF header + section headers + symbols (LOAD_HDR | LOAD_SYM) ----
    let elfp = round_up(maxp as usize, 8) as u64;
    maxp = elfp;
    maxp += EHDR_SIZE as u64; // LOAD_HDR

    let sz = e_shnum * SHDR_SIZE;
    // Working copy of the section header table that we mutate, then BCOPY.
    let mut shp: alloc::vec::Vec<u8> = image[elf.e_shoff()..elf.e_shoff() + sz].to_vec();

    let shpp = maxp;
    maxp += round_up(sz, 8) as u64;

    let mut off = round_up(EHDR_SIZE + sz, 8) as u64;

    let mut havesyms = false;
    for i in 0..e_shnum {
        if elf.shdr(i).sh_type == SHT_SYMTAB {
            havesyms = true;
        }
    }

    for i in 0..e_shnum {
        if !is_loaded_section(&elf, i) {
            continue;
        }
        let sh = elf.shdr(i);
        let base = i * SHDR_SIZE;

        if havesyms {
            let dst = soff(maxp);
            write_at(
                staging,
                dst,
                &image[sh.sh_offset as usize..(sh.sh_offset + sh.sh_size) as usize],
                "symbol/string section",
            );
        }
        maxp += round_up(sh.sh_size as usize, 8) as u64;

        // shp[i].sh_offset = off; shp[i].sh_flags |= SHF_ALLOC;
        shp[base + 24..base + 32].copy_from_slice(&off.to_le_bytes());
        let sh_flags = rd_u64(&shp, base + 8) | SHF_ALLOC;
        shp[base + 8..base + 16].copy_from_slice(&sh_flags.to_le_bytes());

        off += round_up(sh.sh_size as usize, 8) as u64;
    }

    // BCOPY(shp, shpp, sz)
    let shpp_dst = soff(shpp);
    write_at(staging, shpp_dst, &shp, "section header table");

    // ---- Frob and copy the ELF header (LOAD_HDR) ----
    let mut ehdr: alloc::vec::Vec<u8> = image[0..EHDR_SIZE].to_vec();
    ehdr[32..40].copy_from_slice(&0u64.to_le_bytes()); // e_phoff = 0
    ehdr[40..48].copy_from_slice(&(EHDR_SIZE as u64).to_le_bytes()); // e_shoff
    ehdr[54..56].copy_from_slice(&0u16.to_le_bytes()); // e_phentsize = 0
    ehdr[56..58].copy_from_slice(&0u16.to_le_bytes()); // e_phnum = 0
    let elfp_dst = soff(elfp);
    write_at(staging, elfp_dst, &ehdr, "ELF header");

    marks[MARK_START] = loadaddr(minp);
    marks[MARK_ENTRY] = loadaddr(e_entry);
    marks[MARK_VENTRY] = e_entry;
    marks[MARK_NSYM] = 1;
    marks[MARK_SYM] = loadaddr(elfp);
    marks[MARK_END] = loadaddr(maxp);

    assert!(
        soff(maxp) <= staging.len(),
        "kernel image exceeds staging region"
    );

    LoadedKernel { marks, e_entry }
}

/// Assert that `[off, off+len)` fits within a staging region of `staging_len`
/// bytes, returning the end offset. Gives a clear diagnostic instead of an
/// opaque slice-index panic when a kernel image overruns the staging region.
fn check_bounds(staging_len: usize, off: usize, len: usize, what: &str) -> usize {
    let end = off + len;
    assert!(
        end <= staging_len,
        "{} at staging offset {:#x}..{:#x} exceeds the {:#x}-byte staging region",
        what,
        off,
        end,
        staging_len
    );
    end
}

/// Bounds-checked copy of `data` into `staging` at byte offset `off`.
fn write_at(staging: &mut [u8], off: usize, data: &[u8], what: &str) {
    let end = check_bounds(staging.len(), off, data.len(), what);
    staging[off..end].copy_from_slice(data);
}

/// Seed a ChaCha8 RNG from the CPU hardware RNG (RDRAND).
fn seed_chacha8() -> ChaCha8Rng {
    let mut seed = [0u8; 32];
    for chunk in seed.chunks_exact_mut(8) {
        chunk.copy_from_slice(&rand64().to_le_bytes());
    }
    ChaCha8Rng::from_seed(seed)
}

/// Read a 64-bit value from the CPU's hardware RNG. RDRAND is required.
fn rand64() -> u64 {
    let mut out: u64;
    let mut ok: u8;
    for _ in 0..100 {
        unsafe {
            core::arch::asm!(
                "rdrand {v}",
                "setc {ok}",
                v = out(reg) out,
                ok = out(reg_byte) ok,
                options(nostack, nomem),
            );
        }
        if ok != 0 {
            return out;
        }
    }
    panic!("RDRAND failed to produce a value");
}
