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

const PT_LOAD: u32 = 1;
const PT_OPENBSD_RANDOMIZE: u32 = 0x65a3_dbe6;

const PF_X: u32 = 0x1;
const PF_W: u32 = 0x2;
const PF_R: u32 = 0x4;

const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHF_ALLOC: u64 = 0x2;

const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const SHDR_SIZE: usize = 64;

const ELF_CTF: &[u8] = b".SUNW_ctf";
const DEBUG_LINE: &[u8] = b".debug_line";

#[inline]
fn rd_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}
#[inline]
fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
#[inline]
fn rd_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

struct Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
}

fn phdr(b: &[u8], off: usize) -> Phdr {
    Phdr {
        p_type: rd_u32(b, off),
        p_flags: rd_u32(b, off + 4),
        p_offset: rd_u64(b, off + 8),
        p_paddr: rd_u64(b, off + 24),
        p_filesz: rd_u64(b, off + 32),
        p_memsz: rd_u64(b, off + 40),
    }
}

pub struct LoadedKernel {
    pub marks: [u64; MARK_MAX],
    pub e_entry: u64,
}

/// Load `image` (a decompressed ELF64) into `staging` (the EFI load space whose
/// base physical address is `efi_loadaddr`).  Returns the OpenBSD `marks[]`.
pub fn load(image: &[u8], staging: &mut [u8], efi_loadaddr: u64) -> LoadedKernel {
    assert!(&image[0..4] == b"\x7fELF", "not an ELF image");
    assert!(image[4] == 2, "not ELF64");
    assert!(image[5] == 1, "not little-endian ELF");

    let e_entry = rd_u64(image, 24);
    let e_phoff = rd_u64(image, 32) as usize;
    let e_shoff = rd_u64(image, 40) as usize;
    let e_phnum = rd_u16(image, 56) as usize;
    let e_shnum = rd_u16(image, 60) as usize;
    let e_shstrndx = rd_u16(image, 62) as usize;

    // offset == marks[MARK_START] == 0 for the EFI boot path.
    let loadaddr = |a: u64| -> u64 { (a & 0x0fff_ffff) + efi_loadaddr };
    // Byte offset of an absolute load address within `staging`.
    let soff = |a: u64| -> usize { (a & 0x0fff_ffff) as usize };

    let mut marks = [0u64; MARK_MAX];

    let mut minp: u64 = !0;
    let mut maxp: u64 = 0;

    // ---- Program headers: text/data/bss + randomize ----
    for i in 0..e_phnum {
        let ph = phdr(image, e_phoff + i * PHDR_SIZE);

        if ph.p_type == PT_OPENBSD_RANDOMIZE {
            let dst = soff(ph.p_paddr);
            fill_random(&mut staging[dst..dst + ph.p_filesz as usize]);
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
        staging[dst..dst + fsz].copy_from_slice(&image[fstart..fstart + fsz]);

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
            staging[bss..bss + bsz].fill(0);
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
    let mut shp: alloc::vec::Vec<u8> = image[e_shoff..e_shoff + sz].to_vec();

    let shpp = maxp;
    maxp += round_up(sz, 8) as u64;

    // Section header string table.
    let shstr_off = rd_u64(&shp, e_shstrndx * SHDR_SIZE + 24) as usize;
    let shstr_sz = rd_u64(&shp, e_shstrndx * SHDR_SIZE + 32) as usize;
    let shstr = &image[shstr_off..shstr_off + shstr_sz];

    let mut off = round_up(EHDR_SIZE + sz, 8) as u64;

    let mut havesyms = false;
    for i in 0..e_shnum {
        if rd_u32(&shp, i * SHDR_SIZE + 4) == SHT_SYMTAB {
            havesyms = true;
        }
    }

    for i in 0..e_shnum {
        let base = i * SHDR_SIZE;
        let sh_name = rd_u32(&shp, base) as usize;
        let sh_type = rd_u32(&shp, base + 4);
        let sh_offset = rd_u64(&shp, base + 24) as usize;
        let sh_size = rd_u64(&shp, base + 32);

        let name = cstr(shstr, sh_name);
        let want = sh_type == SHT_SYMTAB
            || sh_type == SHT_STRTAB
            || name == DEBUG_LINE
            || name == ELF_CTF;
        if !want {
            continue;
        }

        if havesyms {
            let dst = soff(maxp);
            staging[dst..dst + sh_size as usize]
                .copy_from_slice(&image[sh_offset..sh_offset + sh_size as usize]);
        }
        maxp += round_up(sh_size as usize, 8) as u64;

        // shp[i].sh_offset = off; shp[i].sh_flags |= SHF_ALLOC;
        shp[base + 24..base + 32].copy_from_slice(&off.to_le_bytes());
        let sh_flags = rd_u64(&shp, base + 8) | SHF_ALLOC;
        shp[base + 8..base + 16].copy_from_slice(&sh_flags.to_le_bytes());

        off += round_up(sh_size as usize, 8) as u64;
    }

    // BCOPY(shp, shpp, sz)
    let shpp_dst = soff(shpp);
    staging[shpp_dst..shpp_dst + sz].copy_from_slice(&shp);

    // ---- Frob and copy the ELF header (LOAD_HDR) ----
    let mut ehdr: alloc::vec::Vec<u8> = image[0..EHDR_SIZE].to_vec();
    ehdr[32..40].copy_from_slice(&0u64.to_le_bytes()); // e_phoff = 0
    ehdr[40..48].copy_from_slice(&(EHDR_SIZE as u64).to_le_bytes()); // e_shoff
    ehdr[54..56].copy_from_slice(&0u16.to_le_bytes()); // e_phentsize = 0
    ehdr[56..58].copy_from_slice(&0u16.to_le_bytes()); // e_phnum = 0
    let elfp_dst = soff(elfp);
    staging[elfp_dst..elfp_dst + EHDR_SIZE].copy_from_slice(&ehdr);

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

fn cstr(strtab: &[u8], off: usize) -> &[u8] {
    let end = strtab[off..]
        .iter()
        .position(|&c| c == 0)
        .map(|p| off + p)
        .unwrap_or(strtab.len());
    &strtab[off..end]
}

/// Fill a buffer with random bytes for `PT_OPENBSD_RANDOMIZE`.
/// Prefers RDRAND; falls back to a TSC-seeded xorshift if unavailable.
fn fill_random(buf: &mut [u8]) {
    let mut chunks = buf.chunks_exact_mut(8);
    for c in &mut chunks {
        c.copy_from_slice(&rand64().to_le_bytes());
    }
    let rem = chunks.into_remainder();
    if !rem.is_empty() {
        let r = rand64().to_le_bytes();
        rem.copy_from_slice(&r[..rem.len()]);
    }
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
