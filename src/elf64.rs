//! Minimal shared ELF64 parsing used by both the OpenBSD and FreeBSD backends.
//!
//! Each backend uses a different subset of the accessors/constants, so some are
//! unused in any single-feature build.
#![allow(dead_code)]

pub const PT_LOAD: u32 = 1;
pub const PT_OPENBSD_RANDOMIZE: u32 = 0x65a3_dbe6;

pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;

pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHF_ALLOC: u64 = 0x2;

pub const EHDR_SIZE: usize = 64;
pub const PHDR_SIZE: usize = 56;
pub const SHDR_SIZE: usize = 64;

#[inline]
pub fn rd_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
#[inline]
pub fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
#[inline]
pub fn rd_u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

pub struct Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
}

pub struct Shdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
}

/// A borrowed, bounds-checked view over an ELF64 little-endian image.
pub struct Elf<'a> {
    pub image: &'a [u8],
}

impl<'a> Elf<'a> {
    pub fn parse(image: &'a [u8]) -> Self {
        assert!(
            image.len() >= EHDR_SIZE && &image[0..4] == b"\x7fELF",
            "not an ELF image"
        );
        assert!(image[4] == 2, "not ELF64");
        assert!(image[5] == 1, "not little-endian ELF");
        Elf { image }
    }

    pub fn e_entry(&self) -> u64 {
        rd_u64(self.image, 24)
    }
    pub fn e_phoff(&self) -> usize {
        rd_u64(self.image, 32) as usize
    }
    pub fn e_shoff(&self) -> usize {
        rd_u64(self.image, 40) as usize
    }
    pub fn e_phnum(&self) -> usize {
        rd_u16(self.image, 56) as usize
    }
    pub fn e_shnum(&self) -> usize {
        rd_u16(self.image, 60) as usize
    }
    pub fn e_shstrndx(&self) -> usize {
        rd_u16(self.image, 62) as usize
    }

    pub fn phdr(&self, i: usize) -> Phdr {
        let o = self.e_phoff() + i * PHDR_SIZE;
        let b = self.image;
        Phdr {
            p_type: rd_u32(b, o),
            p_flags: rd_u32(b, o + 4),
            p_offset: rd_u64(b, o + 8),
            p_vaddr: rd_u64(b, o + 16),
            p_paddr: rd_u64(b, o + 24),
            p_filesz: rd_u64(b, o + 32),
            p_memsz: rd_u64(b, o + 40),
        }
    }

    pub fn shdr(&self, i: usize) -> Shdr {
        let o = self.e_shoff() + i * SHDR_SIZE;
        let b = self.image;
        Shdr {
            sh_name: rd_u32(b, o),
            sh_type: rd_u32(b, o + 4),
            sh_flags: rd_u64(b, o + 8),
            sh_offset: rd_u64(b, o + 24),
            sh_size: rd_u64(b, o + 32),
        }
    }

    /// The section-header string table bytes.
    pub fn shstrtab(&self) -> &'a [u8] {
        let sh = self.shdr(self.e_shstrndx());
        &self.image[sh.sh_offset as usize..(sh.sh_offset + sh.sh_size) as usize]
    }

    pub fn section_name(&self, sh: &Shdr) -> &'a [u8] {
        cstr(self.shstrtab(), sh.sh_name as usize)
    }

    /// `(file_offset, size)` of the first section named `name`, if any.
    pub fn section_by_name(&self, name: &[u8]) -> Option<(usize, usize)> {
        let strtab = self.shstrtab();
        for i in 0..self.e_shnum() {
            let sh = self.shdr(i);
            if cstr(strtab, sh.sh_name as usize) == name {
                return Some((sh.sh_offset as usize, sh.sh_size as usize));
            }
        }
        None
    }
}

pub fn cstr(strtab: &[u8], off: usize) -> &[u8] {
    let end = strtab[off..]
        .iter()
        .position(|&c| c == 0)
        .map(|p| off + p)
        .unwrap_or(strtab.len());
    &strtab[off..end]
}
