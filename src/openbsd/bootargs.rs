//! OpenBSD 32-bit bootarg vector construction.
//!
//! Mirrors `makebootargs32()` in `sys/stand/boot/bootarg.c` and the record
//! structs in `machine/biosvar.h`.  Each record is laid out as:
//!
//! ```text
//!   int ba_type;   /* 4 */
//!   int ba_size;   /* 4 -- == 12 + payload_len */
//!   int ba_nextX;  /* 4 -- unused in the flattened vector */
//!   u_char ba_arg[payload_len];
//! ```
//!
//! and the vector is terminated by a lone `int ba_type = BOOTARG_END (-1)`.

use crate::util::any_to_bytes;

// bootarg types (machine/biosvar.h, stand/boot/bootarg.h)
pub const BOOTARG_MEMMAP: i32 = 0;
pub const BOOTARG_CONSDEV: i32 = 5;
pub const BOOTARG_BOOTDUID: i32 = 9;
pub const BOOTARG_EFIINFO: i32 = 11;
pub const BOOTARG_END: i32 = -1;

// BOOTARG_APIVER = BAPIV_VECTOR | BAPIV_ENV | BAPIV_BMEMMAP
pub const BOOTARG_APIVER: u32 = 0x0000_0002 | 0x0000_0004 | 0x0000_0008;

// bios_efiinfo flags
pub const BEI_64BIT: u32 = 0x0000_0001;

#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
pub struct BiosEfiInfo {
    pub config_acpi: u64,
    pub config_smbios: u64,
    pub fb_addr: u64,
    pub fb_size: u64,
    pub fb_height: u32,
    pub fb_width: u32,
    pub fb_pixpsl: u32,
    pub fb_red_mask: u32,
    pub fb_green_mask: u32,
    pub fb_blue_mask: u32,
    pub fb_reserved_mask: u32,
    pub flags: u32,
    pub mmap_desc_ver: u32,
    pub mmap_desc_size: u32,
    pub mmap_size: u32,
    pub mmap_start: u64,
    pub system_table: u64,
    pub config_esrt: u64,
}

#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
pub struct BiosConsdev {
    pub consdev: i32,
    pub conspeed: i32,
    pub consaddr: u64,
    pub consfreq: i32,
    pub flags: u32,
    pub reg_width: i32,
    pub reg_shift: i32,
}

/// OpenBSD makedev(major, minor).
pub const fn makedev(maj: u32, min: u32) -> i32 {
    (((maj & 0xff) << 8) | (min & 0xff) | ((min & 0xffff00) << 8)) as i32
}

/// Incrementally builds a bootarg32 vector into a fixed buffer.
pub struct BootArgs<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> BootArgs<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        BootArgs { buf, pos: 0 }
    }

    pub fn push(&mut self, ty: i32, payload: &[u8]) {
        let size = 12 + payload.len();
        let p = self.pos;
        self.buf[p..p + 4].copy_from_slice(&ty.to_le_bytes());
        self.buf[p + 4..p + 8].copy_from_slice(&(size as i32).to_le_bytes());
        self.buf[p + 8..p + 12].copy_from_slice(&0i32.to_le_bytes());
        self.buf[p + 12..p + 12 + payload.len()].copy_from_slice(payload);
        self.pos += size;
    }

    pub fn push_struct<T>(&mut self, ty: i32, v: &T) {
        self.push(ty, any_to_bytes(v));
    }

    /// Write the `BOOTARG_END` terminator and return `ac`, the total length
    /// reported to the kernel (matching makebootargs32: `sizeof(bootarg32) +
    /// sum(record sizes)`).
    pub fn finish(&mut self) -> usize {
        let p = self.pos;
        self.buf[p..p + 4].copy_from_slice(&BOOTARG_END.to_le_bytes());
        16 + self.pos
    }
}

/// Raw serial (COM1) debug output usable after ExitBootServices.
pub mod serial {
    use core::arch::asm;

    const COM1: u16 = 0x3f8;

    #[inline]
    unsafe fn outb(port: u16, val: u8) {
        asm!("out dx, al", in("dx") port, in("al") val, options(nostack, nomem));
    }
    #[inline]
    unsafe fn inb(port: u16) -> u8 {
        let v: u8;
        asm!("in al, dx", out("al") v, in("dx") port, options(nostack, nomem));
        v
    }

    pub fn putc(c: u8) {
        unsafe {
            // wait for THR empty (LSR bit 5)
            while inb(COM1 + 5) & 0x20 == 0 {}
            outb(COM1, c);
        }
    }

    pub fn puts(s: &str) {
        for &b in s.as_bytes() {
            if b == b'\n' {
                putc(b'\r');
            }
            putc(b);
        }
    }

    pub fn puthex(v: u64) {
        puts("0x");
        let mut started = false;
        for i in (0..16).rev() {
            let nib = ((v >> (i * 4)) & 0xf) as u8;
            if nib != 0 || started || i == 0 {
                started = true;
                let c = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
                putc(c);
            }
        }
    }
}
