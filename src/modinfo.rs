use crate::{staging::StagingRegion, util::round_up};

pub const MODINFO_NAME: u32 = 0x0001; /* Name of module (string) */
pub const MODINFO_TYPE: u32 = 0x0002; /* Type of module (string) */
pub const MODINFO_ADDR: u32 = 0x0003; /* Loaded address */
pub const MODINFO_SIZE: u32 = 0x0004; /* Size of module */
pub const MODINFO_METADATA: u32 = 0x8000; /* Module-specfic */

pub const MODINFOMD_ENVP: u32 = 0x0006; /* envp[] */
pub const MODINFOMD_HOWTO: u32 = 0x0007; /* boothowto */
pub const MODINFOMD_FW_HANDLE: u32 = 0x000c; /* Firmware dependent handle */

#[cfg(target_arch = "x86_64")]
pub const MODINFOMD_EFI_MAP: u32 = 0x1004;
#[cfg(target_arch = "x86_64")]
pub const MODINFOMD_EFI_FB: u32 = 0x1005;

// pub const RB_VERBOSE: u32 = 0x800;
// pub const RB_SERIAL: u32 = 0x1000;
pub const RB_MULTIPLE: u32 = 0x20000000;

pub fn push(buffer: &mut StagingRegion, ty: u32, data: &[u8]) {
    allocate(buffer, ty, data.len()).copy_from_slice(data);
}

pub fn allocate(buffer: &mut StagingRegion, ty: u32, len: usize) -> &'static mut [u8] {
    let buffer = buffer
        .allocate(8 + round_up(len, core::mem::size_of::<usize>()))
        .into_mut_slice();
    buffer[0..4].copy_from_slice(&ty.to_le_bytes());
    buffer[4..8].copy_from_slice(&(len as u32).to_le_bytes());
    &mut buffer[8..8 + len]
}
