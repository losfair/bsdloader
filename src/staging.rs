use core::{
    ops::{Deref, DerefMut},
    ptr::NonNull,
};

use uefi::boot::MemoryType;

use crate::sysmem;
use crate::util::round_up;

pub const STAGING_ALIGNMENT: usize = sysmem::STAGING_ALIGN;
const BASE_START_GAP: usize = 0x20_0000;

pub struct StagingRegion {
    ptr: NonNull<u8>,
    len: usize,
    watermark: usize,
}

pub struct StagingRegionHandle {
    ptr: NonNull<u8>,
    len: usize,
    vm_offset_from_base: usize,
}

impl StagingRegion {
    /// Allocate a staging region of (at least) `size` bytes below 4 GiB. No
    /// fallback: panics if the request cannot be satisfied.
    pub fn with_size(size: usize) -> Self {
        let (ptr, len) = sysmem::alloc_staging(size, 0x1_0000_0000u64, MemoryType::LOADER_CODE);
        unsafe {
            ptr.write_bytes(0, len);
        }
        log::info!("Allocated staging at {:p}, length {}", ptr, len);
        Self {
            ptr,
            len,
            watermark: 0,
        }
    }

    pub fn allocate(&mut self, len: usize) -> StagingRegionHandle {
        if self.watermark.saturating_add(len) > self.len {
            panic!("StagingRegion::allocate: overflow");
        }
        let h = StagingRegionHandle {
            ptr: unsafe { self.ptr.add(self.watermark) },
            len,
            vm_offset_from_base: BASE_START_GAP + self.watermark,
        };
        self.watermark += len;
        h
    }

    pub fn ptr(&self) -> NonNull<u8> {
        self.ptr
    }

    pub fn size(&self) -> usize {
        self.len
    }

    pub fn align(&mut self, to: usize) {
        assert!(to.is_power_of_two());
        self.watermark = round_up(self.watermark, to);
    }

    pub fn current_vm_offset_from_base(&self) -> usize {
        BASE_START_GAP + self.watermark
    }

    pub fn current_vm_offset_from_start(&self) -> usize {
        self.watermark
    }

    pub fn remaining(&self) -> usize {
        self.len - self.watermark
    }
}

impl StagingRegionHandle {
    pub fn vm_offset_from_base(&self) -> usize {
        self.vm_offset_from_base
    }

    pub fn into_mut_slice(self) -> &'static mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Deref for StagingRegionHandle {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr() as *const _, self.len) }
    }
}

impl DerefMut for StagingRegionHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}
