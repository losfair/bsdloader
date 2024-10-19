use core::{
    ops::{Deref, DerefMut},
    ptr::NonNull,
};

use uefi::{
    boot::{AllocateType, MemoryType, PAGE_SIZE},
    proto::media::file::{File, FileAttribute, FileInfo, FileMode},
    CStr16,
};

use crate::util::round_up;

pub struct OwnedBuffer {
    ptr: NonNull<u8>,
    len: usize,
    num_pages: usize,
}

impl OwnedBuffer {
    pub fn new(ty: AllocateType, len: usize) -> Self {
        let num_pages = round_up(len, PAGE_SIZE) / PAGE_SIZE;
        let ptr = uefi::boot::allocate_pages(ty, MemoryType::LOADER_DATA, num_pages)
            .expect("failed to allocate owned buffer");
        Self {
            ptr,
            len,
            num_pages,
        }
    }

    pub fn leak(self) -> &'static mut [u8] {
        let ptr = self.ptr;
        let len = self.len;
        core::mem::forget(self);
        unsafe { core::slice::from_raw_parts_mut(ptr.as_ptr(), len) }
    }
}

impl Drop for OwnedBuffer {
    fn drop(&mut self) {
        unsafe {
            uefi::boot::free_pages(self.ptr, self.num_pages).expect("failed to free owned buffer");
        }
    }
}

impl Deref for OwnedBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl DerefMut for OwnedBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

pub fn load_image_from_disk(filename: &str, buffer: &mut [u8]) -> Option<usize> {
    let mut fs = match uefi::boot::get_image_file_system(uefi::boot::image_handle()) {
        Ok(x) => x,
        Err(e) => {
            log::error!("failed to get image file system: {:?}", e);
            return None;
        }
    };
    let mut volume = match fs.open_volume() {
        Ok(x) => x,
        Err(e) => {
            log::error!("failed to open volume: {:?}", e);
            return None;
        }
    };
    let mut filename_buf = [0u16; 16];
    let filename = CStr16::from_str_with_buf(filename, &mut filename_buf).unwrap();
    let file = match volume.open(filename, FileMode::Read, FileAttribute::empty()) {
        Ok(x) => x,
        Err(e) => {
            log::error!("failed to open file: {:?}", e);
            return None;
        }
    };
    let mut file = match file.into_regular_file() {
        Some(x) => x,
        None => {
            log::error!("image is not a regular file");
            return None;
        }
    };
    let mut file_info = OwnedBuffer::new(AllocateType::AnyPages, 4096);
    let info = match file.get_info::<FileInfo>(&mut file_info) {
        Ok(x) => x,
        Err(e) => {
            log::error!("failed to get file info: {:?}", e);
            return None;
        }
    };
    let size = info.file_size() as usize;
    if size > buffer.len() {
        panic!(
            "buffer too small, needed: {}, actual: {}",
            size,
            buffer.len()
        );
    }
    let n = match file.read(buffer) {
        Ok(x) => x,
        Err(e) => {
            log::error!("failed to read file: {:?}", e);
            return None;
        }
    };

    log::info!("Loaded file: {}, size: {}", filename, size);

    Some(n)
}
