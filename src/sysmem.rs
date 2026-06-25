//! Shared physical-memory helpers for dynamically-sized staging regions.
//!
//! Both backends compute the exact staging size they need from the kernel
//! image, then allocate it here. There is intentionally **no fallback**: if the
//! request cannot be satisfied, allocation panics with a diagnostic rather than
//! silently shrinking or retrying.

use core::ptr::NonNull;

use uefi::boot::{AllocateType, MemoryType, PAGE_SIZE};
use uefi::mem::memory_map::{MemoryMap, MemoryMapOwned};

use crate::util::round_up;

/// Staging regions are aligned (and the FreeBSD page tables mapped) in 2 MiB
/// units.
pub const STAGING_ALIGN: usize = 2 * 1024 * 1024;

/// Total free conventional memory strictly below `limit`, in bytes.
pub fn free_below(limit: u64) -> u64 {
    let mm: MemoryMapOwned =
        uefi::boot::memory_map(MemoryType::LOADER_DATA).expect("failed to get UEFI memory map");
    let mut free = 0u64;
    for d in mm.entries() {
        if d.ty != MemoryType::CONVENTIONAL {
            continue;
        }
        let start = d.phys_start;
        if start >= limit {
            continue;
        }
        let end = start + d.page_count * PAGE_SIZE as u64;
        free += end.min(limit) - start;
    }
    free
}

/// Allocate a staging region of at least `size` bytes with a 2 MiB-aligned
/// base, entirely below `max_addr`, of memory type `mem_type`. Returns the
/// aligned base pointer and the usable length (a multiple of 2 MiB, `>= size`).
///
/// Panics — with the requested size and the amount actually free — if the
/// request does not fit available memory or the allocation fails.
pub fn alloc_staging(
    size: usize,
    max_addr: u64,
    mem_type: MemoryType,
) -> (NonNull<u8>, usize) {
    // Over-allocate by one alignment unit so the base can be rounded up.
    let raw = round_up(size, PAGE_SIZE) + STAGING_ALIGN;
    let free = free_below(max_addr);
    if (raw as u64) > free {
        panic!(
            "staging needs {} MiB below {:#x}, but only {} MiB is free",
            raw / 1048576,
            max_addr,
            free / 1048576
        );
    }
    let ptr = uefi::boot::allocate_pages(
        AllocateType::MaxAddress(max_addr),
        mem_type,
        raw / PAGE_SIZE,
    )
    .unwrap_or_else(|e| {
        panic!(
            "failed to allocate {} MiB staging below {:#x}: {:?}",
            raw / 1048576,
            max_addr,
            e
        )
    });
    let off = ptr.align_offset(STAGING_ALIGN);
    let base = unsafe { ptr.add(off) };
    let len = (raw - off) & !(STAGING_ALIGN - 1);
    assert!(len >= size);
    (base, len)
}
