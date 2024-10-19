pub fn round_up(n: usize, sz: usize) -> usize {
    (n + (sz - 1)) & !(sz - 1)
}

pub fn any_to_bytes<T>(x: &T) -> &[u8] {
    unsafe { core::slice::from_raw_parts(x as *const T as *const u8, core::mem::size_of::<T>()) }
}
