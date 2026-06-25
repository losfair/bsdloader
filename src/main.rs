#![no_main]
#![no_std]

extern crate alloc;

#[cfg(not(any(feature = "openbsd", feature = "freebsd")))]
compile_error!(
    "a backend feature is required: build with `--no-default-features --features openbsd` \
     or `--no-default-features --features freebsd`"
);

#[cfg(all(feature = "openbsd", feature = "freebsd"))]
compile_error!("the `openbsd` and `freebsd` features are mutually exclusive; enable exactly one");

mod image_loader;
mod tpm;
mod util;

#[cfg(feature = "freebsd")]
mod boot;
#[cfg(feature = "freebsd")]
mod freebsd_main;
#[cfg(feature = "freebsd")]
mod modinfo;
#[cfg(feature = "freebsd")]
mod staging;

#[cfg(feature = "openbsd")]
mod openbsd;

use uefi::prelude::*;

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();

    log::info!("bsdloader starting...");

    #[cfg(feature = "openbsd")]
    {
        openbsd::run()
    }

    #[cfg(feature = "freebsd")]
    {
        freebsd_main::run()
    }
}
