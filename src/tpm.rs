use core::sync::atomic::AtomicBool;

use alloc::format;
use uefi::{
    boot::PAGE_SIZE,
    proto::tcg::{
        v2::{HashLogExtendEventFlags, PcrEvent, PcrEventDigests, PcrEventInputs, Tcg},
        EventType, PcrIndex,
    },
    Identify,
};

use crate::{
    staging::{StagingRegion, StagingRegionHandle},
    util::round_up,
};

#[allow(dead_code)]
struct VeryUnsafeEventLog {
    location: *const u8,
    last_entry: *const u8,

    is_truncated: bool,
}

pub fn read_tpm_event_log(staging: &mut StagingRegion) -> Option<StagingRegionHandle> {
    let Some(protocol) =
        uefi::boot::locate_handle_buffer(uefi::boot::SearchType::ByProtocol(&Tcg::GUID))
            .ok()
            .and_then(|x| x.get(0).copied())
    else {
        return None;
    };

    let mut protocol =
        uefi::boot::open_protocol_exclusive::<Tcg>(protocol).expect("failed to open Tcg protocol");

    let event_log = protocol
        .get_event_log_v2()
        .expect("failed to get event log");

    let unsafe_event_log: VeryUnsafeEventLog = unsafe { core::mem::transmute_copy(&event_log) };
    let header = get_tpm2_header(&unsafe_event_log);
    log::info!(
        "TPM event log location: {:p}, header size {}",
        unsafe_event_log.location,
        header.len()
    );

    let it = || {
        let body = event_log.iter().flat_map(|log| {
            log.pcr_index()
                .0
                .to_le_bytes()
                .into_iter()
                .chain(log.event_type().0.to_le_bytes())
                .chain(
                    (fix_pcr_event_digests_lifetime(&log).into_iter().count() as u32).to_le_bytes(),
                )
                .chain(
                    fix_pcr_event_digests_lifetime(&log)
                        .into_iter()
                        .flat_map(|digest| {
                            digest
                                .0
                                 .0
                                .to_le_bytes()
                                .into_iter()
                                .chain(digest.1.iter().copied())
                        }),
                )
                .chain((log.event_data().len() as u32).to_le_bytes())
                .chain(fix_pcr_event_data_lifetime(&log).iter().copied())
        });
        header.iter().copied().chain(body)
    };

    let data_size = it().count();
    let buf_size = data_size + 4;
    let mut buf = staging.allocate(round_up(buf_size, PAGE_SIZE));
    buf.iter_mut().zip(it()).for_each(|(a, b)| *a = b);
    Some(buf)
}

pub fn measure_image(image: &[u8], pcr: PcrIndex, image_name: &str) {
    static DID_PRINT_TCG_CAPABILITY: AtomicBool = AtomicBool::new(false);

    if image.is_empty() {
        panic!("measure_image: empty image");
    }

    if image.as_ptr() as usize + image.len() > 0x1_0000_0000usize {
        panic!("measure_image: image is not in lower 4GB");
    }

    let Some(protocol) =
        uefi::boot::locate_handle_buffer(uefi::boot::SearchType::ByProtocol(&Tcg::GUID))
            .ok()
            .and_then(|x| x.get(0).copied())
    else {
        return;
    };

    let mut protocol =
        uefi::boot::open_protocol_exclusive::<Tcg>(protocol).expect("failed to open Tcg protocol");

    if DID_PRINT_TCG_CAPABILITY
        .compare_exchange(
            false,
            true,
            core::sync::atomic::Ordering::Relaxed,
            core::sync::atomic::Ordering::Relaxed,
        )
        .is_ok()
    {
        let capability = protocol
            .get_capability()
            .expect("failed to get Tcg capability");

        log::info!("Tcg capability: {:?}", capability);
    }

    let event_data = format!("{}\0", image_name);
    protocol
        .hash_log_extend_event(
            HashLogExtendEventFlags::empty(),
            image,
            &PcrEventInputs::new_in_box(pcr, EventType::IPL, event_data.as_bytes())
                .expect("failed to create PcrEventInputs"),
        )
        .expect("failed to extend PCR");
    log::info!("Extended PCR {}: {}", pcr.0, image_name);
}

fn fix_pcr_event_digests_lifetime<'a>(event: &PcrEvent<'a>) -> PcrEventDigests<'a> {
    let bad = event.digests();
    unsafe { core::mem::transmute::<PcrEventDigests<'_>, PcrEventDigests<'a>>(bad) }
}

fn fix_pcr_event_data_lifetime<'a>(event: &PcrEvent<'a>) -> &'a [u8] {
    unsafe { core::mem::transmute::<&[u8], &'a [u8]>(event.event_data()) }
}

fn get_tpm2_header(log: &VeryUnsafeEventLog) -> &[u8] {
    unsafe {
        let ptr_u32: *const u32 = log.location.cast();
        let event_size = ptr_u32.add(7).read_unaligned() as usize;
        let header_size = event_size + 32;
        core::slice::from_raw_parts(log.location, header_size)
    }
}
