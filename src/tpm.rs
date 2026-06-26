use core::sync::atomic::AtomicBool;

use alloc::vec::Vec;
use uefi::{
    proto::tcg::{
        v2::{HashLogExtendEventFlags, PcrEvent, PcrEventDigests, PcrEventInputs, Tcg},
        EventType, PcrIndex,
    },
    Identify,
};

#[cfg(feature = "freebsd")]
use uefi::boot::PAGE_SIZE;

#[cfg(feature = "freebsd")]
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

#[cfg(feature = "freebsd")]
pub fn read_tpm_event_log(staging: &mut StagingRegion) -> Option<StagingRegionHandle> {
    let data = read_tpm_event_log_bytes()?;
    let buf_size = data.len() + 4;
    let mut buf = staging.allocate(round_up(buf_size, PAGE_SIZE));
    buf.iter_mut().zip(data).for_each(|(a, b)| *a = b);
    Some(buf)
}

pub fn read_tpm_event_log_bytes() -> Option<Vec<u8>> {
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

    // Active PCR-bank algorithms, taken from the first crypto-agile event.
    let algs: Vec<u16> = event_log
        .iter()
        .next()
        .map(|first| {
            fix_pcr_event_digests_lifetime(&first)
                .into_iter()
                .map(|digest| (digest.0).0)
                .collect()
        })
        .unwrap_or_default();

    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(header);
    for log in event_log.iter() {
        data.extend_from_slice(&log.pcr_index().0.to_le_bytes());
        data.extend_from_slice(&log.event_type().0.to_le_bytes());
        data.extend_from_slice(
            &(fix_pcr_event_digests_lifetime(&log).into_iter().count() as u32).to_le_bytes(),
        );
        for digest in fix_pcr_event_digests_lifetime(&log).into_iter() {
            data.extend_from_slice(&(digest.0).0.to_le_bytes());
            data.extend_from_slice(digest.1);
        }
        data.extend_from_slice(&(log.event_data().len() as u32).to_le_bytes());
        data.extend_from_slice(fix_pcr_event_data_lifetime(&log));
    }

    // The firmware measures these EV_EFI_ACTION events into PCR 5 as part of
    // ExitBootServices(), which happens *after* we snapshot the TCG2 log above,
    // so they are missing from our copy even though the live PCR 5 (and any
    // later quote) reflects them. Append them with the correct EV_EFI_ACTION
    // type so the handed-off log replays cleanly against the post-EBS PCR 5.
    // Without this, parsers such as go-eventlog detect the gap, inject
    // synthetic EBS events with a default (EV_PREBOOT_CERT) type, and then
    // reject the log ("ExitBootServices event but non EFIAction type: 0").
    if !algs.is_empty() {
        const EV_EFI_ACTION: u32 = 0x8000_0007;
        const EBS_PCR: u32 = 5;
        for action in [
            b"Exit Boot Services Invocation".as_slice(),
            b"Exit Boot Services Returned with Success".as_slice(),
        ] {
            data.extend(encode_event2(EBS_PCR, EV_EFI_ACTION, &algs, action));
        }
    }

    Some(data)
}

/// Hash `data` with the TPM hash algorithm identified by `alg` (a `TPMI_ALG_HASH`
/// value as it appears in a crypto-agile event log).
fn hash_action(alg: u16, data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    match alg {
        0x0004 => sha1::Sha1::digest(data).to_vec(),
        0x000b => sha2::Sha256::digest(data).to_vec(),
        0x000c => sha2::Sha384::digest(data).to_vec(),
        0x000d => sha2::Sha512::digest(data).to_vec(),
        other => panic!("unsupported TPM event-log hash algorithm {other:#06x}"),
    }
}

/// Encode a TCG_PCR_EVENT2 record (crypto-agile event log entry) for the given
/// PCR, event type, active hash algorithms and event data. The recorded digest
/// for each bank is the hash of `data`, matching how firmware measures
/// EV_EFI_ACTION events.
fn encode_event2(pcr: u32, event_type: u32, algs: &[u16], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&pcr.to_le_bytes());
    out.extend_from_slice(&event_type.to_le_bytes());
    out.extend_from_slice(&(algs.len() as u32).to_le_bytes());
    for &alg in algs {
        out.extend_from_slice(&alg.to_le_bytes());
        out.extend_from_slice(&hash_action(alg, data));
    }
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    out
}

pub fn measure_image(image: &[u8], pcr: PcrIndex, event_data: &[u8]) {
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

    protocol
        .hash_log_extend_event(
            HashLogExtendEventFlags::empty(),
            image,
            &PcrEventInputs::new_in_box(pcr, EventType::IPL, event_data)
                .expect("failed to create PcrEventInputs"),
        )
        .expect("failed to extend PCR");
    log::info!("Extended PCR {}", pcr.0);
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
