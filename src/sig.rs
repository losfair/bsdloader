//! Shared Ed25519 signature verification and signing-key measurement.
//!
//! Used by both backends so the security-critical verify/measure logic lives in
//! exactly one place; only the signed manifest differs per backend.

use alloc::format;
use alloc::vec;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use uefi::proto::tcg::PcrIndex;

use crate::image_loader::load_image_from_disk;
use crate::tpm::measure_image;

/// Verify the optional `siginfo` Ed25519 signature over `manifest`, then
/// **always** measure the signing public key into **PCR 14** as an `EV_IPL`
/// event (32 zero bytes when no `siginfo` is present, so the PCR distinguishes
/// "unsigned" from a specific key).
///
/// `siginfo` on the ESP is two hex lines: the 32-byte public key, then the
/// 64-byte signature over `manifest`. If `siginfo` is present and verification
/// fails, the boot is aborted.
pub fn verify_and_measure_key(manifest: &[u8]) {
    let mut siginfo = vec![0u8; 256];
    let public_key: [u8; 32] = if let Some(n) = load_image_from_disk("siginfo", &mut siginfo) {
        let mut lines = core::str::from_utf8(&siginfo[..n])
            .expect("siginfo is not valid utf-8")
            .split('\n');
        let mut public_key = [0u8; 32];
        let mut signature = [0u8; 64];
        hex::decode_to_slice(
            lines.next().expect("missing public key").as_bytes(),
            &mut public_key,
        )
        .expect("invalid public key");
        hex::decode_to_slice(
            lines.next().expect("missing signature").as_bytes(),
            &mut signature,
        )
        .expect("invalid signature");
        VerifyingKey::from_bytes(&public_key)
            .expect("public key is not valid ed25519 point")
            .verify(manifest, &Signature::from_bytes(&signature))
            .expect("signature verification failed");
        log::info!("Verified Ed25519 signature");
        public_key
    } else {
        [0u8; 32]
    };

    let mut public_key_hex = [0u8; 64];
    hex::encode_to_slice(&public_key, &mut public_key_hex).unwrap();
    let public_key_hex = core::str::from_utf8(&public_key_hex).unwrap();
    let public_key_desc = format!("ed25519-{}", public_key_hex).into_bytes();
    measure_image(&public_key_desc, PcrIndex(14), &public_key_desc);
}
