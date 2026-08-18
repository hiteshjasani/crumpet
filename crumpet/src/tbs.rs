use std::error::Error;

use super::tpm::{commands::*, constants::*};

/// TPM Base Services
pub trait Tbs: Sized {
    fn open() -> Result<Self, Box<dyn Error>>;
    fn submit_command(&self, command: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;
}

/// Queries TPM_PT_NV_BUFFER_MAX; falls back to a conservative default if the
/// property isn't reported (some TPMs omit it, meaning "use the command's
/// natural limit", which is safely covered by our fallback).
fn get_nv_buffer_max(tbs: &impl Tbs) -> u16 {
    const FALLBACK: u16 = 1024;
    let try_it = || -> Result<u16, Box<dyn Error>> {
        let cmd = build_get_capability_command(TPM_CAP_TPM_PROPERTIES, TPM_PT_NV_BUFFER_MAX, 1);
        let resp = tbs.submit_command(&cmd)?;
        let mut r = Reader::new(&resp);
        let _tag = r.u16()?;
        let _size = r.u32()?;
        let rc = r.u32()?;
        if rc != 0 {
            return Err(format!("GetCapability failed: 0x{:08X}", rc).into());
        }
        let _more_data = r.u8()?;
        let _capability = r.u32()?;
        let count = r.u32()?;
        if count == 0 {
            return Ok(FALLBACK);
        }
        let property = r.u32()?;
        let value = r.u32()?;
        if property == TPM_PT_NV_BUFFER_MAX && value > 0 && value <= u16::MAX as u32 {
            Ok(value as u16)
        } else {
            Ok(FALLBACK)
        }
    };
    try_it().unwrap_or(FALLBACK)
}

/// Reads an NV index (e.g. the EK certificate) in chunks and returns the
/// concatenated raw bytes.
pub fn read_nv_data(tbs: &impl Tbs, nv_index: u32) -> Result<Vec<u8>, Box<dyn Error>> {
    let pub_cmd = build_nv_read_public_command(nv_index);
    let pub_resp = tbs.submit_command(&pub_cmd)?;
    let total_size = parse_nv_read_public_response(&pub_resp)?;
    if total_size == 0 {
        return Err("NV index is defined but empty".into());
    }

    let chunk_max = get_nv_buffer_max(tbs);
    let mut data = Vec::with_capacity(total_size as usize);
    let mut offset: u16 = 0;
    while (offset as u32) < total_size as u32 {
        let remaining = total_size - offset;
        let this_chunk = remaining.min(chunk_max);
        let cmd = build_nv_read_command(nv_index, this_chunk, offset);
        let resp = tbs.submit_command(&cmd)?;
        let chunk = parse_nv_read_response(&resp)?;
        if chunk.is_empty() {
            return Err("NV_Read returned no data before expected end".into());
        }
        offset += chunk.len() as u16;
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

// ---------- Creating/loading a child key parented under the EK ----------
//
// The EK's policy requires TPM2_PolicySecret against TPM_RH_ENDORSEMENT.
// Standard provisioning leaves endorsementAuth empty, so this needs no
// privilege beyond ordinary TBS access - no admin, no owner password.

/// Starts a fresh policy session and satisfies it against TPM_RH_ENDORSEMENT
/// with empty auth. Returns a session handle good for exactly one further
/// authorized command (continueSession is left unset, so the TPM flushes it
/// automatically after that command completes).
fn get_endorsement_policy_session(tbs: &impl Tbs) -> Result<u32, Box<dyn Error>> {
    let resp = tbs.submit_command(&build_start_auth_session_command())?;
    let session = parse_start_auth_session_response(&resp)?;
    let resp2 = tbs.submit_command(&build_policy_secret_command(session))?;
    parse_policy_secret_response(&resp2)?;
    Ok(session)
}

pub fn create_child_under_ek(
    tbs: &impl Tbs,
    parent_handle: u32,
    auth_value: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let session = get_endorsement_policy_session(tbs)?;
    let template = build_rsa_signing_template();
    let cmd = build_create_command(parent_handle, session, auth_value, &template);
    let resp = tbs.submit_command(&cmd)?;
    parse_create_response(&resp)
}

pub fn load_child_under_ek(
    tbs: &impl Tbs,
    parent_handle: u32,
    in_private: &[u8],
    in_public: &[u8],
) -> Result<u32, Box<dyn Error>> {
    let session = get_endorsement_policy_session(tbs)?;
    let cmd = build_load_command(parent_handle, session, in_private, in_public);
    let resp = tbs.submit_command(&cmd)?;
    parse_load_response(&resp)
}

/// Hashes `data` with SHA-256 and signs it with an already-loaded key.
/// Returns the raw PKCS#1 v1.5 signature bytes.
pub fn sign_with_child_key(
    tbs: &impl Tbs,
    key_handle: u32,
    key_auth: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    let cmd = build_sign_command(key_handle, key_auth, &digest);
    let resp = tbs.submit_command(&cmd)?;
    parse_sign_response(&resp)
}

pub fn flush_context(tbs: &impl Tbs, handle: u32) -> Result<(), Box<dyn Error>> {
    let cmd = build_flush_context_command(handle);
    let resp = tbs.submit_command(&cmd)?;
    parse_flush_context_response(&resp)
}

pub fn try_read_ek(tbs: &impl Tbs, handle: u32) -> Result<EkPublic, Box<dyn Error>> {
    let cmd = build_read_public_command(handle);
    let resp = tbs.submit_command(&cmd)?;
    parse_read_public_response(&resp)
}

/// Sends `TPM2_Startup(TPM_SU_CLEAR)`. A freshly-connected simulator (e.g.
/// the `mssim` backend talking to tpmsim.rs) rejects every other command
/// until this succeeds; call it once right after `Tbs::open()`.
pub fn startup_clear(tbs: &impl Tbs) -> Result<(), Box<dyn Error>> {
    let resp = tbs.submit_command(&build_startup_command(TPM_SU_CLEAR))?;
    parse_startup_response(&resp)
}
