use std::error::Error;

use super::constants::*;

pub fn build_read_public_command(handle: u32) -> Vec<u8> {
    let mut cmd = Vec::new();
    cmd.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&[0u8; 4]); // placeholder for commandSize
    cmd.extend_from_slice(&TPM_CC_READ_PUBLIC.to_be_bytes());
    cmd.extend_from_slice(&handle.to_be_bytes());
    let len = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&len.to_be_bytes());
    cmd
}

pub fn parse_read_public_response(resp: &[u8]) -> Result<EkPublic, Box<dyn Error>> {
    let mut r = Reader::new(resp);
    let _tag = r.u16()?;
    let _size = r.u32()?;
    let rc = r.u32()?;
    if rc != 0 {
        return Err(format!("TPM returned error 0x{:08X}", rc).into());
    }

    // TPM2B_PUBLIC
    let public_size = r.u16()? as usize;
    let public_bytes = r.bytes(public_size)?;
    parse_public_area(public_bytes)
}

/// Parses a raw TPMT_PUBLIC byte span (the payload inside any TPM2B_PUBLIC -
/// from a ReadPublic response, a Create response's outPublic, etc.) into an
/// EkPublic. Also usable directly on a Create's outPublic blob by first
/// stripping its 2-byte TPM2B length prefix (see `parse_tpm2b_public`).
fn parse_public_area(public_bytes: &[u8]) -> Result<EkPublic, Box<dyn Error>> {
    let mut p = Reader::new(public_bytes);

    let obj_type = p.u16()?;
    let _name_alg = p.u16()?;
    let _object_attrs = p.u32()?;

    // authPolicy: TPM2B_DIGEST
    let auth_policy_size = p.u16()? as usize;
    p.bytes(auth_policy_size)?;

    match obj_type {
        TPM_ALG_RSA => {
            // TPMS_RSA_PARMS: symmetric, scheme, keyBits, exponent
            skip_sym_def(&mut p)?;
            skip_rsa_scheme(&mut p)?;
            let _key_bits = p.u16()?;
            let mut exponent = p.u32()?;
            if exponent == 0 {
                exponent = 65537; // TPM convention: 0 means the default 2^16+1
            }
            // unique: TPM2B_PUBLIC_KEY_RSA
            let mod_size = p.u16()? as usize;
            let modulus = p.bytes(mod_size)?.to_vec();
            Ok(EkPublic::Rsa { modulus, exponent })
        }
        TPM_ALG_ECC => {
            skip_sym_def(&mut p)?;
            let scheme = p.u16()?;
            if scheme != TPM_ALG_NULL {
                let _hash_alg = p.u16()?; // most ECC schemes carry a hash alg param
            }
            let curve_id = p.u16()?;
            let kdf = p.u16()?;
            if kdf != TPM_ALG_NULL {
                let _kdf_hash = p.u16()?;
            }
            // unique: TPMS_ECC_POINT { x: TPM2B, y: TPM2B }
            let x_size = p.u16()? as usize;
            let x = p.bytes(x_size)?.to_vec();
            let y_size = p.u16()? as usize;
            let y = p.bytes(y_size)?.to_vec();
            Ok(EkPublic::Ecc { curve_id, x, y })
        }
        other => Err(format!("unsupported public algorithm 0x{:04X}", other).into()),
    }
}

/// Strips a TPM2B_PUBLIC's 2-byte length prefix and parses what's inside.
pub fn parse_tpm2b_public(wrapped: &[u8]) -> Result<EkPublic, Box<dyn Error>> {
    let mut r = Reader::new(wrapped);
    let size = r.u16()? as usize;
    let bytes = r.bytes(size)?;
    parse_public_area(bytes)
}

fn skip_sym_def(p: &mut Reader) -> Result<(), Box<dyn Error>> {
    let alg = p.u16()?;
    if alg != TPM_ALG_NULL {
        let _key_bits = p.u16()?;
        let _mode = p.u16()?;
    }
    Ok(())
}

fn skip_rsa_scheme(p: &mut Reader) -> Result<(), Box<dyn Error>> {
    let scheme = p.u16()?;
    if scheme != TPM_ALG_NULL {
        // Virtually all RSA schemes (RSASSA, RSAES, RSAPSS, OAEP) carry a
        // single hash-algorithm parameter.
        let _hash_alg = p.u16()?;
    }
    Ok(())
}

// ---------- NV storage access (for the EK certificate) ----------

pub fn build_nv_read_public_command(nv_index: u32) -> Vec<u8> {
    let mut cmd = Vec::new();
    cmd.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&[0u8; 4]); // commandSize placeholder
    cmd.extend_from_slice(&TPM_CC_NV_READ_PUBLIC.to_be_bytes());
    cmd.extend_from_slice(&nv_index.to_be_bytes());
    let len = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&len.to_be_bytes());
    cmd
}

/// Returns the defined data size of the NV index (i.e. the certificate size).
pub fn parse_nv_read_public_response(resp: &[u8]) -> Result<u16, Box<dyn Error>> {
    let mut r = Reader::new(resp);
    let _tag = r.u16()?;
    let _size = r.u32()?;
    let rc = r.u32()?;
    if rc != 0 {
        return Err(format!("TPM returned error 0x{:08X}", rc).into());
    }

    let nv_public_size = r.u16()? as usize;
    let nv_public_bytes = r.bytes(nv_public_size)?;
    let mut p = Reader::new(nv_public_bytes);

    let _nv_index = p.u32()?;
    let _name_alg = p.u16()?;
    let _attributes = p.u32()?;
    let auth_policy_size = p.u16()? as usize;
    p.bytes(auth_policy_size)?;
    let data_size = p.u16()?;
    Ok(data_size)
}

pub fn build_nv_read_command(nv_index: u32, size: u16, offset: u16) -> Vec<u8> {
    // Authorization session area: TPM_RS_PW with empty nonce/hmac (empty auth).
    let mut auth_area = Vec::new();
    auth_area.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    auth_area.extend_from_slice(&0u16.to_be_bytes()); // nonce size = 0
    auth_area.push(0u8); // sessionAttributes = 0
    auth_area.extend_from_slice(&0u16.to_be_bytes()); // hmac size = 0

    let mut cmd = Vec::new();
    cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&[0u8; 4]); // commandSize placeholder
    cmd.extend_from_slice(&TPM_CC_NV_READ.to_be_bytes());
    cmd.extend_from_slice(&nv_index.to_be_bytes()); // authHandle (the index's own auth)
    cmd.extend_from_slice(&nv_index.to_be_bytes()); // nvIndex
    cmd.extend_from_slice(&(auth_area.len() as u32).to_be_bytes()); // authorizationSize
    cmd.extend_from_slice(&auth_area);
    cmd.extend_from_slice(&size.to_be_bytes());
    cmd.extend_from_slice(&offset.to_be_bytes());

    let len = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&len.to_be_bytes());
    cmd
}

pub fn parse_nv_read_response(resp: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut r = Reader::new(resp);
    let _tag = r.u16()?;
    let _size = r.u32()?;
    let rc = r.u32()?;
    if rc != 0 {
        return Err(format!("TPM returned error 0x{:08X}", rc).into());
    }
    let _parameter_size = r.u32()?; // present because tag == TPM_ST_SESSIONS
    let data_size = r.u16()? as usize;
    Ok(r.bytes(data_size)?.to_vec())
}

pub fn build_get_capability_command(capability: u32, property: u32, count: u32) -> Vec<u8> {
    let mut cmd = Vec::new();
    cmd.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&[0u8; 4]);
    cmd.extend_from_slice(&TPM_CC_GET_CAPABILITY.to_be_bytes());
    cmd.extend_from_slice(&capability.to_be_bytes());
    cmd.extend_from_slice(&property.to_be_bytes());
    cmd.extend_from_slice(&count.to_be_bytes());
    let len = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&len.to_be_bytes());
    cmd
}

pub fn build_start_auth_session_command() -> Vec<u8> {
    let nonce_caller = generate_nonce(32);
    let mut cmd = Vec::new();
    cmd.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&[0u8; 4]); // commandSize placeholder
    cmd.extend_from_slice(&TPM_CC_START_AUTH_SESSION.to_be_bytes());
    cmd.extend_from_slice(&TPM_RH_NULL.to_be_bytes()); // tpmKey: unsalted
    cmd.extend_from_slice(&TPM_RH_NULL.to_be_bytes()); // bind: unbound
    cmd.extend_from_slice(&tpm2b(&nonce_caller));
    cmd.extend_from_slice(&tpm2b(&[])); // encryptedSalt: none
    cmd.push(TPM_SE_POLICY);
    cmd.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // symmetric: none
    cmd.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes()); // authHash
    let len = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&len.to_be_bytes());
    cmd
}

pub fn parse_start_auth_session_response(resp: &[u8]) -> Result<u32, Box<dyn Error>> {
    let mut r = Reader::new(resp);
    let _tag = r.u16()?;
    let _size = r.u32()?;
    let rc = r.u32()?;
    if rc != 0 {
        return Err(format!("StartAuthSession failed: 0x{:08X}", rc).into());
    }
    let session_handle = r.u32()?;
    Ok(session_handle)
}

pub fn build_policy_secret_command(session_handle: u32) -> Vec<u8> {
    // Authorization area: TPM_RS_PW with empty password, authorizing
    // TPM_RH_ENDORSEMENT (assumes empty endorsementAuth, the default).
    let mut auth_area = Vec::new();
    auth_area.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    auth_area.extend_from_slice(&tpm2b(&[])); // nonce
    auth_area.push(0u8); // sessionAttributes
    auth_area.extend_from_slice(&tpm2b(&[])); // hmac (empty password)

    let mut cmd = Vec::new();
    cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&[0u8; 4]); // commandSize placeholder
    cmd.extend_from_slice(&TPM_CC_POLICY_SECRET.to_be_bytes());
    cmd.extend_from_slice(&TPM_RH_ENDORSEMENT.to_be_bytes()); // authHandle
    cmd.extend_from_slice(&session_handle.to_be_bytes()); // policySession
    cmd.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
    cmd.extend_from_slice(&auth_area);
    cmd.extend_from_slice(&tpm2b(&[])); // nonceTPM
    cmd.extend_from_slice(&tpm2b(&[])); // cpHashA
    cmd.extend_from_slice(&tpm2b(&[])); // policyRef
    cmd.extend_from_slice(&0i32.to_be_bytes()); // expiration

    let len = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&len.to_be_bytes());
    cmd
}

pub fn parse_policy_secret_response(resp: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut r = Reader::new(resp);
    let _tag = r.u16()?;
    let _size = r.u32()?;
    let rc = r.u32()?;
    if rc != 0 {
        return Err(format!("PolicySecret failed: 0x{:08X}", rc).into());
    }
    Ok(())
}

/// Builds a plain TPMT_PUBLIC template for an RSA-2048 signing-only key
/// (unrestricted, RSASSA/SHA-256). Adjust attributes/scheme here if you
/// want a decrypt/storage key instead.
pub fn build_rsa_signing_template() -> Vec<u8> {
    // objectAttributes: fixedTPM | fixedParent | sensitiveDataOrigin |
    // userWithAuth | sign
    let attrs: u32 = (1 << 1) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 18);
    // let attrs: u32 = TPMA_OBJECT_FIXED_TPM
    //     | TPMA_OBJECT_FIXED_PARENT
    //     | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
    //     | TPMA_OBJECT_USER_WITH_AUTH
    //     | TPMA_OBJECT_SIGN_ENCRYPT;

    let mut t = Vec::new();
    t.extend_from_slice(&TPM_ALG_RSA.to_be_bytes()); // type
    t.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes()); // nameAlg
    t.extend_from_slice(&attrs.to_be_bytes()); // objectAttributes
    t.extend_from_slice(&tpm2b(&[])); // authPolicy: none (plain password auth)

    // TPMS_RSA_PARMS
    t.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // symmetric: none
    t.extend_from_slice(&TPM_ALG_RSASSA.to_be_bytes()); // scheme
    t.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes()); // scheme hash
    t.extend_from_slice(&2048u16.to_be_bytes()); // keyBits
    t.extend_from_slice(&0u32.to_be_bytes()); // exponent: 0 = default 65537

    t.extend_from_slice(&tpm2b(&[])); // unique: empty (TPM generates it)
    t
}

pub fn build_create_command(
    parent_handle: u32,
    session_handle: u32,
    auth_value: &[u8],
    public_template: &[u8],
) -> Vec<u8> {
    let mut auth_area = Vec::new();
    auth_area.extend_from_slice(&session_handle.to_be_bytes());
    auth_area.extend_from_slice(&tpm2b(&[])); // nonce
    auth_area.push(0u8); // sessionAttributes
    auth_area.extend_from_slice(&tpm2b(&[])); // hmac: unused for policy sessions

    // tpms_sensitive_create
    let mut inner_sensitive = Vec::new();
    inner_sensitive.extend_from_slice(&tpm2b(auth_value)); // userAuth
    inner_sensitive.extend_from_slice(&tpm2b(&[])); // data

    let mut cmd = Vec::new();
    cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&[0u8; 4]); // commandSize placeholder
    cmd.extend_from_slice(&TPM_CC_CREATE.to_be_bytes());
    cmd.extend_from_slice(&parent_handle.to_be_bytes());
    cmd.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
    cmd.extend_from_slice(&auth_area);
    cmd.extend_from_slice(&tpm2b(&inner_sensitive)); // inSensitive
    cmd.extend_from_slice(&tpm2b(public_template)); // inPublic
    cmd.extend_from_slice(&tpm2b(&[])); // outsideInfo
    cmd.extend_from_slice(&0u32.to_be_bytes()); // creationPCR: empty selection

    let len = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&len.to_be_bytes());
    cmd
}

/// Returns (outPrivate, outPublic) exactly as the TPM emitted them (each
/// still carrying its own TPM2B length prefix) - save these verbatim and
/// feed them straight back into `build_load_command` later.
pub fn parse_create_response(resp: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let mut r = Reader::new(resp);
    let _tag = r.u16()?;
    let _size = r.u32()?;
    let rc = r.u32()?;
    if rc != 0 {
        return Err(format!("Create failed: 0x{:08X}", rc).into());
    }
    let _parameter_size = r.u32()?;

    let priv_len = r.u16()?;
    let priv_data = r.bytes(priv_len as usize)?;
    let mut out_private = priv_len.to_be_bytes().to_vec();
    out_private.extend_from_slice(priv_data);

    let pub_len = r.u16()?;
    let pub_data = r.bytes(pub_len as usize)?;
    let mut out_public = pub_len.to_be_bytes().to_vec();
    out_public.extend_from_slice(pub_data);

    Ok((out_private, out_public))
}

pub fn build_load_command(
    parent_handle: u32,
    session_handle: u32,
    in_private: &[u8],
    in_public: &[u8],
) -> Vec<u8> {
    let mut auth_area = Vec::new();
    auth_area.extend_from_slice(&session_handle.to_be_bytes());
    auth_area.extend_from_slice(&tpm2b(&[]));
    auth_area.push(0u8);
    auth_area.extend_from_slice(&tpm2b(&[]));

    let mut cmd = Vec::new();
    cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&[0u8; 4]);
    cmd.extend_from_slice(&TPM_CC_LOAD.to_be_bytes());
    cmd.extend_from_slice(&parent_handle.to_be_bytes());
    cmd.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
    cmd.extend_from_slice(&auth_area);
    cmd.extend_from_slice(in_private); // already TPM2B-wrapped
    cmd.extend_from_slice(in_public); // already TPM2B-wrapped

    let len = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&len.to_be_bytes());
    cmd
}

pub fn parse_load_response(resp: &[u8]) -> Result<u32, Box<dyn Error>> {
    let mut r = Reader::new(resp);
    let _tag = r.u16()?;
    let _size = r.u32()?;
    let rc = r.u32()?;
    if rc != 0 {
        return Err(format!("Load failed: 0x{:08X}", rc).into());
    }
    let object_handle = r.u32()?;
    Ok(object_handle)
}

/// Signs a pre-computed digest with an already-loaded key using RSASSA/SHA-256.
/// `key_auth` is the plain-password auth value the key was created with (see
/// `auth_value` parameter).
pub fn build_sign_command(key_handle: u32, key_auth: &[u8], digest: &[u8]) -> Vec<u8> {
    let mut auth_area = Vec::new();
    auth_area.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    auth_area.extend_from_slice(&tpm2b(&[])); // nonce
    auth_area.push(0u8); // sessionAttributes
    auth_area.extend_from_slice(&tpm2b(key_auth)); // hmac = the key's auth value

    let mut cmd = Vec::new();
    cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&[0u8; 4]); // commandSize placeholder
    cmd.extend_from_slice(&TPM_CC_SIGN.to_be_bytes());
    cmd.extend_from_slice(&key_handle.to_be_bytes());
    cmd.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
    cmd.extend_from_slice(&auth_area);

    cmd.extend_from_slice(&tpm2b(digest)); // digest: TPM2B_DIGEST
    cmd.extend_from_slice(&TPM_ALG_RSASSA.to_be_bytes()); // inScheme.scheme
    cmd.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes()); // inScheme.details.hashAlg

    // validation: TPMT_TK_HASHCHECK - hierarchy = TPM_RH_NULL tells the TPM
    // "this digest wasn't produced by TPM2_Hash, don't check a ticket";
    // allowed because this key is unrestricted.
    cmd.extend_from_slice(&TPM_ST_HASHCHECK.to_be_bytes());
    cmd.extend_from_slice(&TPM_RH_NULL.to_be_bytes());
    cmd.extend_from_slice(&tpm2b(&[]));

    let len = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&len.to_be_bytes());
    cmd
}

pub fn parse_sign_response(resp: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut r = Reader::new(resp);
    let _tag = r.u16()?;
    let _size = r.u32()?;
    let rc = r.u32()?;
    if rc != 0 {
        return Err(format!("Sign failed: 0x{:08X}", rc).into());
    }
    let _parameter_size = r.u32()?;
    let _sig_alg = r.u16()?;
    let _hash_alg = r.u16()?;
    let sig_size = r.u16()? as usize;
    Ok(r.bytes(sig_size)?.to_vec())
}

pub fn build_flush_context_command(handle: u32) -> Vec<u8> {
    let mut cmd = Vec::new();
    cmd.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&[0u8; 4]);
    cmd.extend_from_slice(&TPM_CC_FLUSH_CONTEXT.to_be_bytes());
    cmd.extend_from_slice(&handle.to_be_bytes());
    let len = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&len.to_be_bytes());
    cmd
}

pub fn parse_flush_context_response(resp: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut r = Reader::new(&resp);
    let _tag = r.u16()?;
    let _size = r.u32()?;
    let rc = r.u32()?;
    if rc != 0 {
        return Err(format!("FlushContext failed: 0x{:08X}", rc).into());
    }
    Ok(())
}

// ---------- Small byte-cursor helpers (TPM structures are big-endian) ----------

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    pub fn u8(&mut self) -> Result<u8, String> {
        let b = *self.buf.get(self.pos).ok_or("unexpected EOF (u8)")?;
        self.pos += 1;
        Ok(b)
    }
    pub fn u16(&mut self) -> Result<u16, String> {
        let s = self.bytes(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    pub fn u32(&mut self) -> Result<u32, String> {
        let s = self.bytes(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.buf.len() {
            return Err(format!(
                "unexpected EOF (want {} bytes at pos {}, len {})",
                n,
                self.pos,
                self.buf.len()
            ));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

// TPM2B wrap helper: 2-byte big-endian length prefix + data.
fn tpm2b(data: &[u8]) -> Vec<u8> {
    let mut v = (data.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(data);
    v
}

// Cheap, non-cryptographic nonce generator. This is fine here: nonceCaller's
// role is session freshness, not secrecy - the actual security of the
// exchange rests on the TPM's own state, not on this value being
// unpredictable. Swap in a real CSPRNG if you'd rather not rely on that.
fn generate_nonce(len: usize) -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push((state & 0xFF) as u8);
    }
    out
}

pub enum EkPublic {
    Rsa {
        modulus: Vec<u8>,
        exponent: u32,
    },
    Ecc {
        curve_id: u16,
        x: Vec<u8>,
        y: Vec<u8>,
    },
}
