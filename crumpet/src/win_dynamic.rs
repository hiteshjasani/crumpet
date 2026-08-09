//! Windows api as exposed through Tbs.dll
//!
//! Dynamically load the dll and find the functions we want to use
//! related to TPM Base Services to talk to the TPM 2.0 device.
//!
//! This means we have fewer crate dependencies, don't have to wait
//! for the big windows crate to compile (it's slow) and we don't
//! have the churn seen by the changing windows rust apis.
//!
//! The downside is that we're loading the DLL at runtime which
//! is less secure.  Security conscious coders may want to use
//! the "windows_static" feature flag and use the windows crate
//! dependency.
//!
//! Most functions should be usable on Windows by a non-privileged
//! (non-admin) user.
//!
//! Reads the well-known persistent EK handle (0x81010001, RSA) via
//! TPM2_ReadPublic through the TBS (TPM Base Services) API. ReadPublic
//! requires no authorization, so no elevation is needed as long as the
//!
//! Expectations are that the platform firmware or Windows has already
//! provisioned the EK (the normal default on essentially all modern PCs).
//!

use libloading::{Library, Symbol};
use std::error::Error;
use std::ffi::c_void;

use super::tbs::*;

// ---------- TBS FFI type definitions (from tbs.h) ----------

type TbsHContext = *mut c_void;
type TbsResult = u32;

const TBS_SUCCESS: TbsResult = 0;

#[repr(C)]
struct TbsContextParams2 {
    version: u32, // TBS_CONTEXT_VERSION_TWO
    flags: u32,   // bit0 = includeTpm12, bit1 = includeTpm20
}

const TBS_CONTEXT_VERSION_TWO: u32 = 2;
// TBS_CONTEXT_PARAMS2 flag bits: bit0 = requestRaw, bit1 = includeTpm12,
// bit2 = includeTpm20.
const INCLUDE_TPM20: u32 = 1 << 2;

const TBS_COMMAND_LOCALITY_ZERO: u32 = 0;
const TBS_COMMAND_PRIORITY_NORMAL: u32 = 200;

type FnContextCreate =
    unsafe extern "system" fn(*const TbsContextParams2, *mut TbsHContext) -> TbsResult;
type FnSubmitCommand = unsafe extern "system" fn(
    TbsHContext,
    u32, // locality
    u32, // priority
    *const u8,
    u32,
    *mut u8,
    *mut u32,
) -> TbsResult;
type FnContextClose = unsafe extern "system" fn(TbsHContext) -> TbsResult;

// ---------- TBS wrapper ----------

pub struct TbsDyn {
    _lib: Library, // keep DLL loaded for the lifetime of the handle
    ctx: TbsHContext,
    submit: FnSubmitCommand,
    close: FnContextClose,
}

impl Tbs for TbsDyn {
    fn open() -> Result<Self, Box<dyn Error>> {
        unsafe {
            let lib = Library::new("Tbs.dll")?;
            let create: Symbol<FnContextCreate> = lib.get(b"Tbsi_Context_Create\0")?;
            let submit: Symbol<FnSubmitCommand> = lib.get(b"Tbsip_Submit_Command\0")?;
            let close: Symbol<FnContextClose> = lib.get(b"Tbsip_Context_Close\0")?;

            let params = TbsContextParams2 {
                version: TBS_CONTEXT_VERSION_TWO,
                flags: INCLUDE_TPM20,
            };
            let mut ctx: TbsHContext = std::ptr::null_mut();
            let rc = create(&params, &mut ctx);
            if rc != TBS_SUCCESS {
                return Err(format!("Tbsi_Context_Create failed: 0x{:08X}", rc).into());
            }

            let submit_fn = *submit;
            let close_fn = *close;
            // Detach the `Symbol`s' borrow by copying the raw fn pointers;
            // the underlying DLL stays loaded via `_lib`.
            Ok(Self {
                _lib: lib,
                ctx,
                submit: submit_fn,
                close: close_fn,
            })
        }
    }

    fn submit_command(&self, command: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut out = vec![0u8; 4096];
        let mut out_len: u32 = out.len() as u32;
        let rc = unsafe {
            (self.submit)(
                self.ctx,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                command.as_ptr(),
                command.len() as u32,
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        if rc != TBS_SUCCESS {
            return Err(format!("Tbsip_Submit_Command failed: 0x{:08X}", rc).into());
        }
        out.truncate(out_len as usize);
        Ok(out)
    }
}

impl Drop for TbsDyn {
    fn drop(&mut self) {
        unsafe {
            let res = (self.close)(self.ctx);
            if res != 0 {
                eprintln!("Warning: failed to cleanly close TBS context: {:#X}", res);
            }
        }
    }
}
