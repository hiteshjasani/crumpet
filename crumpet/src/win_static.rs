//! Using the Windows crate provided TPM Base Services for comms to the TPM
//!
//! This is the windows api to the transport channel sitting above
//! the device driver.  Being so low level, it requires encoding
//! the comms into byte streams and then decoding results.
//!
//! rust docs: https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/TpmBaseServices/fn.Tbsip_Submit_Command.html
//! windows docs: https://learn.microsoft.com/en-us/windows/win32/api/tbs/nf-tbs-tbsi_context_create
//! constants: https://docs.rs/tss-esapi/latest/tss_esapi/constants/tss/index.html
//! https://crates.io/crates/tss-esapi
//! https://github.com/parallaxsecond/rust-tss-esapi/blob/main/tss-esapi/src/constants/tss.rs
//!

use std::error::Error;
use std::ffi::c_void;

use anyhow::anyhow;
use windows::Win32::System::TpmBaseServices::{
    TBS_COMMAND_LOCALITY, TBS_COMMAND_PRIORITY, TBS_CONTEXT_PARAMS2, TBS_CONTEXT_PARAMS2_0,
    TBS_CONTEXT_PARAMS2_0_0, TBS_CONTEXT_VERSION_TWO, TBS_SUCCESS, Tbsi_Context_Create,
    Tbsip_Context_Close, Tbsip_Submit_Command,
};

use super::tbs::Tbs;

pub struct TbsStatic {
    context_handle: *mut c_void,
}

impl Tbs for TbsStatic {
    fn open() -> Result<Self, Box<dyn Error>> {
        unsafe {
            let tbs2_flags = TBS_CONTEXT_PARAMS2_0_0 { _bitfield: 1 };
            let context_params = TBS_CONTEXT_PARAMS2 {
                version: TBS_CONTEXT_VERSION_TWO,
                Anonymous: TBS_CONTEXT_PARAMS2_0 { asUINT32: (1 << 2) },
            };
            let mut context_handle: *mut c_void = std::ptr::null_mut();

            let create_res = Tbsi_Context_Create(
                &context_params as *const TBS_CONTEXT_PARAMS2 as *const _,
                &mut context_handle,
            );

            if create_res != TBS_SUCCESS {
                eprintln!("Failed to bind to TPM via TBS2 params: {:#X}", create_res);
                if create_res == 0x8028400F {
                    eprintln!("Error: TPM 2.0 hardware component missing or denied access.");
                }
                return Err(anyhow!("Error from tpm: {:#X}", create_res).into());
            }

            Ok(Self { context_handle })
        }
    }

    fn submit_command(&self, command: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // Prepare a buffer for the response data
        let mut response_buffer = [0u8; 4096];
        let mut response_size: u32 = response_buffer.len() as u32;

        let submit_res = unsafe {
            Tbsip_Submit_Command(
                self.context_handle,
                TBS_COMMAND_LOCALITY(0),   // Locality 0
                TBS_COMMAND_PRIORITY(200), // TBS_COMMAND_PRIORITY_NORMAL
                command,
                response_buffer.as_mut_ptr(),
                &mut response_size,
            )
        };

        if submit_res == TBS_SUCCESS {
            // println!(
            //     "TPM command executed successfully! Response size: {} bytes",
            //     response_size
            // );

            // Print out the raw hexadecimal response from the TPM
            // let active_response = &response_buffer[..response_size as usize];
            // println!("Raw Response: {:02X?}", active_response);
            Ok(response_buffer.to_vec())
        } else {
            Err(anyhow!("Tbsip_Submit_Command failed with error: {:#X}", submit_res).into())
        }
    }
}

impl Drop for TbsStatic {
    fn drop(&mut self) {
        unsafe {
            let res = Tbsip_Context_Close(self.context_handle as *const c_void);
            if res != 0 {
                eprintln!("Warning: failed to cleanly close TBS context: {:#X}", res);
            }
        }
    }
}
