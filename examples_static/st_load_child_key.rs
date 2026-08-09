//!
//! This will only work with loading the child keys from the
//! same TPM that they were saved from.  If you try to load
//! them to a different TPM or they are modified, then you'll
//! get a load error.
//!
//! ```
//! running ...
//! Reloading the child key from its saved blobs to verify round-trip...
//! Error: "Load failed: 0x00000095"
//! ```
//!
use std::error::Error;

use crumpet::{
    tbs::{Tbs, load_child_under_ek},
    tpm::constants::EK_RSA_PERSISTENT_HANDLE,
    win_static::TbsStatic,
};

fn main() -> Result<(), Box<dyn Error>> {
    println!("running ...");
    // We should open a context and connect to the TPM
    // When our context goes out of scope it should drop it cleanly
    let tbs = TbsStatic::open()?;

    let priv_blob = std::fs::read("ek_child_private.blob")?;
    let pub_blob = std::fs::read("ek_child_public.blob")?;
    println!("Reloading the child key from its saved blobs to verify round-trip...");
    let handle = load_child_under_ek(&tbs, EK_RSA_PERSISTENT_HANDLE, &priv_blob, &pub_blob)?;
    println!("Loaded child key at transient handle 0x{:08X}", handle);

    println!("done");
    Ok(())
}
