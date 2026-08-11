//! Example loading child key and signing message
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
    tbs::{Tbs, load_child_under_ek, sign_with_child_key},
    tpm::constants::EK_RSA_PERSISTENT_HANDLE,
    win_dynamic::TbsDyn,
};

fn main() -> Result<(), Box<dyn Error>> {
    // We should open a context and connect to the TPM
    // When our context goes out of scope it should drop it cleanly
    let tbs = TbsDyn::open()?;

    let priv_blob = std::fs::read("ek_child_private.blob")?;
    let pub_blob = std::fs::read("ek_child_public.blob")?;
    println!("Reloading the child key from its saved blobs to verify round-trip...");
    let handle = load_child_under_ek(&tbs, EK_RSA_PERSISTENT_HANDLE, &priv_blob, &pub_blob)?;
    println!("Loaded child key at transient handle 0x{:08X}", handle);

    // Use the child key to sign a message
    let message = b"There's always money in the banana stand!";
    let signature = sign_with_child_key(&tbs, handle, b"", message)?;
    std::fs::write("msg.txt", message)?;
    std::fs::write("sig.bin", &signature)?;
    println!("Wrote message (msg.txt) and signature (sig.bin). To verify:");
    println!("\n  openssl dgst -sha256 -verify ek_child_public.pem -signature sig.bin msg.txt");

    Ok(())
}
