#![cfg_attr(docsrs, feature(doc_cfg))]
//! Library for working with the TPM
//!
//! ## Platforms
//!
//! Windows is the only platform currently supported.  You
//! can dynamically link to `Tbs.dll` using the **"windows_dynamic"**
//! feature flag or statically link to the `windows` crate's
//! `Win32_System_TpmBaseServices` using the **"windows_static"**
//! feature flag.
//!
//! ## Example
//!
//! ### Cargo.toml
//!
//! ```toml
//! win_tpm = { version = "0.1", features = ["windows_dynamic"] }
//! ```
//!
//! ### main.rs
//!
//! ```rust
//! use win_tpm::win_dynamic::TbsDyn;
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!    let tbs = TbsDyn::open()?;
//!
//!    test_all(tbs)?;
//!
//!    Ok(())
//!}
//!
//! ```
//!

pub mod convert;
pub mod tbs;
pub mod tpm;

#[cfg(feature = "windows_dynamic")]
pub mod win_dynamic;

#[cfg(feature = "windows_static")]
pub mod win_static;
