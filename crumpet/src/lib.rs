#![cfg_attr(docsrs, feature(doc_cfg))]
//! Tasty minimal library for working with TPM 2.0
//!
//! ## Platforms
//!
//! Windows is the only platform currently supported.  You
//! can dynamically link to `Tbs.dll` using the **"windows_dynamic"**
//! feature flag or statically link to the `windows` crate's
//! `Win32_System_TpmBaseServices` using the **"windows_static"**
//! feature flag.
//!
//! ## Example - dynamic linking
//!
//! cargo.toml
//!
//! ```toml
//! crumpet = "0.1.1"
//! ```
//!
//! main.rs
//!
//! ```ignore
//! use crumpet::win_dynamic::TbsDyn;
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!    let tbs = TbsDyn::open()?;
//!
//!    // do stuff
//!
//!    Ok(())
//!}
//!
//! ```
//!
//! ## Example - static linking
//!
//! cargo.toml
//!
//! ```toml
//! crumpet = { version = "0.1.1", default-features = false, features = ["windows_static"] }
//! ```
//!
//! main.rs
//!
//! ```ignore
//! use crumpet::win_static::TbsStatic;
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!    let tbs = TbsStatic::open()?;
//!
//!    // do stuff
//!
//!    Ok(())
//!}
//!
//! ```

pub mod convert;
pub mod tbs;
pub mod tpm;

#[cfg(feature = "windows_dynamic")]
pub mod win_dynamic;

#[cfg(feature = "windows_static")]
pub mod win_static;
