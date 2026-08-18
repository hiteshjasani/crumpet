//! Connects to a running tpmsim.rs (or other mssim-protocol simulator)
//! instance, starts it up, and pulls some random bytes.
//!
//! Point this at a running simulator first:
//!
//! ```sh
//! cargo run --manifest-path ../tpmsim.rs/Cargo.toml --release
//! ```
//!
//! Then, from this directory:
//!
//! ```sh
//! cargo run --example mssim_get_random
//! ```
//!
//! Set `CRUMPET_MSSIM_ADDR` to target a non-default `host:port`.

use std::error::Error;

use crumpet::{
    mssim::TbsMssim,
    tbs::{Tbs, startup_clear},
    tpm::commands::{build_get_random_command, parse_get_random_response},
};

fn main() -> Result<(), Box<dyn Error>> {
    println!("connecting to mssim simulator ...");
    let tbs = TbsMssim::open()?;

    println!("starting up ...");
    startup_clear(&tbs)?;

    println!("requesting random bytes ...");
    let resp = tbs.submit_command(&build_get_random_command(16))?;
    let random = parse_get_random_response(&resp)?;
    println!("got {} random bytes: {:02x?}", random.len(), random);

    Ok(())
}
