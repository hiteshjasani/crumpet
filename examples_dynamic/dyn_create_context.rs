use std::error::Error;

use crumpet::{tbs::Tbs, win_dynamic::TbsDyn};

fn main() -> Result<(), Box<dyn Error>> {
    println!("running ...");
    // We should open a context and connect to the TPM
    // When our context goes out of scope it should drop it cleanly
    let _tbs = TbsDyn::open()?;

    println!("done");
    Ok(())
}
