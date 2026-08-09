use std::error::Error;

use crumpet::{
    convert::rsa_public_key_to_pem,
    tbs::{Tbs, create_child_under_ek},
    tpm::{commands::EkPublic, constants::EK_RSA_PERSISTENT_HANDLE},
    win_dynamic::TbsDyn,
};

fn main() -> Result<(), Box<dyn Error>> {
    println!("running ...");
    // We should open a context and connect to the TPM
    // When our context goes out of scope it should drop it cleanly
    let tbs = TbsDyn::open()?;

    match create_child_under_ek(&tbs, EK_RSA_PERSISTENT_HANDLE, b"") {
        Ok((priv_blob, pub_blob)) => {
            std::fs::write("ek_child_private.blob", &priv_blob)?;
            std::fs::write("ek_child_public.blob", &pub_blob)?;
            println!(
                "Saved child key blobs: ek_child_private.blob ({} bytes), ek_child_public.blob ({} bytes)",
                priv_blob.len(),
                pub_blob.len()
            );

            match crumpet::tpm::commands::parse_tpm2b_public(&pub_blob)? {
                EkPublic::Rsa { modulus, exponent } => {
                    let pem = rsa_public_key_to_pem(&modulus, exponent)?;
                    std::fs::write("ek_child_public.pem", &pem)?;
                    println!(
                        "Wrote child key SubjectPublicKeyInfo PEM to ek_child_public.pem:\n{pem}"
                    );
                }
                EkPublic::Ecc { .. } => {
                    println!("Child key is ECC; PEM export not implemented for this template.");
                }
            }
        }
        Err(e) => {
            eprintln!("creating child failed: {e}");
            Err(e)?;
        }
    }

    println!("done");
    Ok(())
}
