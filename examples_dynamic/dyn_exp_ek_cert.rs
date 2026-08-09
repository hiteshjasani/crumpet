use std::error::Error;

use crumpet::{
    convert::{hex_encode, rsa_public_key_to_pem, to_pem},
    tbs::{Tbs, read_nv_data, try_read_ek},
    tpm::{
        commands::EkPublic,
        constants::{
            EK_ECC_CERT_NV_INDEX, EK_ECC_PERSISTENT_HANDLE, EK_RSA_CERT_NV_INDEX,
            EK_RSA_PERSISTENT_HANDLE,
        },
    },
    win_dynamic::TbsDyn,
};

fn main() -> Result<(), Box<dyn Error>> {
    println!("running ...");
    // We should open a context and connect to the TPM
    // When our context goes out of scope it should drop it cleanly
    let tbs = TbsDyn::open()?;

    // Let try to read the EK pub key
    let (ek, cert_nv_index) = match try_read_ek(&tbs, EK_RSA_PERSISTENT_HANDLE) {
        Ok(ek) => (ek, EK_RSA_CERT_NV_INDEX),
        Err(e) => {
            eprintln!("RSA EK read failed ({e}), trying ECC EK handle...");
            (
                try_read_ek(&tbs, EK_ECC_PERSISTENT_HANDLE)?,
                EK_ECC_CERT_NV_INDEX,
            )
        }
    };

    match ek {
        EkPublic::Rsa { modulus, exponent } => {
            println!("EK algorithm: RSA");
            println!("Exponent: {}", exponent);
            println!(
                "Modulus ({} bytes): {}",
                modulus.len(),
                hex_encode(&modulus)
            );

            let pem = rsa_public_key_to_pem(&modulus, exponent)?;
            std::fs::write("ek_public.pem", &pem)?;
            println!("\nWrote SubjectPublicKeyInfo PEM to ek_public.pem:\n{pem}");
        }
        EkPublic::Ecc { curve_id, x, y } => {
            println!("EK algorithm: ECC (curve id 0x{:04X})", curve_id);
            println!("X ({} bytes): {}", x.len(), hex_encode(&x));
            println!("Y ({} bytes): {}", y.len(), hex_encode(&y));
            println!("(ECC PEM export not implemented in this example; raw point printed above.)");
        }
    }

    // Attempt to also pull the manufacturer-issued EK certificate from NV
    // storage. Not all TPMs/OEMs provision one, so failure here is common
    // and non-fatal.
    println!(
        "\nLooking for an EK certificate in NV storage (index 0x{:08X})...",
        cert_nv_index
    );
    match read_nv_data(&tbs, cert_nv_index) {
        Ok(der) => {
            std::fs::write("ek_certificate.der", &der)?;
            let pem = to_pem(&der, "CERTIFICATE");
            std::fs::write("ek_certificate.pem", &pem)?;
            println!(
                "Found EK certificate ({} bytes). Wrote ek_certificate.der and ek_certificate.pem.",
                der.len()
            );
            println!("View it with:\n  openssl x509 -in ek_certificate.pem -text -noout");
        }
        Err(e) => {
            println!("No EK certificate found at that index ({e}).");
            println!(
                "This is common on TPMs that weren't provisioned with a manufacturer \
                 EK certificate (e.g. some fTPMs/VMs), or when the cert lives at a \
                 non-default NV index."
            );
        }
    }

    println!("done");
    Ok(())
}
