# cruMPeT
A tasty TPM 2.0 library

## Usage

Let's say we want to export the Endorsement Key (EK) public key and X.509 certificate.  We'll do a quick project using the windows dynamic linking feature, which is the default.

```toml
# Cargo.toml
crumpet = "0.1.1"
```

```rust
use std::error::Error;
use crumpet::{
    convert::*, tbs::*, tpm::{ commands::EkPublic, constants::* },
    win_dynamic::TbsDyn,
};

fn main() -> Result<(), Box<dyn Error>> {
    let tbs = TbsDyn::open()?;

    // Let try to read the EK pub key
    let cert_nv_handle = EK_RSA_CERT_NV_INDEX;
    let ek = try_read_ek(&tbs, EK_RSA_PERSISTENT_HANDLE)?;

    if let EkPublic::Rsa { modulus, exponent } = ek {
        let pem = rsa_public_key_to_pem(&modulus, exponent)?;
        std::fs::write("ek_public.pem", &pem)?;
        println!("\nWrote public key ek_public.pem:\n{pem}");
    }

    // try to get the EK X.509 public certificate
    if let Ok(der) = read_nv_data(&tbs, cert_nv_index) {
        std::fs::write("ek_certificate.der", &der)?;
        let pem = to_pem(&der, "CERTIFICATE");
        std::fs::write("ek_certificate.pem", &pem)?;
    }
    Ok(())
}
```

See the examples in either [examples_dynamic](examples_dynamic) or [examples_static](examples_static).

## Platforms

Currently two different ways of accessing Windows services to the TPM are supported.  One is a dynamic linking option where the windows Tbs.dll is loaded at runtime and the functions we need are mapped.  This has the advantage of being able to develop and compile on non-windows platforms and is fast.

The second option is static linking with the windows crate.  It's slower for builds but is more secure.

Linux support is desired, but it will be later.

## License
This project is dual-licensed under the Apache License, Version 2.0 and the MIT License. See the [LICENSE](LICENSE.md) file for details.
