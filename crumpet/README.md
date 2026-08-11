# cruMPeT
A tasty minimal TPM 2.0 library

[![Rust](https://github.com/hiteshjasani/crumpet/actions/workflows/rust.yml/badge.svg)](https://github.com/hiteshjasani/crumpet/actions/workflows/rust.yml)
[![Crates.io Version](https://img.shields.io/crates/v/crumpet)](https://crates.io/crates/crumpet)
[![Documentation](https://docs.rs/crumpet/badge.svg)](https://docs.rs/crumpet)

The priority is on making an easy to use api that handles
some subset of cases rather than being fully compliant with
the specification.

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

See the examples in either [examples_dynamic](https://github.com/hiteshjasani/crumpet/tree/main/examples_dynamic) or [examples_static](https://github.com/hiteshjasani/crumpet/tree/main/examples_static).

## License
This project is dual-licensed under the Apache License, Version 2.0 and the MIT License. See the [LICENSE](LICENSE.md) file for details.
