# LetsEncrypt AcmeV2 for Rust

## Description

This library is a slimmed down version of https://github.com/onur/acme-client into only a rust api and it also supports the Acmev2 protocol. It is currently a work in progress, but you should be able to use it to create certificates.

## Quickstart

```
fn main() -> Result<()> {
    let dir = Directory::lets_encrypt()?;
    let account = dir.account_registration()
        .pkey_from_file(path) // optional, will create a key or provide one with pkey()
        .register()?;
    let order = account
        .create_order("test.autobuild.cloud").unwrap();

    let domain = "yourdomain.com";
    let domains = &[domain];

    for chal in order.challenges.clone() {
        if chal.ctype == "dns-01" {
            chal.validate(&account).unwrap();
        }
    }

    let signer = account.certificate_signer(&domains);

    let cert = signer.sign_certificate(&order).unwrap();

    cert.save_signed_certificate(format!("certs/{}.pem", domain_name))?;
    cert.save_private_key(format!("certs/{}.key", domain_name))?;
}
```

## TODO

- Better egonomics
- More logging
- Housecleaning
- Async support
- Update libraries

