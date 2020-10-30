# LetsEncrypt AcmeV2 for Rust

## Description

This library is a slimmed down version of https://github.com/onur/acme-client into only a rust api and it also supports the Acmev2 protocol. It is currently a work in progress, but you should be able to use it to create certificates using the LetsEncrypt Acmev2 directory.

## Quickstart

```
let order = account.create_order("test.autobuild.cloud").unwrap();
let domain = "test.autobuild.cloud";
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
```

## TODO

- Better egonomics
- More logging
- Housecleaning

