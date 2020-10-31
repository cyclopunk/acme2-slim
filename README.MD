# LetsEncrypt AcmeV2 for Rust

## Description

This library is a slimmed down version of https://github.com/onur/acme-client into only a rust api and it also supports the Acmev2 protocol. It is currently a work in progress, but you should be able to use it to create certificates.

## Development

To compile on windows you will need openssl, here's an easy way to get it installed.

(example in Git Bash)
```
git clone https://github.com/microsoft/vcpkg
cd vcpkg
./bootstrap-vcpkg.sh
./vcpkg.exe install openssl
./vcpkg.exe install openssl:x64-windows-static
# Add OPENSSL_DIR=/vcpkg/path/installed/x64-windows-static
cargo build
```

## Quickstart

```
fn main() -> Result<()> {
    let dir = Directory::lets_encrypt()?;

    let account = dir.account_registration()
        .pkey_from_file(path) // optional, will create a key or provide one with pkey()
        .register()?;


    let domain = "yourdomain.com";
    let domains = &[domain];
    
    let order = account
        .create_order(&domain).unwrap();

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

- Implement all certificate management features 
- Better ergonomics
- More logging
- Housecleaning
- Async support
- Update libraries
- Examples

