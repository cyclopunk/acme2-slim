# LetsEncrypt AcmeV2 for Rust

## Description

This library is a slimmed down version of https://github.com/onur/acme-client into only a rust api and it also supports the Acmev2 protocol. It is currently a work in progress, but you should be able to use it to create certificates.

## Development

To compile on windows you will need openssl, here's an easy way to get it installed.

(example in Git Bash)
```bash
git clone https://github.com/microsoft/vcpkg
cd vcpkg
./bootstrap-vcpkg.sh
./vcpkg.exe install openssl
./vcpkg.exe install openssl:x64-windows-static
# Add OPENSSL_DIR=/vcpkg/path/installed/x64-windows-static
cargo build
```

## Quickstart

```rust
#[tokio::main]
async fn main() -> Result<()> {
    let dir = Directory::lets_encrypt()
        .await?;

    let account = dir.account_registration()
        .pkey_from_file(path) // optional, you can provide one with pkey(), or leave this blank to create a new pkey.
        .register()
        .await?;


    let domain = "yourdomain.com";
    let domains = &[domain];
    
    let order = account
        .create_order(&domain)
        .await
        .expect("create order");

    for chal in order.get_http_challenges() {
        chal.serve_challenge(Duration::from_seconds(30)); // create a temp webserver on port 80 for 30 seconds
        chal.validate(&account).await.expect("to validate");    
    }
    // use order.get_dns_challanges to do dns.

    let signer = account.certificate_signer(&domains);

    let cert = signer.sign_certificate(&order).await.expect("to sign certificate");

    cert.save_signed_certificate(format!("certs/{}.pem", domain_name)).await?;
    cert.save_private_key(format!("certs/{}.key", domain_name)).await?;
}
```

## TODO

- Cert Revocation
- Key change
- Examples

# Contributors 

Thanks to people who are contributing to this effort: 

- @lucacasonato