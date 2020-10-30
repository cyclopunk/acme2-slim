
use LETSENCRYPT_INTERMEDIATE_CERT_URL;
use Write;
use Jws;
use b64;
use helper::gen_key;
use CreateOrderResponse;
use std::{fs::File, io::Read};

use X509Req;
use helper::read_pkey;
use Path;
use PKey;
use CertificateSigner;
use Client;
use ContentType;
use FinalizeResponse;
use X509;
use SignedCertificate;
use serde_json::from_str;
use crate::{error::{Result}, helper::gen_csr};
use serde::{Serialize, Deserialize};
#[derive(Serialize, Deserialize, Clone)]
pub struct CsrRequest {
    csr: String
}

impl<'a> CertificateSigner<'a> {
    /// Set PKey of CSR
    pub fn pkey(mut self, pkey: PKey<openssl::pkey::Private>) -> CertificateSigner<'a> {
        self.pkey = Some(pkey);
        self
    }

    /// Load PEM formatted PKey from file
    pub fn pkey_from_file<P: AsRef<Path>>(mut self, path: P) -> Result<CertificateSigner<'a>> {
        self.pkey = Some(read_pkey(path)?);
        Ok(self)
    }

    /// Set CSR to sign
    pub fn csr(mut self, csr: X509Req) -> CertificateSigner<'a> {
        self.csr = Some(csr);
        self
    }

    /// Load PKey and CSR from file
    pub fn csr_from_file<P: AsRef<Path>>(mut self,
                                         pkey_path: P,
                                         csr_path: P)
                                         -> Result<CertificateSigner<'a>> {
        self.pkey = Some(read_pkey(pkey_path)?);
        let content = {
            let mut file = File::open(csr_path)?;
            let mut content = Vec::new();
            file.read_to_end(&mut content)?;
            content
        };
        self.csr = Some(X509Req::from_pem(&content)?);
        Ok(self)
    }


    /// Signs certificate.
    ///
    /// CSR and PKey will be generated if it doesn't set or loaded first.
    pub fn sign_certificate(self, order : &CreateOrderResponse) -> Result<SignedCertificate> {
        info!("Signing certificate");
        let domains: Vec<&str> = order.domains.iter().map(|s| &s[..]).collect();
        let s_key = gen_key().unwrap();
        let csr = gen_csr(&s_key, &domains).unwrap();
        let csr_payload = CsrRequest{ 
            csr: b64(&csr.to_der()?).to_string() 
        };
        let client = Client::new().unwrap();
        
        let mut resp = client
            .post(&order.finalize_url)
            .header(ContentType("application/jose+json".parse().unwrap()))
            .body({                        
                Jws::new(&order.finalize_url,&self.account, csr_payload)?.serialize(&self.account)?
            })
            .send()?;
        
        let fr : FinalizeResponse = {
            let mut res_content = String::new();
            resp.read_to_string(&mut res_content)?;
            from_str(&res_content)?
        };
        
        let mut cert_resp = client
        .post(&fr.certificate)
        .header(ContentType("application/jose+json".parse().unwrap()))
        .body(                    
            Jws::new(&fr.certificate,&self.account, "")?.serialize(self.account)?)
        .send().unwrap();


        let mut crt_der = String::new();
        cert_resp.read_to_string(&mut crt_der)?;        

        let cert = X509::stack_from_pem(&crt_der.as_bytes())?;

        debug!("Certificate successfully signed");
        
        Ok(SignedCertificate {
               certs: cert,
               csr: csr,
               pkey: s_key,
           })
    }
}



impl SignedCertificate {
    /// Saves signed certificate to a file
    pub fn save_signed_certificate<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_signed_certificate(&mut file)
    }

    /// Saves intermediate certificate to a file
    ///
    /// You can additionally provide intermediate certificate url, by default it will use
    /// [`LETSENCRYPT_INTERMEDIATE_CERT_URL`](constant.LETSENCRYPT_INTERMEDIATE_CERT_URL.html).
    pub fn save_intermediate_certificate<P: AsRef<Path>>(&self,
                                                         url: Option<&str>,
                                                         path: P)
                                                         -> Result<()> {
        let mut file = File::create(path)?;
        self.write_intermediate_certificate(url, &mut file)
    }

    /// Saves intermediate certificate and signed certificate to a file
    ///
    /// You can additionally provide intermediate certificate url, by default it will use
    /// [`LETSENCRYPT_INTERMEDIATE_CERT_URL`](constant.LETSENCRYPT_INTERMEDIATE_CERT_URL.html).
    pub fn save_signed_certificate_and_chain<P: AsRef<Path>>(&self,
                                                             url: Option<&str>,
                                                             path: P)
                                                             -> Result<()> {
        let mut file = File::create(path)?;
        self.write_signed_certificate(&mut file)?;
        self.write_intermediate_certificate(url, &mut file)?;
        Ok(())
    }

    /// Saves private key used to sign certificate to a file
    pub fn save_private_key<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_private_key(&mut file)
    }

    /// Saves CSR used to sign certificateto to a file
    pub fn save_csr<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_csr(&mut file)
    }

    /// Writes signed certificate to writer.
    pub fn write_signed_certificate<W: Write>(&self, writer: &mut W) -> Result<()> {
        for cert in self.cert() {
            writer.write_all(&cert.to_pem()?)?;
        }
        Ok(())
    }

    /// Writes intermediate certificate to writer.
    ///
    /// You can additionally provide intermediate certificate url, by default it will use
    /// [`LETSENCRYPT_INTERMEDIATE_CERT_URL`](constant.LETSENCRYPT_INTERMEDIATE_CERT_URL.html).
    pub fn write_intermediate_certificate<W: Write>(&self,
                                                    url: Option<&str>,
                                                    writer: &mut W)
                                                    -> Result<()> {
        let cert = self.get_intermediate_certificate(url)?;
        writer.write_all(&cert.to_pem()?)?;
        Ok(())
    }

    /// Gets intermediate certificate from url.
    ///
    /// [`LETSENCRYPT_INTERMEDIATE_CERT_URL`](constant.LETSENCRYPT_INTERMEDIATE_CERT_URL.html).
    /// will be used if url is None.
    fn get_intermediate_certificate(&self, url: Option<&str>) -> Result<X509> {
        let client = Client::new()?;
        let mut res = client
            .get(url.unwrap_or(LETSENCRYPT_INTERMEDIATE_CERT_URL))
            .send()?;
        let mut content = Vec::new();
        res.read_to_end(&mut content)?;
        Ok(X509::from_pem(&content)?)
    }

    /// Writes private key used to sign certificate to a writer
    pub fn write_private_key<W: Write>(&self, writer: &mut W) -> Result<()> {
        Ok(writer.write_all(&self.pkey().private_key_to_pem_pkcs8()?)?)
    }

    /// Writes CSR used to sign certificateto a writer
    pub fn write_csr<W: Write>(&self, writer: &mut W) -> Result<()> {
        Ok(writer.write_all(&self.csr().to_pem()?)?)
    }

    /// Returns reference to certificate
    pub fn cert(&self) -> &Vec<X509> {
        &self.certs
    }

    /// Returns reference to CSR used to sign certificate
    pub fn csr(&self) -> &X509Req {
        &self.csr
    }

    /// Returns reference to pkey used to sign certificate
    pub fn pkey(&self) -> &PKey<openssl::pkey::Private> {
        &self.pkey
    }
}
