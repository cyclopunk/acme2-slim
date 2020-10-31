use std::io::Write;
use crate::FinalizeResponse;
use reqwest::{header::ContentType, Response};
use reqwest::Client;
use openssl::x509::X509;
use crate::{CreateOrderResponse, jwt::Jws};
use std::path::Path;
use openssl::{pkey::PKey, x509::X509Req};
use log::{info};
use std::{fs::File, io::Read};

use serde_json::from_str;
use crate::{Account, error::{Result}, helper::*};
use serde::{Serialize, Deserialize};
#[derive(Serialize, Deserialize, Clone)]
pub struct CsrRequest {
    csr: String
}

/// A signed certificate.
pub struct SignedCertificate {
    certs: Vec<X509>,
    csr: X509Req,
    pkey: PKey<openssl::pkey::Private>,
}
  

pub struct CertificateSigner<'a> {
    pub(crate) account: &'a Account,
    pub(crate) pkey: Option<PKey<openssl::pkey::Private>>,
    pub(crate) csr: Option<X509Req>,
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
        let csr = gen_csr(&s_key, &domains)?;
        let payload = &csr.to_der()?;
        
        let csr_payload = CsrRequest{ 
            csr: b64(payload)
        };

        let client = Client::new().unwrap();
        
        let resp = client
            .post(&order.finalize_url)
            .header(ContentType("application/jose+json".parse().unwrap()))
            .body({                        
                Jws::new(&order.finalize_url,&self.account, csr_payload)?.to_string()?
            })
            .send()?;
        
        let finalize_response : FinalizeResponse = resp.into();
    
        Ok(SignedCertificate {
               certs: finalize_response.get_certificates(&self.account)?,
               csr: csr,
               pkey: s_key,
           })
    }
}

impl FinalizeResponse {
    fn get_certificates(&self, account : &Account) -> Result<Vec<X509>> {
        let client = Client::new()?;

        let mut cert_resp = client
            .post(&self.certificate)
            .header(ContentType("application/jose+json".parse().unwrap()))
            .body(                    
                Jws::new(&self.certificate, &account, "")?.to_string()?)
            .send().unwrap();

        let mut crt_der = String::new();

        cert_resp.read_to_string(&mut crt_der)?;        

        let cert = X509::stack_from_pem(&crt_der.as_bytes())?;

        Ok(cert)
    }
}


impl Into<FinalizeResponse> for Response {
    fn into(mut self) -> FinalizeResponse { 
        let mut res_content = String::new();
        self.read_to_string(&mut res_content).unwrap();
        from_str(&res_content).unwrap()
    }
}

impl SignedCertificate {
    /// Saves signed certificate to a file
    pub fn save_signed_certificate<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_signed_certificate(&mut file)
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
