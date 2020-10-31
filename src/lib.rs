#[macro_use]
extern crate error_chain;

use crate::challenge::CheckResponse;
use crate::challenge::Challenge;
use crate::cert::CertificateSigner;
use crate::hyperx::ReplayNonce;
use crate::helper::get_raw;
use jwt::{Jwk, Jws};
use helper::*;
use log::{debug, info};

use register::AccountRegistration;
use reqwest::header::Location;
use hyper::header::ContentType;
use std::{path::Path};
use std::fs::File;
use std::io::{Read, Write};
use std::collections::HashMap;


use openssl::hash::{hash, MessageDigest};
use openssl::pkey::PKey;
use openssl::x509::{X509};

use reqwest::{Client, StatusCode};
use serde_json::{Value, to_string};
use serde::{Serialize, Deserialize};
use error::{Result, ErrorKind};

mod jwt;
mod cert;
mod register;
mod validate;
mod helper;
mod error;
mod challenge;

pub const LETSENCRYPT_DIRECTORY_URL: &'static str = "https://acme-v02.api.letsencrypt.org\
                                                     /directory";
pub const LETSENCRYPT_AGREEMENT_URL: &'static str = "https://letsencrypt.org/documents/LE-SA-v1.2-\
                                                     November-15-2017.pdf";
/// Default Let's Encrypt intermediate certificate URL to chain when needed.
pub const LETSENCRYPT_INTERMEDIATE_CERT_URL: &'static str = "https://letsencrypt.org/certs/\
                                                             lets-encrypt-x3-cross-signed.pem";
/// Default bit lenght for RSA keys and `X509_REQ`
const BIT_LENGTH: u32 = 2048;                                                     
      

/*pub mod prelude {
  pub use super::{Directory, Account, Challenge};
}*/

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DirectoryMetadata {
    caa_identities: Vec<String>,
    terms_of_service: String,
    website:String,
    #[serde(flatten)]
    other: HashMap<String, Value>,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DirectoryResources {
    key_change: String,
    meta: DirectoryMetadata,
    new_account:String,
    new_nonce:String,
    new_order:String,
    revoke_cert:String,
    #[serde(flatten)]
    other: HashMap<String, Value>,
}
#[derive(Clone)]
pub struct Directory {
    /// Base URL of directory
    url: String,
    resources: DirectoryResources
}

#[macro_use] extern crate hyper;

mod hyperx {

    // ReplayNonce header for hyper
    header! { (ReplayNonce, "Replay-Nonce") => [String] }
}


impl Directory {
  /// Creates a Directory from
  /// [`LETSENCRYPT_DIRECTORY_URL`](constant.LETSENCRYPT_DIRECTORY_URL.html).
  pub fn lets_encrypt() -> Result<Directory> {
      Directory::from_url(LETSENCRYPT_DIRECTORY_URL)
  }

  /// Creates a Directory from directory URL.
  ///
  /// Example directory for testing `acme-client` crate with staging API:
  ///
  /// ```rust
  /// # use acme_client::error::Result;
  /// # fn try_main() -> Result<()> {
  /// use acme_client::Directory;
  /// let dir = Directory::from_url("https://acme-staging.api.letsencrypt.org/directory")?;
  /// # Ok(()) }
  /// # fn main () { try_main().unwrap(); }
  /// ```
  pub fn from_url(url: &str) -> Result<Directory> {    
      let raw = &get_raw(url)?[..]; 
      
      Ok(Directory {
             url: url.to_owned(),
             resources: serde_json::from_str(&raw)?,
         })

  }

  /// Consumes directory and creates new AccountRegistration.
  ///
  /// AccountRegistration is used to register an account.
  ///
  /// ```rust,no_run
  /// # use acme_client::error::Result;
  /// # fn try_main() -> Result<()> {
  /// use acme_client::Directory;
  ///
  /// let directory = Directory::lets_encrypt()?;
  /// let account = directory.account_registration()
  ///                        .email("example@example.org")
  ///                        .register()?;
  /// # Ok(()) }
  /// # fn main () { try_main().unwrap(); }
  /// ```
  pub fn account_registration(self) -> AccountRegistration {
      AccountRegistration {
          directory: self,
          pkey: None,
          email: None,
          contact: None,
          agreement: None,
      }
  }

  pub fn new_account_url(&self) -> String {
    self.resources.new_account.clone()
  }
  pub fn new_order_url(&self) -> String {
    self.resources.new_order.clone()
  }
  
  pub fn new_noince_url(&self) -> String {
    self.resources.new_nonce.clone()
  }
  
  pub fn revoke_cert_url(&self) -> String {
    self.resources.revoke_cert.clone()
  }

  /// Gets nonce header from directory.
  ///
  fn get_nonce(&self) -> Result<String> {
      let client = Client::new()?;
      let res = client.get(&self.resources.new_nonce).send()?;
      res.headers()
          .get::<ReplayNonce>()
          .ok_or("Replay-Nonce header not found".into())
          .and_then(|nonce| Ok(nonce.as_str().to_string()))
  }

  /// Makes a new post request to directory, signs payload with pkey.
  ///
  /// Returns the result struct that is deserialized from the result
  fn request<'a, T: Serialize, E>(&self,
                           account:&mut Account,
                           url: &str,
                           payload: T)
                           -> Result<E> where for<'de> E : Deserialize<'de> {

      let jws = Jws::new(url, account, payload)?;

      let client = Client::new()?;

      let mut res = client
          .post(url)
          .header(ContentType("application/jose+json".parse().unwrap()))
          .body(jws.to_string()?)
          .send()?;
      
        let mut res_content = String::new();
        res.read_to_string(&mut res_content)?;        
      
      if let Some(loc) = res.headers().get::<Location>() {            
          if account.pkey_id.is_none() {
            account.pkey_id = Some(loc.to_string());
          }
      }     

      Ok(serde_json::from_str(&res_content)?)
  }
}


pub struct Account {
    directory: Directory,
    pkey: PKey<openssl::pkey::Private>,
    pkey_id: Option<String>
}

#[derive(Clone,Debug, Serialize, Deserialize)]
struct RevokeResponse {
    none: String
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Identifier {
    #[serde(rename = "type")]
    itype: String,
    value: String
}

#[derive(Deserialize, Debug, Clone)]
struct FinalizeResponse {
    status: String,
    finalize: String,
    certificate:String,
    expires: String,    
    authorizations:Vec<String>,
    identifiers: Vec<Identifier>
}


#[derive(Clone,Debug, Serialize, Deserialize)]
pub struct CreateOrderResponse {
    finalize_url: String,
    pub challenges: Vec<Challenge>,
    pub domains: Vec<String>
}

impl CreateOrderResponse {
    pub fn get_dns_challenges(&self) -> Vec<Challenge> {
        self.challenges.iter()
            .cloned()
            .filter(|p| p.ctype == "dns-01")
            .collect()
    }
}

#[derive(Clone,Debug, Serialize)]
pub struct NewOrderRequest {
    identifiers: Vec<Identifier>
}

#[derive(Clone,Debug, Deserialize)]
pub struct NewOrderResponse {
    status: String,
    expires: String,    
    identifiers: Vec<Identifier>,
    authorizations: Vec<String>,
    finalize: String
}

impl Account {
    /// Creates a new identifier authorization object for domain
    pub fn create_order<'a>(&'a mut self, domains: &[&str]) -> Result<CreateOrderResponse> {
        info!("Sending identifier authorization request for {:?}", domains.to_vec());

        let mut challenges: Vec<Challenge> = Vec::new();

        let req = NewOrderRequest {
            identifiers: {
                domains.iter().map(|i| {
                    Identifier {
                        itype: "dns".to_string(),
                        value: i.to_string()
                    }
                }).collect()
            }
        };
        let directory = self.directory().clone();
        
        let new_order: NewOrderResponse = directory
            .request(self, &directory.resources.new_order, req)?;
                
        for auth_url in new_order.authorizations {                 
            let mut resp: CheckResponse = directory
                .request(self, &auth_url,  "")?;
                
            for challenge in resp.challenges.iter_mut() {
                let key_authorization = format!("{}.{}",
                challenge.token,
                b64(&hash(MessageDigest::sha256(),
                           &to_string(&Jwk::new(self.pkey()))?
                                    .into_bytes())?));
                challenge.key_authorization = key_authorization.clone();
                challenge.domain = Some(resp.identifier.value.clone());
                challenges.push(challenge.clone());
            }

            
        }
        
        Ok(CreateOrderResponse {
            finalize_url: new_order.finalize,
            challenges: challenges,
            domains:domains.iter().map(|s| String::from(*s)).collect()
        })
    }       

    /// Creates a new `CertificateSigner` helper to sign a certificate for list of domains.
    ///
    /// `domains` must be list of the domain names you want to sign a certificate for.
    /// Currently there is no way to retrieve subject alt names from a X509Req.
    ///
    /// You can additionally use your own private key and CSR.
    /// See [`CertificateSigner`](struct.CertificateSigner.html) for details.
    pub fn certificate_signer<'a>(&'a self) -> CertificateSigner<'a> {
        CertificateSigner {
            account: self,
            pkey: None,
            csr: None,
        }
    }

    /// Revokes a signed certificate from pem formatted file
    pub fn revoke_certificate_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let content = {
            let mut file = File::open(path)?;
            let mut content = Vec::new();
            file.read_to_end(&mut content)?;
            content
        };
        let cert = X509::from_pem(&content)?;
        self.revoke_certificate(&cert)
    }

    /// Revokes a signed certificate
    pub fn revoke_certificate(&mut self, cert: &X509) -> Result<()> {
        let mut map = HashMap::new();
        map.insert("certificate".to_owned(), b64(&cert.to_der()?));
        let directory = self.directory().clone();

        let _response : RevokeResponse = directory
            .request(self, &directory.resources.revoke_cert, map)?;

        Ok(())
    }

    /// Writes account private key to a writer
    pub fn write_private_key<W: Write>(&self, writer: &mut W) -> Result<()> {
        Ok(writer.write_all(&self.pkey().private_key_to_pem_pkcs8()?)?)
    }

    /// Saves account private key to a file
    pub fn save_private_key<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_private_key(&mut file)
    }

    /// Returns a reference to account private key
    pub fn pkey(&self) -> &PKey<openssl::pkey::Private> {
        &self.pkey
    }

    /// Returns a reference to directory used to create account
    pub fn directory(&self) -> &Directory {
        &self.directory
    }
}

#[test]
fn test_order() {
    let _ = env_logger::init();
    let mut account = jwt::tests::test_acc().unwrap();
    let order = account
        .create_order(&vec!["test.shangrila.dev"])
        .unwrap();

    for chal in order.get_dns_challenges() {
        println!("Add {} to .acme-challenge.{}", chal.signature().unwrap(), &chal.domain.as_ref().unwrap());
        
        chal.validate(&account).unwrap();
    }

    let signer = account.certificate_signer();

    signer.sign_certificate(&order).unwrap().save_signed_certificate("tests/cert.pem")
        .unwrap();
}