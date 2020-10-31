
use crate::{ContentType, jwt::Jws};
use crate::Client;
use crate::Account;
use crate::File;
use crate::Path;
use crate::Identifier;
use std::io::Read;

use openssl::hash::{hash, MessageDigest};
use crate::helper::*;
use log::debug;
use reqwest::{Response, StatusCode};

use crate::error::{Result, ErrorKind};
use serde::{Serialize, Deserialize};

#[derive(Deserialize, Serialize, Debug, Clone)]
/// A verification challenge.
pub struct Challenge {
    #[serde(skip)]
    pub(crate) auth : Option<String>,
    /// Type of verification challenge. Usually `http-01`, `dns-01` for letsencrypt.
    #[serde(rename = "type")]
    pub(crate) ctype: String,
    /// URL to trigger challenge.
    pub(crate) url: String,
    /// Challenge token.
    pub(crate) token: String,
    /// Key authorization.
    pub(crate) status: String,
    #[serde(skip)]
    pub(crate) key_authorization: String
}
#[derive(Deserialize, Debug, Clone)]
pub struct CheckResponse {
    pub(crate) status: String,
    pub(crate) expires: String,    
    pub(crate) identifier: Identifier,
    pub(crate) challenges: Vec<Challenge>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ValidatePayload {
    #[serde(rename = "type")]
    pub(crate) ctype: String,
    pub(crate) token: String,
    pub(crate) resource: String,
    #[serde(rename = "keyAuthorization")]
    pub(crate) key_authorization: String
}

impl Challenge {
    /// Saves key authorization into `{path}/.well-known/acme-challenge/{token}` for http challenge.
    pub fn save_key_authorization<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        use std::fs::create_dir_all;
        let path = path.as_ref().join(".well-known").join("acme-challenge");
        debug!("Saving validation token into: {:?}", &path);
        create_dir_all(&path)?;

        let _file = File::create(path.join(&self.token))?;
        //writeln!(&mut file, "{}", self.key_authorization)?;

        Ok(())
    }

    /// Gets DNS validation signature.
    ///
    /// This value is used for verification of domain over DNS. Signature must be saved
    /// as a TXT record for `_acme_challenge.example.com`.
    pub fn signature(&self) -> Result<String> {
        Ok(b64(&hash(MessageDigest::sha256(),
                     &self.key_authorization.clone().into_bytes())?))
        
    }

    /// Returns challenge type, usually `http-01` or `dns-01` for Let's Encrypt.
    pub fn ctype(&self) -> &str {
        &self.ctype
    }

    /// Returns challenge token
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Returns key_authorization
    pub fn key_authorization(&self) -> &str {
        &self.key_authorization
    }

    /// Triggers validation.
    pub fn validate(&self, account: &Account) -> Result<()> {        
        let payload = 
            Jws::new(&self.url, account, ValidatePayload {
                ctype: self.ctype.clone(),
                token: self.token.clone(),
                resource: "challenge".into(),
                key_authorization: self.key_authorization().to_string()
            })?;        

        let client = Client::new()?;

        let mut resp = client.post(&self.url)
            .header(ContentType("application/jose+json".parse().unwrap()))
            .body(payload.to_string()?).send()?;

        if resp.status() != &StatusCode::Accepted && resp.status() != &StatusCode::Ok {
            return Err(ErrorKind::Msg("Unacceptable status when trying to validate".to_string()).into());
        }

        let mut auth : Challenge = resp.into();
        
        auth.key_authorization = self.key_authorization().to_string();

        loop {
            let status = &auth.status;

            if status == "pending" {
                let mut resp = client
                    .post(&auth.url)
                    .header(ContentType("application/jose+json".parse().unwrap()))
                    .body({                        
                        Jws::new(&auth.url,account, "")?.to_string()?
                    })
                    .send()?;

                    let mut res_content = String::new();
                    
                    resp.read_to_string(&mut res_content)?;

                    auth = serde_json::from_str(&res_content)?;

            } else if status == "valid" {
                
                
                return Ok(());
            } else if status == "invalid" {
                return Err(ErrorKind::Msg("Invalid response.".into()).into());
            }

            use std::thread::sleep;
            use std::time::Duration;
            sleep(Duration::from_secs(2));
        }
    }
}

impl From<Response> for Challenge {
    fn from(mut response: Response) -> Self {
        let mut res_content = String::new();
        response.json().unwrap()
    }
}