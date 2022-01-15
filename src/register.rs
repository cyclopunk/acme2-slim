use std::{collections::HashMap, path::Path};

use log::info;
use openssl::pkey::PKey;

use crate::error::Result;
use crate::helper::*;
use crate::{Account, Directory};
use serde::{Deserialize, Serialize};
pub struct AccountRegistration {
    pub directory: Directory,
    pub pkey: Option<PKey<openssl::pkey::Private>>,
    pub email: Option<String>,
    pub contact: Option<Vec<String>>,
    pub agreement: Option<String>,
}

#[derive(Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct RegisterRequest {
    pub terms_of_service_agreed: bool,
}
#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct RegisterResult {
    #[serde(default)]
    contact: Vec<String>,
    initial_ip: String,
    created_at: String,
    status: String,
    #[serde(flatten)]
    key: HashMap<String, serde_json::Value>,
}

impl Default for RegisterResult {
    fn default() -> Self {
        RegisterResult {
            contact: Vec::default(),
            initial_ip: String::default(),
            created_at: String::default(),
            status: String::default(),
            key: HashMap::default(),
        }
    }
}
impl AccountRegistration {
    /// Sets contact email address
    pub fn email(mut self, email: &str) -> AccountRegistration {
        self.email = Some(email.to_owned());
        self
    }

    /// Sets contact details such as telephone number (Let's Encrypt only supports email address).
    pub fn contact(mut self, contact: &[&str]) -> AccountRegistration {
        self.contact = Some(contact.iter().map(|c| c.to_string()).collect());
        self
    }

    /// Sets agreement url,
    /// [`LETSENCRYPT_AGREEMENT_URL`](constant.LETSENCRYPT_AGREEMENT_URL.html)
    /// will be used during registration if it's not set.
    pub fn agreement(mut self, url: &str) -> AccountRegistration {
        self.agreement = Some(url.to_owned());
        self
    }

    /// Sets account private key. A new key will be generated if it's not set.
    pub fn pkey(mut self, pkey: PKey<openssl::pkey::Private>) -> AccountRegistration {
        self.pkey = Some(pkey);
        self
    }

    /// Sets PKey from a PEM formatted file.
    pub async fn pkey_from_file<P: AsRef<Path>>(mut self, path: P) -> Result<AccountRegistration> {
        self.pkey = Some(read_pkey(path).await?);
        Ok(self)
    }

    /// Registers an account.
    ///
    /// A PKey will be generated if it doesn't exists.
    pub async fn register(self) -> Result<Account> {
        info!("Registering account");

        let pkey = self.pkey.unwrap_or(gen_key()?);

        let mut account = Account {
            directory: self.directory.clone(),
            pkey_id: None,
            pkey,
        };

        let url = &self.directory.resources.new_account.clone();

        let _result: RegisterResult = self
            .directory
            .request(
                &mut account,
                &url,
                RegisterRequest {
                    terms_of_service_agreed: true,
                },
            )
            .await?;

        Ok(account)
    }
}
