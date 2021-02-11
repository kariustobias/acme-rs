use openssl::{
    hash::MessageDigest,
    nid::Nid,
    pkey::Private,
    rsa::Rsa,
    sha::Sha256,
    x509::{X509NameBuilder, X509Req, X509ReqBuilder},
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    error::Error,
    generate_rsa_keypair,
    util::{b64, extract_payload_and_nonce, extract_payload_location_and_nonce, jwk, jws},
    SERVER,
};

pub type Nonce = String;
pub type Certificate = String;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StatusType {
    #[serde(rename = "valid")]
    Valid,
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "invalid")]
    Invalid,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    pub revoke_cert: String,
    pub key_change: String,
    #[serde(skip)]
    nonce: Nonce,
}

impl Directory {
    pub fn fetch_dir(client: &Client) -> Result<Self, Error> {
        let mut dir_infos: Self = client.get(SERVER).send()?.json()?;

        // fetch the new nonce
        let nonce = client
            .head(&dir_infos.new_nonce)
            .send()?
            .headers()
            .get("replay-nonce")
            .ok_or(Error::BadNonce)?
            .to_str()?
            .to_owned();

        dir_infos.nonce = nonce;

        Ok(dir_infos)
    }

    pub fn create_account(&self, client: &Client, p_key: &Rsa<Private>) -> Result<Account, Error> {
        let jwk = jwk(&p_key)?;
        let header = json!({
            "alg": "RS256",
            "url": self.new_account,
            "jwk": jwk,
            "nonce": self.nonce,
        });

        let payload = json!({
            "termsOfServiceAgreed": true,
            "contact": ["mailto:bastian@cmbt.de"]
        });

        let payload = jws(payload, header, p_key)?;

        let response = dbg!(client
            .post(&self.new_account)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_string_pretty(&payload)?)
            .send())?;

        let (location, nonce, mut account): (String, Nonce, Account) =
            extract_payload_location_and_nonce(response)?;

        account.nonce = nonce;
        account.account_location = location;

        Ok(account)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    pub status: String,
    contact: Option<Vec<String>>,
    terms_of_service_agreed: Option<bool>,
    pub orders: Option<Vec<String>>,
    #[serde(skip)]
    pub nonce: Nonce,
    #[serde(skip)]
    pub account_location: String,
}

impl Account {
    pub fn create_new_order(
        &self,
        client: &Client,
        new_order_url: &str,
        p_key: &Rsa<Private>,
        domain: &str,
    ) -> Result<Order, Error> {
        let header = json!({
            "alg": "RS256",
            "url": new_order_url,
            "kid": self.account_location,
            "nonce": self.nonce,
        });

        let payload = json!({
            "identifiers": [
                { "type": "dns", "value": domain }
            ],
        });

        let payload = jws(payload, header, p_key)?;

        let response = dbg!(client
            .post(new_order_url)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_string_pretty(&payload)?)
            .send())?;

        let (nonce, mut order): (Nonce, Order) = extract_payload_and_nonce(response)?;
        order.nonce = nonce;

        Ok(order)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Order {
    pub status: String,
    pub expires: String,
    pub identifiers: serde_json::Value,
    pub authorizations: Vec<String>,
    pub finalize: String,
    #[serde(skip)]
    pub nonce: Nonce,
}

impl Order {
    pub fn fetch_auth_challenges(
        &self,
        client: &Client,
        account_url: &str,
        p_key: &Rsa<Private>,
    ) -> Result<ChallengeAuthorisation, Error> {
        let auth_url = self.authorizations.first().ok_or(Error::NoHttpChallengePresent)?.to_string();

        let header = json!({
            "alg": "RS256",
            "url": auth_url,
            "kid": account_url,
            "nonce": self.nonce,
        });

        let payload = json!("");

        let jws = dbg!(jws(payload, header, p_key)?);

        let response = dbg!(client
            .post(&auth_url)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_string_pretty(&jws)?)
            .send())?;

        let (nonce, mut challenge): (Nonce, ChallengeAuthorisation) =
            extract_payload_and_nonce(response)?;

        challenge.nonce = nonce;

        Ok(challenge)
    }

    pub fn finalize_order(
        &self,
        client: &Client,
        account_url: &str,
        new_nonce: Nonce,
        p_key: &Rsa<Private>,
        domain: &str,
    ) -> Result<UpdatedOrder, Error> {
        let header = json!({
        "alg": "RS256",
        "url": self.finalize,
        "kid": account_url,
        "nonce": new_nonce,
        });

        let csr_key = generate_rsa_keypair()?;
        let csr = Order::request_csr(&csr_key, domain.to_owned())?;
        let csr_string = b64(&csr.to_der()?);

        println!("{}", csr_string);

        let payload = json!({ "csr": csr_string });

        let jws = jws(payload, header, p_key)?;

        let response = dbg!(client
            .post(&self.finalize)
            .header("Content-Type", "application/jose+json")
            .header("Accept", "application/pem-certificate-chain")
            .body(serde_json::to_string_pretty(&jws)?)
            .send())?;

        let (nonce, mut updated_order): (Nonce, UpdatedOrder) =
            extract_payload_and_nonce(response)?;

        updated_order.nonce = nonce;

        Ok(updated_order)
    }

    fn request_csr(private_key: &Rsa<Private>, common_name: String) -> Result<X509Req, Error> {
        let mut request = X509ReqBuilder::new()?;
        let mut c_name = X509NameBuilder::new()?;

        let pri_key =
            &openssl::pkey::PKey::private_key_from_pem(&private_key.private_key_to_pem()?)?;
        let public_key =
            &openssl::pkey::PKey::public_key_from_pem(&private_key.public_key_to_pem()?)?;

        c_name
            .append_entry_by_nid(Nid::COMMONNAME, &common_name)?;
        let name = c_name.build();
        request.set_pubkey(public_key)?;
        request.set_subject_name(name.as_ref())?;
        request.sign(pri_key, MessageDigest::sha256())?;

        Ok(request.build())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub status: StatusType,
    pub token: String,
    #[serde(rename = "type")]
    pub challenge_type: String,
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeAuthorisation {
    // type, value
    pub identifier: serde_json::Value,
    pub status: StatusType,
    pub expires: String,
    pub challenges: Vec<Challenge>,
    pub wildcard: Option<bool>,
    #[serde(skip)]
    pub nonce: Nonce,
}

impl ChallengeAuthorisation {
    pub fn complete_http_challenge(
        self,
        client: &Client,
        account_url: &str,
        p_key: &Rsa<Private>,
    ) -> Result<Nonce, Error> {
        let http_challenge = self
            .challenges
            .into_iter()
            .find(|challenge| challenge.challenge_type == "http-01")
            .ok_or(Error::NoHttpChallengePresent)?;

        Ok(ChallengeAuthorisation::complete_challenge(
            client,
            http_challenge,
            self.nonce,
            account_url,
            p_key,
        )?)
    }

    fn complete_challenge(
        client: &Client,
        challenge_infos: Challenge,
        nonce: Nonce,
        acc_url: &str,
        private_key: &Rsa<Private>,
    ) -> Result<Nonce, Error> {
        let thumbprint = jwk(&private_key)?;
        let mut hasher = Sha256::new();
        hasher.update(&thumbprint.to_string().into_bytes());
        let thumbprint = hasher.finish();

        let challenge_content = format!("{}.{}", challenge_infos.token, b64(&thumbprint));

        let result = ChallengeAuthorisation::kick_off_http_challenge(
            client,
            challenge_infos.clone(),
            nonce,
            acc_url,
            private_key,
        )?;

        std::thread::spawn(|| {
            rouille::start_server("0.0.0.0:80", move |request| {
                if request.raw_url()
                    == format!("/.well-known/acme-challenge/{}", challenge_infos.token)
                {
                    println!("Got Request!");
                    rouille::Response::text(challenge_content.clone())
                } else {
                    rouille::Response::empty_404()
                }
            });
        });
        std::thread::sleep(std::time::Duration::from_secs(5));
        Ok(result)
    }

    fn kick_off_http_challenge(
        client: &Client,
        challenge_infos: Challenge,
        nonce: Nonce,
        acc_url: &str,
        private_key: &Rsa<Private>,
    ) -> Result<Nonce, Error> {
        let header = json!({
            "alg": "RS256",
            "kid": acc_url,
            "nonce": nonce,
            "url": challenge_infos.url
        });

        let payload = json!({});

        let jws = jws(payload, header, private_key)?;

        Ok(dbg!(client
            .post(&challenge_infos.url)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_string_pretty(&jws)?)
            .send())?
        .headers()
        .get("replay-nonce")
        .ok_or(Error::IncorrectResponse)?
        .to_str()?
        .to_owned())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdatedOrder {
    pub status: String,
    expires: String,
    identifiers: serde_json::Value,
    authorizations: serde_json::Value,
    finalize: String,
    pub certificate: String,
    #[serde(skip)]
    pub nonce: Nonce,
}

impl UpdatedOrder {
    pub fn download_certificate(
        &self,
        client: &Client,
        account_url: &str,
        p_key: &Rsa<Private>,
    ) -> Result<Certificate, Error> {
        let header = json!({
            "alg": "RS256",
            "url": self.certificate,
            "kid": account_url,
            "nonce": self.nonce,
        });
        let payload = json!("");

        let jws = dbg!(jws(payload, header, p_key)?);

        Ok(dbg!(client
            .post(&self.certificate)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_string_pretty(&jws)?)
            .send())?
        .text()?)
    }
}
