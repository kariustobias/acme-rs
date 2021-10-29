use openssl::{
    hash::MessageDigest,
    nid::Nid,
    pkey::{Private, Public},
    rsa::Rsa,
    sha::Sha256,
    x509::{X509NameBuilder, X509Req, X509ReqBuilder},
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    error::{Error, Result},
    util::{b64, extract_payload_and_nonce, extract_payload_location_and_nonce, jwk, jws},
};

pub type Nonce = String;
pub type Certificate = String;

/// The current status of the request. The status gets send from
/// the server in every response and shows the progress as well as
/// possible errors.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StatusType {
    #[serde(rename = "valid")]
    Valid,
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "invalid")]
    Invalid,
}

/// The directory information that get returned in the first request
/// to the server. Contains information about the urls of the common
/// http endpoints.
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
    /// Fetches the directory information from a specific server. This is the first request
    /// that's send to the server as it's return value holds information about the endpoints.
    pub fn fetch_dir(client: &Client, server_url: &str) -> Result<Self> {
        let mut dir_infos: Self = client.get(server_url).send()?.json()?;

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

    /// Creates a new account.
    pub fn create_account(
        &self,
        client: &Client,
        p_key: &Rsa<Private>,
        email: &str,
    ) -> Result<Account> {
        let jwk = jwk(p_key)?;
        let header = json!({
            "alg": "RS256",
            "url": self.new_account,
            "jwk": jwk,
            "nonce": self.nonce,
        });

        let payload = json!({
            "termsOfServiceAgreed": true,
            "contact": [format!("mailto:{}", email)]
        });

        let payload = jws(payload, header, p_key)?;

        let response = client
            .post(&self.new_account)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_string_pretty(&payload)?)
            .send()?;

        let (location, nonce, mut account): (String, Nonce, Account) =
            extract_payload_location_and_nonce(response)?;

        account.nonce = nonce;
        account.account_location = location;

        Ok(account)
    }
}

/// A struct that holds information about an `Account` in the `ACME` context.
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
    /// Creates a new order for issuing a dns certificate for a certain domain.
    pub fn create_new_order(
        &self,
        client: &Client,
        new_order_url: &str,
        p_key: &Rsa<Private>,
        domain: &str,
    ) -> Result<Order> {
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

        let response = client
            .post(new_order_url)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_string_pretty(&payload)?)
            .send()?;

        let (nonce, mut order): (Nonce, Order) = extract_payload_and_nonce(response)?;
        order.nonce = nonce;

        Ok(order)
    }
}

/// Holds information about an `Order` in the `ACME` context.
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
    /// Fetches the available authorisation options from the server for a certain order.
    pub fn fetch_auth_challenges(
        &self,
        client: &Client,
        account_url: &str,
        p_key: &Rsa<Private>,
    ) -> Result<ChallengeAuthorisation> {
        let auth_url = self
            .authorizations
            .first()
            .ok_or(Error::NoHttpChallengePresent)?
            .to_string();

        let header = json!({
            "alg": "RS256",
            "url": auth_url,
            "kid": account_url,
            "nonce": self.nonce,
        });

        let payload = json!("");

        let jws = jws(payload, header, p_key)?;

        let response = client
            .post(&auth_url)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_string_pretty(&jws)?)
            .send()?;

        let (nonce, mut challenge): (Nonce, ChallengeAuthorisation) =
            extract_payload_and_nonce(response)?;

        challenge.nonce = nonce;

        Ok(challenge)
    }

    /// Finalizes an order whose challenge was already done. This returns an `UpdatedOrder` object which
    /// is able to download the issued certificate. This method `panics` if the challenge was not yet completed.
    pub fn finalize_order(
        &self,
        client: &Client,
        account_url: &str,
        new_nonce: Nonce,
        p_key: &Rsa<Private>,
        cert_keypair: &(Rsa<Private>, Rsa<Public>),
        domain: &str,
    ) -> Result<UpdatedOrder> {
        let header = json!({
        "alg": "RS256",
        "url": self.finalize,
        "kid": account_url,
        "nonce": new_nonce,
        });

        let csr = Order::request_csr(cert_keypair, domain.to_owned())?;
        let csr_string = b64(&csr.to_der()?);

        let payload = json!({ "csr": csr_string });

        let jws = jws(payload, header, p_key)?;

        let response = client
            .post(&self.finalize)
            .header("Content-Type", "application/jose+json")
            .header("Accept", "application/pem-certificate-chain")
            .body(serde_json::to_string_pretty(&jws)?)
            .send()?;

        let (nonce, mut updated_order): (Nonce, UpdatedOrder) =
            extract_payload_and_nonce(response)?;

        updated_order.nonce = nonce;

        Ok(updated_order)
    }

    /// Factors a csr request, which needs to be sent during finalization.
    fn request_csr(keypair: &(Rsa<Private>, Rsa<Public>), common_name: String) -> Result<X509Req> {
        let mut request = X509ReqBuilder::new()?;
        let mut c_name = X509NameBuilder::new()?;

        let pri_key = &openssl::pkey::PKey::private_key_from_pem(&keypair.0.private_key_to_pem()?)?;
        let public_key =
            &openssl::pkey::PKey::public_key_from_pem(&keypair.1.public_key_to_pem()?)?;

        c_name.append_entry_by_nid(Nid::COMMONNAME, &common_name)?;
        let name = c_name.build();
        request.set_pubkey(public_key)?;
        request.set_subject_name(name.as_ref())?;
        request.sign(pri_key, MessageDigest::sha256())?;

        Ok(request.build())
    }
}

/// Holds information about a `Challenge` in the `ACME` context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub status: StatusType,
    pub token: String,
    #[serde(rename = "type")]
    pub challenge_type: String,
    pub url: String,
}

/// Holds information about the authentification options in the `ACME` context.
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
    /// Completes the http challenge by opening an `http` server which returns the needed token
    /// under the specified path.
    pub fn complete_http_challenge(
        self,
        client: &Client,
        account_url: &str,
        p_key: &Rsa<Private>,
    ) -> Result<Nonce> {
        let http_challenge = self
            .challenges
            .into_iter()
            .find(|challenge| challenge.challenge_type == "http-01")
            .ok_or(Error::NoHttpChallengePresent)?;

        ChallengeAuthorisation::complete_challenge(
            client,
            http_challenge,
            self.nonce,
            account_url,
            p_key,
        )
    }

    /// Actually opens the server and kicks of the challenge.
    fn complete_challenge(
        client: &Client,
        challenge_infos: Challenge,
        nonce: Nonce,
        acc_url: &str,
        private_key: &Rsa<Private>,
    ) -> Result<Nonce> {
        let thumbprint = jwk(private_key)?;
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
                    rouille::Response::text(challenge_content.clone())
                } else {
                    rouille::Response::empty_404()
                }
            });
        });
        std::thread::sleep(std::time::Duration::from_secs(5));
        Ok(result)
    }

    /// Requests the check of the server at the `ACME` server instance.
    fn kick_off_http_challenge(
        client: &Client,
        challenge_infos: Challenge,
        nonce: Nonce,
        acc_url: &str,
        private_key: &Rsa<Private>,
    ) -> Result<Nonce> {
        let header = json!({
            "alg": "RS256",
            "kid": acc_url,
            "nonce": nonce,
            "url": challenge_infos.url
        });

        let payload = json!({});

        let jws = jws(payload, header, private_key)?;

        Ok(client
            .post(&challenge_infos.url)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_string_pretty(&jws)?)
            .send()?
            .headers()
            .get("replay-nonce")
            .ok_or(Error::IncorrectResponse)?
            .to_str()?
            .to_owned())
    }
}

/// Holds information about a finalized order in the `ACME` context.
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
    /// Downloads an issued certificate.
    pub fn download_certificate(
        &self,
        client: &Client,
        account_url: &str,
        p_key: &Rsa<Private>,
    ) -> Result<Certificate> {
        let header = json!({
            "alg": "RS256",
            "url": self.certificate,
            "kid": account_url,
            "nonce": self.nonce,
        });
        let payload = json!("");

        let jws = jws(payload, header, p_key)?;

        Ok(client
            .post(&self.certificate)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_string_pretty(&jws)?)
            .send()?
            .text()?)
    }
}
