mod error;
mod serialized_structs;
mod util;

use error::Error;
use openssl::{hash::MessageDigest, x509};
use openssl::{nid::Nid, pkey::Private, rsa::Rsa, sha::Sha256};
use reqwest::blocking::Client;

use serde_json::{json, Value};
use serialized_structs::{Challenge, ChallengeAuthorisation, Directory};
use util::{
    b64, extract_payload_and_nonce, extract_payload_location_and_nonce, jwk, jws, save_certificates,
};
use x509::{X509NameBuilder, X509Req, X509ReqBuilder};

const IDENTIFIER: &str = "mb.cmbt.de";
const SERVER: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const KEY_WIDTH: u32 = 2048;

type Nonce = String;

fn main() {
    let client = Client::new();
    let p_key = generate_rsa_keypair().unwrap();

    let dir_infos = Directory::fetch_dir(&client).unwrap();
    let new_acc = dir_infos.create_account(&client, &p_key).unwrap();

    println!("{:?}", new_acc);

    let order = new_acc
        .create_new_order(&client, &dir_infos.new_order, &p_key)
        .unwrap();
    println!("{:#?}", &order);

    let chall = order
        .fetch_auth_challenges(&client, &new_acc.account_location, &p_key)
        .unwrap();

    let new_nonce = chall
        .complete_http_challenge(&client, &new_acc.account_location, &p_key)
        .unwrap();


    let finalized_cert = order.finalize_order(&client, &new_acc.account_location, new_nonce, &p_key).unwrap();

    let new_nonce = finalized_cert.nonce;
    let cert_url = finalized_cert.certificate;

    let cert_chain = download_certificate(
        &client,
        new_nonce,
        cert_url,
        &new_acc.account_location,
        &p_key,
    )
    .unwrap();
    println!("{}", &cert_chain);

    save_certificates(cert_chain).unwrap();
}

fn fetch_directory_locations(client: &Client) -> Result<Directory, Error> {
    Ok(client.get(SERVER).send()?.json()?)
}

fn send_get_new_nonce(client: &Client, new_nonce_url: String) -> Result<Nonce, Error> {
    Ok(client
        .head(&new_nonce_url)
        .send()?
        .headers()
        .get("replay-nonce")
        .ok_or(Error::BadNonce)?
        .to_str()?
        .to_owned())
}

fn get_new_account(
    client: &Client,
    nonce: Nonce,
    url: String,
    p_key: &Rsa<Private>,
) -> Result<(String, Nonce, Value), Error> {
    let jwk = jwk(&p_key)?;
    let header = json!({
        "alg": "RS256",
        "url": url,
        "jwk": jwk,
        "nonce": nonce,
    });

    let payload = json!({
        "termsOfServiceAgreed": true,
        "contact": ["mailto:bastian@cmbt.de"]
    });

    let payload = jws(payload, header, p_key)?;

    let response = dbg!(client
        .post(&url)
        .header("Content-Type", "application/jose+json")
        .body(serde_json::to_string_pretty(&payload)?)
        .send())?;

    Ok(extract_payload_location_and_nonce(response)?)
}

fn get_new_order(
    client: &Client,
    nonce: Nonce,
    url: String,
    p_key: &Rsa<Private>,
    kid: &str,
) -> Result<(Nonce, serde_json::Value), Error> {
    let header = json!({
        "alg": "RS256",
        "url": url,
        "kid": kid,
        "nonce": nonce,
    });

    let payload = json!({
        "identifiers": [
            { "type": "dns", "value": IDENTIFIER }
        ],
    });

    let payload = jws(payload, header, p_key)?;

    let response = dbg!(client
        .post(&url)
        .header("Content-Type", "application/jose+json")
        .body(serde_json::to_string_pretty(&payload)?)
        .send())?;

    Ok(extract_payload_and_nonce(response)?)
}

fn get_authorisation(
    client: &Client,
    nonce: Nonce,
    url: String,
    acct_url: &str,
    private_key: &Rsa<Private>,
) -> Result<(Nonce, ChallengeAuthorisation), Error> {
    let header = json!({
        "alg": "RS256",
        "url": url,
        "kid": acct_url,
        "nonce": dbg!(nonce),
    });
    let payload = json!("");

    let jws = dbg!(jws(payload, header, private_key)?);

    let response = dbg!(client
        .post(&url)
        .header("Content-Type", "application/jose+json")
        .body(serde_json::to_string_pretty(&jws)?)
        .send())?;

    Ok(extract_payload_and_nonce(response)?)
}

fn kick_off_http_chall(
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
    .unwrap()
    .to_str()
    .unwrap()
    .to_owned())
}

fn generate_rsa_keypair() -> Result<Rsa<Private>, Error> {
    Ok(Rsa::generate(KEY_WIDTH)?)
}

fn finalize_order(
    client: &Client,
    nonce: Nonce,
    url: String,
    private_key: &Rsa<Private>,
    acc_url: &str,
) -> Result<(Nonce, serde_json::Value), Error> {
    let header = json!({
    "alg": "RS256",
    "url": url,
    "kid": acc_url,
    "nonce": nonce,
    });

    let csr_key = generate_rsa_keypair()?;
    let csr = request_csr(csr_key, IDENTIFIER.to_owned());
    let csr_string = b64(&csr.to_der().unwrap());

    println!("{}", csr_string);

    let payload = json!({ "csr": csr_string });

    let jws = jws(payload, header, private_key).unwrap();

    let response = dbg!(client
        .post(&url)
        .header("Content-Type", "application/jose+json")
        .header("Accept", "application/pem-certificate-chain")
        .body(serde_json::to_string_pretty(&jws)?)
        .send())?;
    Ok(extract_payload_and_nonce(response)?)
}

fn download_certificate(
    client: &Client,
    nonce: Nonce,
    cert_url: String,
    acct_url: &str,
    private_key: &Rsa<Private>,
) -> Result<String, Error> {
    let header = json!({
        "alg": "RS256",
        "url": cert_url,
        "kid": acct_url,
        "nonce": dbg!(nonce),
    });
    let payload = json!("");

    let jws = dbg!(jws(payload, header, private_key)?);

    Ok(dbg!(client
        .post(&cert_url)
        .header("Content-Type", "application/jose+json")
        .body(serde_json::to_string_pretty(&jws)?)
        .send())?
    .text()?)
}

fn request_csr(private_key: Rsa<Private>, common_name: String) -> X509Req {
    let mut request = X509ReqBuilder::new().unwrap();
    let mut c_name = X509NameBuilder::new().unwrap();

    let pri_key =
        &openssl::pkey::PKey::private_key_from_pem(&private_key.private_key_to_pem().unwrap())
            .unwrap();
    let public_key =
        &openssl::pkey::PKey::public_key_from_pem(&private_key.public_key_to_pem().unwrap())
            .unwrap();

    c_name
        .append_entry_by_nid(Nid::COMMONNAME, &common_name)
        .unwrap();
    let name = c_name.build();
    request.set_pubkey(public_key).unwrap();
    request.set_subject_name(name.as_ref()).unwrap();
    request.sign(pri_key, MessageDigest::sha256()).unwrap();

    request.build()
}
