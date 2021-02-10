/// enum Option<T> {
///     Some(T),
///     None    
// }

/// enum Result<T, E> {
///     Ok(T),
///     Err(E)    
// }
mod error;
mod serialized_structs;
mod signer;

use base64::encode_config;
use error::Error;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::{Padding, Rsa},
    sign::Signer,
};
use reqwest::blocking::Client;
use reqwest::Url;
use serde_json::json;
use serialized_structs::{AccountCreated, GetDirectory};

const SERVER: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
#[allow(dead_code)]
const KEY_WIDTH: u32 = 2048;
const ACCOUNT: &str = "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct";

fn main() {
    let client = Client::new();

    let get_dir = get_directory(&client).unwrap();
    let new_nonce = send_get_new_nonce(&client, get_dir.new_nonce).unwrap();

    println!(
        "{:?}",
        post_get_new_account(&client, new_nonce).unwrap()
    );
}

fn get_directory(client: &Client) -> Result<GetDirectory, Error> {
    let url = Url::parse(SERVER)?;
    Ok(client.get(url).send()?.json()?)
}

fn send_get_new_nonce(client: &Client, new_nonce_url: String) -> Result<String, Error> {
    let url = Url::parse(&new_nonce_url)?;
    // this should never fail, as the whole protocol uses utf-8
    Ok(std::str::from_utf8(
        client
            .head(url)
            .send()?
            .headers()
            .get("replay-nonce")
            .ok_or(Error::BadNonce)?
            .as_bytes(),
    )?
    .to_owned())
}

fn post_get_new_account(
    client: &Client,
    nonce: String,
) -> Result<String, Error> {
    let p_key = generate_rsa_keypair()?;

    let jwk = jwk(p_key.clone())?;

    let header = json!({
        "alg": "RS256",
        "url": "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct",
        "jwk": jwk,
        "nonce": nonce,
    });

    let payload = json!({
        "termsOfServiceAgreed": true,
        "contact": ["mailto:bastian@cmbt.de"]
    });

    let payload = jws(payload, header, p_key)?;

    Ok(dbg!(client
        .post(ACCOUNT)
        .header("Content-Type", "application/jose+json")
        .body(serde_json::to_string_pretty(&payload).unwrap())
        .send())?
    .text()?)
}

fn generate_rsa_keypair() -> Result<Rsa<Private>, Error> {
    Ok(Rsa::generate(KEY_WIDTH)?)
}

fn jwk(private_key: Rsa<Private>) -> Result<serde_json::Value, Error> {
    let e = base64::encode_config(&private_key.e().to_vec(), base64::URL_SAFE_NO_PAD);
    let n = base64::encode_config(&private_key.n().to_vec(), base64::URL_SAFE_NO_PAD);

    Ok(json!({
        "e": e,
        "n": n,
        "kty": "RSA",
    }))
}

fn jws(
    payload: serde_json::Value,
    header: serde_json::Value,
    private_key: Rsa<Private>,
) -> Result<serde_json::Value, Error> {
    let payload64 = base64::encode_config(
        serde_json::to_string_pretty(&payload).unwrap().as_bytes(),
        base64::URL_SAFE_NO_PAD,
    );
    let header64 = base64::encode_config(
        serde_json::to_string_pretty(&header).unwrap(),
        base64::URL_SAFE_NO_PAD,
    );

    let p_key = PKey::private_key_from_pem(&private_key.private_key_to_pem()?)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &p_key)?;

    signer.set_rsa_padding(Padding::PKCS1)?;
    signer.update(&format!("{}.{}", header64, payload64).as_bytes())?;
    let signature = base64::encode_config(&signer.sign_to_vec()?, base64::URL_SAFE_NO_PAD);

    Ok(json!({
        "protected": header64,
        "payload": payload64,
        "signature": signature
    }))
}
