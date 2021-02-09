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

use error::Error;
use openssl::{pkey::Private, rsa::{Padding, Rsa}};
use reqwest::blocking::Client;
use reqwest::Url;
use serde_json::json;
use jsonwebkey_convert::*;
use jsonwebkey_convert::der::FromPem;
use serialized_structs::{AccountCreated, GetDirectory};
use jws::{JsonObject, compact::{EncodedSignedMessage, encode_sign}};
use jws::hmac::{Hs512Signer};

const SERVER: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
#[allow(dead_code)]
const KEY_WIDTH: u32 = 2048;
const ACCOUNT: &str = "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct";

fn main() {
    let client = Client::new();

    let get_dir = get_directory(&client).unwrap();
    let new_nonce = send_get_new_nonce(&client, get_dir.new_nonce).unwrap();

    println!("{:?}", post_get_new_account(&client, "mb.cmbt.de", new_nonce).unwrap());
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
    url_to_register: &str,
    nonce: String,
) -> Result<String, Error> {
    let p_key = generate_rsa_keypair()?;

    let rsa_jwk = RSAPublicKey::from_pem(p_key.public_key_to_pem()?).unwrap();
    let jwk_byte_vec = dbg!(serde_json::to_string(&rsa_jwk).unwrap());

    let mut jws_header = JsonObject::new();
    jws_header.insert("url".to_owned(), json!("https://acme/new-acct"));
    jws_header.insert("nonce".to_owned(), json!(nonce));
    jws_header.insert("jwk".to_owned(), json!(jwk_byte_vec));
    
    let payload = json!({
        "termsOfServiceAgreed": true,
        "contact": ["mailto:bastian@cmbt.de"]
    });
        
    
    let jws_payload = sign_payload_via_jws(payload, p_key, jws_header)?;
    let payload_for_real = json!({
        "payload": jws_payload.payload(),
        "protected": dbg!(jws_payload.header()),
        "signature": jws_payload.signature()
    });

    Ok(dbg!(client
        .post(ACCOUNT)
        .header("Content-Type", "application/jose+json")
        .body(base64::encode(payload_for_real.to_string()))
        .send())?
        .text()?)
}

fn generate_rsa_keypair() -> Result<Rsa<Private>, Error> {
    Ok(Rsa::generate(KEY_WIDTH)?)
}

fn sign_payload_via_jws(payload: serde_json::Value, private_key: Rsa<Private>, header: JsonObject) -> Result<EncodedSignedMessage, Error> {
    
    let mut real_payload: Vec<u8> = vec![0; private_key.size() as usize];
    let _ = private_key.private_encrypt(&payload.to_string().into_bytes(), &mut real_payload, Padding::PKCS1)?;

    let signer = signer::RS256Signer::new(private_key);
    Ok(encode_sign(header, &real_payload, &signer)?)
}
