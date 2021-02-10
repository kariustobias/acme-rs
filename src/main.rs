mod error;
mod serialized_structs;

use base64::encode_config;
use error::Error;
use openssl::{pkey::{self, Private}, rsa::{Padding, Rsa}, hash::MessageDigest};
use openssl::pkey::PKey;
use openssl::nid::Nid;
use openssl::x509;
use openssl::sign::Signer;
use pkey::{Public};
use x509::{X509NameBuilder, X509Req, X509ReqBuilder};
use reqwest::blocking::Client;
use reqwest::Url;
use serde_json::json;
use serialized_structs::GetDirectory;

const IDENTIFIER: &str = "cmbt.de";
const SERVER: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const KEY_WIDTH: u32 = 2048;

fn main() {
    let client = Client::new();
    let p_key = generate_rsa_keypair().unwrap();

    let get_dir = get_directory(&client).unwrap();
    let new_nonce = send_get_new_nonce(&client, get_dir.new_nonce).unwrap();

    let new_acc = get_new_account(&client, new_nonce, get_dir.new_account, p_key.clone()).unwrap();
    println!(
        "{:?}",
        new_acc.2
    );
    let kid = dbg!(new_acc.0);
    let new_nonce = new_acc.1;
    println!(
        "{:?}",
        get_new_order(&client, new_nonce, get_dir.new_order, p_key.clone(), kid).unwrap()
    );

    let csr = request_csr(p_key.clone(),IDENTIFIER.to_owned());
    let mut csr_string =  String::from_utf8(csr.to_pem().unwrap()).unwrap();
    let csr_string = csr_string.split("\n").into_iter();
    
    
    
    println!("{}", csr_string);

    //let finalize_o = finalize_order(&client, new_nonce, order_url, p_key.clone()).unwrap();
}

fn get_directory(client: &Client) -> Result<GetDirectory, Error> {
    let url = Url::parse(SERVER)?;
    Ok(client.get(url).send()?.json()?)
}

fn send_get_new_nonce(client: &Client, new_nonce_url: String) -> Result<String, Error> {
    let url = Url::parse(&new_nonce_url)?;
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

fn get_new_account(
    client: &Client,
    nonce: String,
    url: String,
    p_key: Rsa<Private>,
) -> Result<(String, String, String), Error> {
    let jwk = jwk(p_key.clone())?;

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

    Ok((response.headers().get("location").unwrap().to_str().unwrap().to_owned(), response.headers().get("replay-nonce").unwrap().to_str().unwrap().to_owned(), response.text()?))
}

fn get_new_order(
    client: &Client,
    nonce: String,
    url: String,
    p_key: Rsa<Private>,
    kid: String,
) -> Result<serde_json::Value, Error> {
    let header = json!({
        "alg": "RS256",
        "url": url,
        //"jwk": jwk,
        "kid": kid,
        "nonce": nonce,
    });

    let payload = json!({
        "identifiers": [
            { "type": "dns", "value": IDENTIFIER }
        ]
    });

    let payload = jws(payload, header, p_key)?;

    Ok(dbg!(client
        .post(&url)
        .header("Content-Type", "application/jose+json")
        .body(serde_json::to_string_pretty(&payload)?)
        .send())?
        .json()?)
}
fn finalize_order(client: &Client,
                  nonce: String,
                  url: String,
                  p_key: Rsa<Public>,
                  private_key: Rsa<Private>,
                  common_name: String,
                  kid: String,
) -> Result<String, Error> {
    let header = json!({
        "alg": "RS256",
        "url": url,
        "kid": kid,
        "nonce": nonce,
    });

    let csr = request_csr(private_key.clone(), common_name.clone());
    let csr_string =  String::from_utf8(csr.to_pem().unwrap()).unwrap();

    println!("{}" , csr_string);

    let payload = json!({
        "csr": csr_string
    });

    let payload = jws(payload, header, private_key).unwrap();

    Ok(dbg!(client
        .post(&url)
        .header("Content-Type", "application/jose+json")
        .body(serde_json::to_string_pretty(&payload)?)
        .send())?
        .json()?)
}

fn generate_rsa_keypair() -> Result<Rsa<Private>, Error> {
    Ok(Rsa::generate(KEY_WIDTH)?)
}

fn jwk(private_key: Rsa<Private>) -> Result<serde_json::Value, Error> {
    let e = b64(&private_key.e().to_vec());
    let n = b64(&private_key.n().to_vec());

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
    let payload64 = b64(serde_json::to_string_pretty(&payload)?.as_bytes());
    let header64 = b64(serde_json::to_string_pretty(&header)?.as_bytes());

    let p_key = PKey::private_key_from_pem(&private_key.private_key_to_pem()?)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &p_key)?;

    signer.set_rsa_padding(Padding::PKCS1)?;
    signer.update(&format!("{}.{}", header64, payload64).as_bytes())?;
    let signature = b64(&signer.sign_to_vec()?);

    Ok(json!({
        "protected": header64,
        "payload": payload64,
        "signature": signature
    }))
}

fn b64(to_encode: &[u8]) -> String {
    encode_config(to_encode, base64::URL_SAFE_NO_PAD)
}

#[allow(dead_code)]
fn request_csr(private_key: Rsa<Private>, common_name: String) -> X509Req {
    let mut request = X509ReqBuilder::new().unwrap();
    let mut c_name = X509NameBuilder::new().unwrap();

    let pri_key = &openssl::pkey::PKey::private_key_from_pem(&private_key.private_key_to_pem().unwrap()).unwrap(); 
    let public_key  = &openssl::pkey::PKey::public_key_from_pem(&private_key.public_key_to_pem().unwrap()).unwrap(); 

    c_name.append_entry_by_nid(Nid::COMMONNAME, &common_name).unwrap();
    let name = c_name.build();
    request.set_pubkey(public_key).unwrap();
    request.set_subject_name(name.as_ref()).unwrap();
    request.sign(pri_key, MessageDigest::sha256()).unwrap();

    request.build()
}
