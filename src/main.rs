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

use error::Error;
use openssl::{pkey::Private, rsa::Rsa};
use reqwest::blocking::Client;
use reqwest::Url;
use serde_json::json;
use serialized_structs::{AccountCreated, RegisterAccount};
use base64::encode;

const SERVER: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
#[allow(dead_code)]
const KEY_WIDTH: u32 = 2048;
const ACCOUNT: &str = "https://acme-staging-v02.api.letsencrypt.org/acme/new-account";
const NONCE: &str = "https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce";

fn main() {
    let client = Client::new();

    println!("{:#?}", post_get_new_account(&client, String::from("mb.cmbt.de"), String::from("rgtfjgefjklrhgljk")).unwrap());
    //get the JSONs from get_directory in String form
    get_directory(&client);
    let response = send_get_new_nonce(&client).unwrap();

    println!("Our nonce: {}", response);

    //parse the

    //println!("{}", get_directory(&client).unwrap());
}

fn get_directory(client: &Client) {
    //perform get request to initial URL
    let response = send_get_directory_request(&client).unwrap();
    println!("{}", response);
    //deserialize the JSON String

    //store the important URLs
}

fn send_get_directory_request(client: &Client) -> Result<String, Error> {
    let url = Url::parse(SERVER)?;
    Ok(client.get(url).send()?.text()?)
}

fn send_get_new_nonce(client: &Client) -> Result<String, Error> {
    let url = Url::parse(NONCE)?;
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
    url_to_register: String,
    nonce: String,
) -> Result<AccountCreated, Error> {
    let alg = "RS256";
    let jwk = json!({
                    "e" : ["AQAB"],
                    "n" : ["WEIß ich nicht"],
                    "kty": ["RSA"],
    });
    let protected = json!({
                    "url": [url_to_register],
                    "alg": [alg],
                    "nonce": [nonce],
                    "jwk" : [jwk],
    });
    let data: serialized_structs::RegisterAccount = RegisterAccount {
        payload: (
            true, // alway signed the TOS
            serde_json::Value::String("bastian@cmbt.de".to_owned()), // hardcoded email address
        ),
        protected: (protected),
        signature: ("123".to_owned()),
    };

    let account_creation = serde_json::to_string(&data).unwrap();

    Ok(client
        .post(ACCOUNT)
        .body(encode(account_creation.into_bytes()))
        .send()
        .unwrap()
        .json()?)
}

#[allow(dead_code)]
fn generate_rsa_keypair() -> Result<Rsa<Private>, Error> {
    Ok(Rsa::generate(KEY_WIDTH)?)
}
