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
use reqwest::blocking::Client;
use reqwest::Url;
use openssl::{pkey::Private, rsa::Rsa};
use serde_json::json;
use serialized_structs::{Account, AccountManagment};

const SERVER: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
#[allow(dead_code)]
const KEY_WIDTH: u32 = 2048;
const ACCOUNT:&str = "";
const NONCE: &str = "https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce";

fn main() {
    let client = Client::new();

    //get the JSONs from get_directory in String form
    get_directory(&client);
    let response = send_get_new_nonce(&client).unwrap();
    println!("test");
    println!("{}", response);

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
    let url = Url::parse(NONCE).unwrap();
    Some(client.head(url).send().unwrap().headers().get("replay-nonce").unwrap().to_str().unwrap().to_owned())
}
fn post_get_new_Account(client: &Client, url: String, nonce: String, mailTo:serde_json::Value, termsOfServiceAgreed: bool, signature: String) -> Option<Account>{
    let alg = "RS256";
    let jwk = json!({
        "e" : ["AQAB"],
        "n" : ["WEIß ich nicht"],
        "kty": ["RSA"],
    });
    let protected = json!({
        "url": [url],
        "alg": [alg],
        "nonce": [nonce],
        "jwk" : [jwk],
        });
    let data: serialized_structs::AccountManagment = AccountManagment { payload: (termsOfServiceAgreed, mailTo), protected: (protected), signature: (signature), contact: (None), terms_Of_Service_Agreed: (None), only_return_existing: (None), external_Account_Binding: (None) };
    if let Ok(accountCreation) = serde_json::to_string(&data) {
        //senden
        let result:Result<serialized_structs::Account, reqwest::Error>  = client.post(ACCOUNT).body(accountCreation).send().unwrap().json();
        match result {
            Ok(data) => {return Some(data)}
            Err(error) => {println!("{:?}", error)}
        }
    }
    //Failure
    return None;
}


#[allow(dead_code)]
fn generate_rsa_keypair() -> Result<Rsa<Private>, Error> {
    Ok(Rsa::generate(KEY_WIDTH)?)
}
