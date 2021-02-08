/// enum Option<T> {
///     Some(T),
///     None    
// }

/// enum Result<T, E> {
///     Ok(T),
///     Err(E)    
// }
mod error;

use error::Error;
use reqwest::blocking::Client;
use reqwest::Url;
use serde::de::value::StrDeserializer;
use std::iter::Map;
use openssl::{pkey::Private, rsa::Rsa};

const SERVER: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const KEY_WIDTH: u32 = 2048;


struct Status_type {
    valid: serde_json::Value::String,
    pending: serde_json::Value::String,
    invalid: serde_json::Value::String,
}

struct Get_directory {
    new_nonce: Url,
    new_account: Url,
    new_order: Url,
    revoke_cert: Url,
    key_change: Url,
}

struct Register_account {
    // Terms_of_Service_agreed:bool, contact:String
    payload: (serde_json::Value::Bool, serde_json::Value::Array),
    protected: serde_json::Value,
    signature: serde_json::Value::String,
}

struct Account_created {
    contact: serde_json::Value::Array,
    status: Status_type,
    orders: Url,
}

struct New_order {
    payload: serde_json::Value,
    protected: serde_json::Value,
    signature: serde_json::Value::String,
}

struct Created_new_order {
    status: Status_type,
    expires: serde_json::Value::String,
    identifiers: serde_json::Value::Array,
    not_before: serde_json::Value::String,
    authorisations: serde_json::Value::Array,
    finalize: Url,
}

struct Authorisation {
    payload: Option<String>,
    protected: serde_json::Value,
    signature: serde_json::Value::String,
}

struct Challenge_authorisation {
    // type, value
    identifier: serde_json::Value,
    status: Status_type,
    expires: serde_json::Value::String,
    challenges: serde_json::Value::Array,
    wildcard: serde_json::Value::Bool,
}

struct finalize_order {
    payload: serde_json::Value,
    protected: serde_json::Value,
    signature: serde_json::Value::String,
}


struct updated_order_object {
    status: Status_type,
    expires: serde_json::Value::String,
    identifiers: serde_json::Value,
    not_before: serde_json::Value::String,
    not_after: serde_json::Value::String,
    authorisations: serde_json::Value::Array,
    finalize: Url,
    certificate: Url,
}

struct get_certificate {
    payload: option<String>,
    protected: serde_json::Value,
    signature: serde_json::Value::String,
}

struct Certificate {}

struct conformation {
    certificate: Certificate,
}

fn main() {
    let client = Client::new();

    //get the JSONs from get_directory in String form
    get_directory(&client);

    

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

fn generate_rsa_keypair() -> Result<Rsa<Private>, Error> {
    Ok(Rsa::generate(KEY_WIDTH)?)
}
