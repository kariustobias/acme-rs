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
use serialized_structs::GetDirectory;

const SERVER: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
#[allow(dead_code)]
const KEY_WIDTH: u32 = 2048;

const NONCE: &str = "https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce";

fn main() {
    let client = Client::new();

    //get the JSONs from get_directory in String form
    get_directory(&client);

    let response = send_get_new_nonce(&client).unwrap();
    println!("test");
    println!("{}", response.unwrap());

    //parse the

    //println!("{}", get_directory(&client).unwrap());
}

fn get_directory(client: &Client) {
    //perform get request to initial URL
    let response = send_get_directory_request(&client).unwrap();
    println!("{:#?}", response);

    //store the important URLs
}

fn send_get_directory_request(client: &Client) -> Result<GetDirectory, Error> {
    let url = Url::parse(SERVER)?;
    Ok(client.get(url).send()?.json()?)
}

fn send_get_new_nonce(client: &Client) -> Result<Option<String>, Error> {
    let url = Url::parse(NONCE)?;
    // TODO: make nicer
    Ok(client
        .head(url)
        .send()?
        .headers()
        .get("replay-nonce")
        .map(|value| String::from(value.to_str().unwrap())))
}

#[allow(dead_code)]
fn generate_rsa_keypair() -> Result<Rsa<Private>, Error> {
    Ok(Rsa::generate(KEY_WIDTH)?)
}
