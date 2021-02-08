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

const SERVER: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
#[allow(dead_code)]
const KEY_WIDTH: u32 = 2048;

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

#[allow(dead_code)]
fn generate_rsa_keypair() -> Result<Rsa<Private>, Error> {
    Ok(Rsa::generate(KEY_WIDTH)?)
}
