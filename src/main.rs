/// enum Option<T> {
///     Some(T),
///     None    
// }

/// enum Result<T, E> {
///     Ok(T),
///     Err(E)    
// }
mod error;

use reqwest::blocking::Client;
use reqwest::Url;

const SERVER: &str = "https://google.de";

fn main() {
    let client = Client::new();
    println!("{}", send_get_request(&client).unwrap());
}

fn send_get_request(client: &Client) -> Result<String, error::Error> {
    let url = Url::parse(SERVER)?;
    Ok(client.get(url).send()?.text()?)
}
