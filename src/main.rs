/// enum Option<T> {
///     Some(T),
///     None    
// }

/// enum Result<T, E> {
///     Ok(T),
///     Err(E)    
// }

use reqwest::blocking::Client;
use reqwest::Url;

const SERVER: &str = "http://google.de";

fn main() {
    let client = Client::new();
    println!("{}", send_get_request(&client).unwrap());

    println!("{}", send_get_request(&client).unwrap());
}

fn send_get_request(client: &Client) -> Result<String, reqwest::Error> {
    if let Ok(url) = Url::parse(SERVER) {
        return client.get(url).send()?.text();
    }
    Ok(String::from("-Hat ned geklappt"))
}

