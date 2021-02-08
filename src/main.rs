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

const SERVER: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

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

fn send_get_directory_request(client: &Client) -> Result<String, error::Error> {
    let url = Url::parse(SERVER)?;
    Ok(client.get(url).send()?.text()?)
}
