mod error;
mod types;
mod util;

use reqwest::blocking::Client;

use types::Directory;
use util::{generate_rsa_keypair, save_certificates, save_keypair};

const IDENTIFIER: &str = "mb.cmbt.de";
const SERVER: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const KEY_WIDTH: u32 = 2048;

fn main() {
    // create a new client (passed through to each step to make use of the keep-alive function)
    // and create a new key pair
    let client = Client::new();
    let p_key = generate_rsa_keypair().unwrap();

    // fetch the directory infos an create a new account
    let dir_infos = Directory::fetch_dir(&client).unwrap();
    let new_acc = dir_infos.create_account(&client, &p_key).unwrap();
    println!("{:?}", new_acc);

    // create a new order
    let order = new_acc
        .create_new_order(&client, &dir_infos.new_order, &p_key)
        .unwrap();
    println!("{:#?}", &order);

    // fetch the auth challenges
    let challenge = order
        .fetch_auth_challenges(&client, &new_acc.account_location, &p_key)
        .unwrap();

    // complete the challenge and save the nonce that's needed for further authentification
    let new_nonce = challenge
        .complete_http_challenge(&client, &new_acc.account_location, &p_key)
        .unwrap();

    // finalize the order to retrieve location of the final cert
    let updated_order = order
        .finalize_order(&client, &new_acc.account_location, new_nonce, &p_key)
        .unwrap();

    // download the certificate
    let cert_chain = updated_order
        .download_certificate(&client, &new_acc.account_location, &p_key)
        .unwrap();
    println!("{}", &cert_chain);

    // save the certificate and the keypair
    save_certificates(cert_chain).unwrap();
    save_keypair(p_key).unwrap();
}
