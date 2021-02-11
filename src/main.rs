mod error;
mod types;
mod util;

use clap::Clap;
use error::Error;
use openssl::{pkey::Private, rsa::Rsa};
use reqwest::blocking::Client;

use types::{Certificate, Directory};
use util::{generate_rsa_keypair, load_keys_from_file, save_certificates, save_keypair};

const SERVER: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const KEY_WIDTH: u32 = 2048;

#[derive(Clap)]
#[clap(version = "0.1.0", author = "Bastian Kersting <bastian@cmbt.de>, Tobias Karius <tobias.karius@yahoo.de>, Elena Lilova <elena.lilova@gmx.de>, Dominik Jantschar <dominik.jantschar@web.de>")]
struct Opts {
    /// The domain to register the certificate for
    #[clap(short, long)]
    domain: String,
    /// An optional private key file (PEM format) to load the keys from
    #[clap(short, long)]
    private_key: Option<String>,
}

fn main() {
    // parse the cmd arguments
    let opts: Opts = Opts::parse();

    // create a new key pair
    let p_key = match opts.private_key {
        Some(path) => load_keys_from_file(path),
        None => generate_rsa_keypair(),
    }.expect("Could not generate keypair");

    // get the certificate
    let cert_chain = generate_cert_for_domain(&p_key, opts.domain).expect("Error during creation");

    // save the certificate and the keypair
    save_certificates(cert_chain).expect("Unable to save certificate");
    save_keypair(p_key).expect("Unable to save keypair");
}

fn generate_cert_for_domain<T: AsRef<str>>(
    keypair: &Rsa<Private>,
    domain: T,
) -> Result<Certificate, Error> {
    // create a new client (passed through to each step to make use of the keep-alive function)
    let client = Client::new();

    // fetch the directory infos an create a new account
    let dir_infos = Directory::fetch_dir(&client)?;
    let new_acc = dir_infos.create_account(&client, &keypair)?;
    println!("{:?}", new_acc);

    // create a new order
    let order =
        new_acc.create_new_order(&client, &dir_infos.new_order, &keypair, domain.as_ref())?;
    println!("{:#?}", &order);

    // fetch the auth challenges
    let challenge = order.fetch_auth_challenges(&client, &new_acc.account_location, &keypair)?;

    // complete the challenge and save the nonce that's needed for further authentification
    let new_nonce =
        challenge.complete_http_challenge(&client, &new_acc.account_location, &keypair)?;

    // finalize the order to retrieve location of the final cert
    let updated_order = order.finalize_order(
        &client,
        &new_acc.account_location,
        new_nonce,
        &keypair,
        domain.as_ref(),
    )?;

    // download the certificate
    let cert_chain =
        updated_order.download_certificate(&client, &new_acc.account_location, &keypair)?;
    println!("{}", &cert_chain);

    Ok(cert_chain)
}
