//! This crate provides the ability to create a new `ACME` certificate. It therefore follows the implementation details
//! specified in [RFC8555](https://tools.ietf.org/html/rfc8555).
//!
//! ## Features
//! - `acme-rs` in its current state does only support the http challenge. The port 80 must not be blocked as this tool opens a http server in order to complete the challenge <br>
//! - You have the option to generate you keypair for the certificate first before executing the client. <br>
//! - By default, acme-rs will send the request to the URL https://acme-v02.api.letsencrypt.org/directory. However, you can manually change the ACME Server URL by using the `--server` flag. Just make sure you pass in the URL pointing to the _directory_ information. The client then fetches all paths for further requests from the endpoint.
//!
//! # Usage
//! This crate currently only exposes a few methods. The main method `generate_cert_for_domain` exposes the functionality of the full working process of requesting a SSL/TLS certificate.
//! It therefore completes the following steps:
//! - Create a new account for a specialized `email` address.
//! - Create a new order with that account for a certificate over the specified `domain`.
//! - Fetch the list of available challenges from the order.
//! - Complete the http challenge by opening a webserver on port `80`.
//! - Download the certificate from the server and return it.
//!
//! The method takes a RSA keypair, the domain, the email and the ACME server url as an input.
//!
//! This method is also used by the binary cli that ships with this crate. Usage instructions for the cli and information about the project in general can be found [here](https://github.com/kariustobias/acme-rs).
//!
//! ## Example
//! ```ignore,rust
//! use acme_rs::{generate_cert_for_domain, util::{generate_rsa_keypair, save_certificates, save_keypair}};
//!
//! // create a keypair and request the certificate for it
//! let keypair = generate_rsa_keypair().expect("Error during key creation");
//! let cert_chain = generate_cert_for_domain(
//!            &keypair,
//!            None,
//!            "www.example.org",
//!            "https://acme-v02.api.letsencrypt.org/directory",
//!            "max@mustermann.de",
//!            false,
//!            false,
//!        ).expect("Error while requesting the certificate.")
//!
//! // save the certificate in two files called my_cert.crt and cert_chain.crt
//! save_certificates(cert_chain).expect("Unable to save certificate");
//! ```

use error::Error;
use log::info;
use openssl::{
    pkey::{Private, Public},
    rsa::Rsa,
    x509::X509Req,
};
use reqwest::blocking::Client;
use types::{Certificate, Directory};
use util::generate_rsa_key;

/// The module which encapsulates the error enumeration
/// and related code and types.
pub mod error;
/// All types concerning the ACME context. All of the types are
/// serializable for easy communication.
mod types;
/// A module that contains utility methods used in the acme-rs context. This
/// module heavily uses the `serde_json` and `openssl` libaries.
pub mod util;

const KEY_WIDTH: u32 = 2048;

/// Generates a certificate for a certain domain. This method contains the logic for communicating with
/// the server in order to authenticate for the certificate. The keypair that's passed to this method is
/// used to sign the certificate signing request (CSR). In case a pre loaded CSR is passed in, the keypair
/// needs to be the same as the one that signed the CSR.
/// # Example
/// ```ignore,rust
/// use acme_rs::{generate_cert_for_domain, util::{generate_rsa_keypair, save_certificates, save_keypair}};
///
/// // create a keypair and request the certificate for it
/// let keypair = generate_rsa_keypair().expect("Error during key creation");
/// let cert_chain = generate_cert_for_domain(
///            &keypair,
///            None,
///            "www.example.org",
///            "https://acme-v02.api.letsencrypt.org/directory",
///            "max@mustermann.de",
///            false,
///            false,
///        ).expect("Error while requesting the certificate.")
///
/// // save the certificate in two files called my_cert.crt and cert_chain.crt
/// save_certificates(cert_chain).expect("Unable to save certificate");
/// ```
pub fn generate_cert_for_domain<T: AsRef<str>>(
    keypair_for_cert: &(Rsa<Private>, Rsa<Public>),
    optional_csr: Option<X509Req>,
    domain: T,
    server: T,
    email: T,
    standalone: bool,
    verbose: bool,
) -> Result<Certificate, Error> {
    // this keypair is used for authentificating the requests, but does not matter afterwards
    let keypair = generate_rsa_key()?;
    // create a new client (passed through to each step to make use of the keep-alive function)
    let client = Client::new();

    // fetch the directory infos an create a new account
    let dir_infos = Directory::fetch_dir(&client, server.as_ref())?;
    let new_acc = dir_infos.create_account(&client, &keypair, email.as_ref())?;
    if verbose {
        info!("Created account: {:#?}", new_acc);
    }

    // create a new order
    let order = new_acc.create_new_order(
        &client,
        &dir_infos.new_order,
        &keypair,
        domain.as_ref(),
        optional_csr,
    )?;
    if verbose {
        info!(
            "Opened new order for domain {}: {:#?}",
            domain.as_ref(),
            &order
        );
    }

    // fetch the auth challenges
    let challenge = order.fetch_auth_challenges(&client, &new_acc.account_location, &keypair)?;
    if verbose {
        info!(
            "Got the following authorization challenges: {:#?}",
            &challenge
        );
    }

    // complete the challenge and save the nonce that's needed for further authentification
    let new_nonce = challenge.complete_http_challenge(
        &client,
        &new_acc.account_location,
        &keypair,
        standalone,
    )?;
    if verbose {
        info!("Succesfully completed the http challenge");
    }

    // finalize the order to retrieve location of the final cert
    let updated_order = order.finalize_order(
        &client,
        &new_acc.account_location,
        new_nonce,
        &keypair,
        keypair_for_cert,
        domain.as_ref(),
    )?;

    // download the certificate
    let cert_chain =
        updated_order.download_certificate(&client, &new_acc.account_location, &keypair)?;
    if verbose {
        info!("Received the following certificate chain: {}", cert_chain);
    }

    Ok(cert_chain)
}
