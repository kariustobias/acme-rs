use acme_rs::{
    generate_cert_for_domain,
    util::{
        check_for_existing_server, generate_rsa_keypair, load_csr_from_file, load_keys_from_file,
        save_certificates, save_keypair,
    },
};
use clap::{IntoApp, Parser};
use flexi_logger::Logger;
use log::info;

const LETS_ENCRYPT_SERVER: &str = "https://acme-v02.api.letsencrypt.org/directory";
#[allow(dead_code)]
const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// An acme client (RFC8555) written in the rust programming language
#[derive(Parser)]
#[clap(
    version = "0.1.0",
    author = "Bastian Kersting <bastian@cmbt.de>, Tobias Karius <tobias.karius@yahoo.de>, Elena Lilova <elena.lilova@gmx.de>, Dominik Jantschar <dominik.jantschar@web.de>"
)]
struct Opts {
    // The email associated with the domain
    #[clap(short, long)]
    email: String,
    /// The domain to register the certificate for
    #[clap(short, long)]
    domain: String,
    /// An optional private key file (PEM format) to load the keys from
    #[clap(long)]
    private_key: Option<String>,
    // An optional public key file (PEM format) to load the keys from
    #[clap(long)]
    public_key: Option<String>,
    /// The ACME server's URL
    #[clap(short, long)]
    server: Option<String>,
    /// Initialize a standalone web server if there is not one already using port 80.
    #[clap(long)]
    standalone: bool,
    /// An optional path to a PEM formatted Certificate Signing Request (CSR)
    #[clap(long)]
    csr_path: Option<String>,
    /// Enables debug output.
    #[clap(short, long)]
    verbose: bool,
}

fn main() {
    // parse the cmd arguments
    let opts: Opts = Opts::parse();
    let mut app = Opts::into_app();

    if opts.verbose {
        // setup the logger if necessary
        Logger::with_str("info")
            .log_target(flexi_logger::LogTarget::StdOut)
            .start()
            .unwrap_or_else(|e| panic!("Logger initialization failed with {}", e));
    }

    if opts.csr_path.is_some() && (opts.private_key.is_none() || opts.public_key.is_none()) {
        app.error(
            clap::ErrorKind::ArgumentConflict,
            r#"Error! If you provide a CSR you must also specify the keypair
                        that signed the CSR via --private-key and --public-key"#,
        )
        .exit();
    }

    // create a new key pair or otherwise read from a file
    let keypair_for_cert = match (opts.private_key.as_ref(), opts.public_key.as_ref()) {
        (Some(priv_path), Some(pub_path)) => load_keys_from_file(priv_path, pub_path),
        (Some(_), None) | (None, Some(_)) => app
            .error(
                clap::ErrorKind::ArgumentConflict,
                "Error! Provide both a public and a private key!",
            )
            .exit(),

        (None, None) => generate_rsa_keypair(),
    }
    .expect("Could not generate keypair");

    let optional_csr = if let Some(path) = opts.csr_path {
        Some(load_csr_from_file(&path).expect("Error loading the CSR"))
    } else {
        None
    };

    if opts.verbose && optional_csr.is_some() {
        info!("Successfully loaded CSR");
    }

    if opts.standalone && check_for_existing_server() {
        app.error(
            clap::ErrorKind::DisplayHelp,
            "Error! Provided the standalone option with a process already listening on port 80",
        )
        .exit();
    }

    // get the certificate
    let cert_chain = match opts.server {
        Some(url) => generate_cert_for_domain(
            &keypair_for_cert,
            optional_csr,
            opts.domain,
            url,
            opts.email,
            opts.standalone,
            opts.verbose,
        ),
        None => generate_cert_for_domain(
            &keypair_for_cert,
            optional_csr,
            opts.domain,
            LETS_ENCRYPT_SERVER.to_owned(),
            opts.email,
            opts.standalone,
            opts.verbose,
        ),
    }
    .expect("Error during creation");

    // save the certificate and the keypair
    save_certificates(cert_chain).expect("Unable to save certificate");
    if opts.public_key.as_ref().is_none() {
        save_keypair(&keypair_for_cert).expect("Unable to save keypair");
    }
}
