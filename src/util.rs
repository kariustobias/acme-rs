use base64::encode_config;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::{Padding, Rsa},
    sign::Signer,
    x509::X509Req,
};
use reqwest::blocking::Response;
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::{
    error::Error,
    types::{Certificate, Nonce},
    KEY_WIDTH,
};

/// Generates a `RSA` private key.
pub(crate) fn generate_rsa_key() -> Result<Rsa<Private>, Error> {
    Ok(Rsa::generate(KEY_WIDTH)?)
}

/// Generates a `RSA` keypair.
pub fn generate_rsa_keypair() -> Result<(Rsa<Private>, Rsa<Public>), Error> {
    let rsa_key = generate_rsa_key()?;
    Ok((
        Rsa::private_key_from_pem(&rsa_key.private_key_to_pem()?)?,
        Rsa::public_key_from_pem(&rsa_key.public_key_to_pem()?)?,
    ))
}

/// Builds a json web key `JWK` (RFC7517) for a RSA private key.
/// # Example
/// ```rust
/// use acme_rs::util::jwk;
/// use openssl::Rsa;
///
/// let priv_key = Rsa::generate(2048).expect("Error while receiving private key");
///
/// let jwk = jwk(priv_key).expect("Error while creating jwk");
/// ```
pub fn jwk(private_key: &Rsa<Private>) -> Result<serde_json::Value, Error> {
    let e = b64(&private_key.e().to_vec());
    let n = b64(&private_key.n().to_vec());

    Ok(json!({
        "e": e,
        "n": n,
        "kty": "RSA",
    }))
}

/// Constructs a json web signature `JWS` (RFC7515) in the flattened `JSON` form for a specified
/// payload. This involves signing the JWS with the RS256 algorithm.
/// # Example
/// ```rust
/// use acme_rs::util::jws;
/// use serde_json::json;
/// use openssl::Rsa;
///
/// // get the private key, the jws header and the payload
/// let priv_key = Rsa::generate(2048).expect("Error while receiving private key");
/// let header = json!({
///    "alg": "RS256",
///    "nonce": "superRandom",
/// });
///
/// let payload = json!({
///    "termsOfServiceAgreed": true,
///    "email": "foo@bar.de"
/// });
///
/// // calculate the jws
/// let jws = jws(payload, header, &priv_key).expect("Error while creating jws");
///
/// ```
pub fn jws(
    payload: serde_json::Value,
    header: serde_json::Value,
    private_key: &Rsa<Private>,
) -> Result<serde_json::Value, Error> {
    // edge case when the payload needs to be empty, e.g. for
    // fetching the challenges or downloading the certificate
    let empty_payload = payload == json!("");

    let payload64 = b64(serde_json::to_string_pretty(&payload)?.as_bytes());
    let header64 = b64(serde_json::to_string_pretty(&header)?.as_bytes());

    let p_key = PKey::private_key_from_pem(&private_key.private_key_to_pem()?)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &p_key)?;

    signer.set_rsa_padding(Padding::PKCS1)?;
    if empty_payload {
        signer.update(&format!("{}.", header64).as_bytes())?;
    } else {
        signer.update(&format!("{}.{}", header64, payload64).as_bytes())?;
    }

    let signature = b64(&signer.sign_to_vec()?);

    Ok(json!({
        "protected": header64,
        "payload": if empty_payload { "" } else { &payload64 },
        "signature": signature
    }))
}

/// Returns the `base64url` encoding of the input.
pub(crate) fn b64(to_encode: &[u8]) -> String {
    encode_config(to_encode, base64::URL_SAFE_NO_PAD)
}

/// Extracts the payload and `replay-nonce` header field from a given http `Response`.
#[inline]
pub(crate) fn extract_payload_and_nonce<T>(response: Response) -> Result<(Nonce, T), Error>
where
    T: DeserializeOwned,
{
    let replay_nonce = response
        .headers()
        .get("replay-nonce")
        .ok_or(Error::IncorrectResponse)?
        .to_str()?
        .to_owned();

    Ok((replay_nonce, response.json()?))
}

/// Extracts the `location` and `replay-nonce` header field as well as
/// the payload from a given http `Response`.
#[inline]
pub(crate) fn extract_payload_location_and_nonce<T>(
    response: Response,
) -> Result<(String, Nonce, T), Error>
where
    T: DeserializeOwned,
{
    let replay_nonce = response
        .headers()
        .get("replay-nonce")
        .ok_or(Error::IncorrectResponse)?
        .to_str()?
        .to_owned();

    let location = response
        .headers()
        .get("location")
        .ok_or(Error::IncorrectResponse)?
        .to_str()?
        .to_owned();

    Ok((location, replay_nonce, response.json()?))
}

pub fn load_csr_from_file(path: &str) -> Result<X509Req, Error> {
    let bytes = std::fs::read(path)?;

    Ok(X509Req::from_pem(&bytes)?)
}

/// Parses the certificate and writes them into to files:
/// * my_cert.crt -> the certificate issued for the request,
/// * cert_chain.crt -> the certificate chain issued for the request.
pub fn save_certificates(certificate_chain: Certificate) -> Result<(), Error> {
    // extract the first certificat (certificate for the specified domain)
    let cert_me = certificate_chain
        .lines()
        .take_while(|line| !line.is_empty())
        .map(|line| {
            let mut line_with_end = line.to_owned();
            line_with_end.push_str("\r\n");
            line_with_end
        })
        .collect::<String>();

    // save the certs to files
    std::fs::write("my_cert.crt", cert_me.into_bytes())?;
    std::fs::write("cert_chain.crt", certificate_chain.into_bytes())?;

    Ok(())
}

/// Saves an rsa keypair into two files `priv.pem` and `pub.pem`.
pub fn save_keypair(keypair: &(Rsa<Private>, Rsa<Public>)) -> Result<(), Error> {
    let private_key = keypair.0.private_key_to_pem()?;
    let public_key = keypair.1.public_key_to_pem()?;

    std::fs::write("priv.pem", &private_key)?;
    std::fs::write("pub.pem", &public_key)?;

    Ok(())
}

/// Loads a private key and a public key from the given files.
/// The keys need to be safed in the `pem` format.
pub fn load_keys_from_file(
    path_to_private: &str,
    path_to_public: &str,
) -> Result<(Rsa<Private>, Rsa<Public>), Error> {
    let priv_key = std::fs::read(path_to_private)?;
    let pub_key = std::fs::read(path_to_public)?;

    Ok((
        Rsa::private_key_from_pem(&priv_key)?,
        Rsa::public_key_from_pem(&pub_key)?,
    ))
}
