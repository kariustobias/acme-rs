use base64::encode_config;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::{Padding, Rsa},
    sign::Signer,
};
use reqwest::blocking::Response;
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::{
    error::Error,
    types::{Certificate, Nonce},
    KEY_WIDTH,
};

pub fn generate_rsa_key() -> Result<Rsa<Private>, Error> {
    Ok(Rsa::generate(KEY_WIDTH)?)
}

pub fn generate_rsa_keypair() -> Result<(Rsa<Private>, Rsa<Public>), Error> {
    let rsa_key = generate_rsa_key()?;
    Ok((
        Rsa::private_key_from_pem(&rsa_key.private_key_to_pem()?)?,
        Rsa::public_key_from_pem(&rsa_key.public_key_to_pem()?)?,
    ))
}

pub fn jwk(private_key: &Rsa<Private>) -> Result<serde_json::Value, Error> {
    let e = b64(&private_key.e().to_vec());
    let n = b64(&private_key.n().to_vec());

    Ok(json!({
        "e": e,
        "n": n,
        "kty": "RSA",
    }))
}

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

pub fn b64(to_encode: &[u8]) -> String {
    encode_config(to_encode, base64::URL_SAFE_NO_PAD)
}

#[inline]
pub fn extract_payload_and_nonce<T>(response: Response) -> Result<(Nonce, T), Error>
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

#[inline]
pub fn extract_payload_location_and_nonce<T>(
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

pub fn save_keypair(keypair: &(Rsa<Private>, Rsa<Public>)) -> Result<(), Error> {
    let private_key = keypair.0.private_key_to_pem()?;
    let public_key = keypair.1.public_key_to_pem()?;

    std::fs::write("my_key", &private_key)?;
    std::fs::write("my_key.pub", &public_key)?;

    Ok(())
}

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
