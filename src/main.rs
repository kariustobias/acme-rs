mod error;
mod serialized_structs;

use base64::encode_config;
use error::Error;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::x509;
use openssl::{
    hash::MessageDigest,
    pkey::Private,
    rsa::{Padding, Rsa},
};
use openssl::{nid::Nid, sha::Sha256};
use reqwest::blocking::Client;
use reqwest::Url;
use rpki::cert;
use serde_json::json;
use serialized_structs::{Challenge, GetDirectory};
use x509::{X509NameBuilder, X509Req, X509ReqBuilder};

const IDENTIFIER: &str = "mb.cmbt.de";
const SERVER: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const KEY_WIDTH: u32 = 2048;

fn main() {
    let client = Client::new();
    let p_key = generate_rsa_keypair().unwrap();

    let get_dir = get_directory(&client).unwrap();
    let new_nonce = send_get_new_nonce(&client, get_dir.new_nonce).unwrap();

    let new_acc = get_new_account(&client, new_nonce, get_dir.new_account, p_key.clone()).unwrap();
    println!("{:?}", new_acc.2);
    let kid = dbg!(new_acc.0.clone());
    let new_nonce = new_acc.clone().1;

    let order = get_new_order(&client, new_nonce, get_dir.new_order, p_key.clone(), kid).unwrap();
    println!("{:#?}", &order.1);
    let new_nonce = order.0;
    let mut auth_url = order
        .1
        .get("authorizations")
        .unwrap()
        .as_array()
        .unwrap()
        .get(0)
        .unwrap()
        .to_string();

    auth_url.pop();
    auth_url.remove(0);

    let chall = get_authorisation(
        &client,
        new_nonce,
        dbg!(auth_url),
        new_acc.clone().0,
        p_key.clone(),
    )
    .unwrap();
    println!("{:#?}", chall.1);
    let new_nonce = chall.0;

    let http_challenge = dbg!(chall
        .1
        .challenges
        .into_iter()
        .find(|challenge| challenge.challenge_type == "http-01")
        .unwrap());
    let new_nonce = complete_http_challenge(
        &client,
        http_challenge,
        new_nonce.clone(),
        new_acc.0.split("/").last().unwrap().to_owned(),
        new_acc.clone().0,
        p_key.clone(),
    )
    .unwrap();

    let mut finalize_url = order.1.get("finalize").unwrap().to_string();
    finalize_url.pop();
    finalize_url.remove(0);

    let finalized_cert = finalize_order(&client, new_nonce, finalize_url, p_key.clone(), new_acc.clone().0).unwrap();
    println!(
        "{:?}",
        finalized_cert.1,
    );
    let new_nonce = finalized_cert.0;
    let mut cert_url = finalized_cert.1.get("certificate").unwrap().to_string();
    cert_url.pop();
    cert_url.remove(0);

    let certificate = download_certificate(&client, new_nonce, cert_url, new_acc.0, p_key).unwrap();
    println!(
        "{}", 
        &certificate
    );

    let cert_me = certificate.lines().take_while(|line| !line.is_empty()).map(|line| {
        let mut line_with_end = line.to_owned();
        line_with_end.push_str("\r\n");
        line_with_end
    }).collect::<String>();

    std::fs::write("me.cert", cert_me.into_bytes()).unwrap();
    std::fs::write("other.cert", certificate.into_bytes()).unwrap();
}

fn get_directory(client: &Client) -> Result<GetDirectory, Error> {
    let url = Url::parse(SERVER)?;
    Ok(client.get(url).send()?.json()?)
}

fn send_get_new_nonce(client: &Client, new_nonce_url: String) -> Result<String, Error> {
    let url = Url::parse(&new_nonce_url)?;
    Ok(std::str::from_utf8(
        client
            .head(url)
            .send()?
            .headers()
            .get("replay-nonce")
            .ok_or(Error::BadNonce)?
            .as_bytes(),
    )?
    .to_owned())
}

fn get_new_account(
    client: &Client,
    nonce: String,
    url: String,
    p_key: Rsa<Private>,
) -> Result<(String, String, String), Error> {
    let jwk = jwk(p_key.clone())?;

    let header = json!({
        "alg": "RS256",
        "url": url,
        "jwk": jwk,
        "nonce": nonce,
    });

    let payload = json!({
        "termsOfServiceAgreed": true,
        "contact": ["mailto:bastian@cmbt.de"]
    });

    let payload = jws(payload, header, p_key, false)?;

    let response = dbg!(client
        .post(&url)
        .header("Content-Type", "application/jose+json")
        .body(serde_json::to_string_pretty(&payload)?)
        .send())?;

    Ok((
        response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        response
            .headers()
            .get("replay-nonce")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        response.text()?,
    ))
}

fn get_new_order(
    client: &Client,
    nonce: String,
    url: String,
    p_key: Rsa<Private>,
    kid: String,
) -> Result<(String, serde_json::Value), Error> {
    let header = json!({
        "alg": "RS256",
        "url": url,
        "kid": kid,
        "nonce": nonce,
    });

    let payload = json!({
        "identifiers": [
            { "type": "dns", "value": IDENTIFIER }
        ],
    });

    let payload = jws(payload, header, p_key, false)?;

    let response = dbg!(client
        .post(&url)
        .header("Content-Type", "application/jose+json")
        .body(serde_json::to_string_pretty(&payload)?)
        .send())?;

    Ok((
        response
            .headers()
            .get("replay-nonce")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        response.json()?,
    ))
}

fn get_authorisation(
    client: &Client,
    nonce: String,
    url: String,
    acct_url: String,
    private_key: Rsa<Private>,
) -> Result<(String, serialized_structs::ChallengeAuthorisation), Error> {
    let header = json!({
        "alg": "RS256",
        "url": url,
        "kid": acct_url,
        "nonce": dbg!(nonce),
    });
    let payload = json!("");

    let jws = dbg!(jws(payload, header, private_key, true)?);

    let response = dbg!(client
        .post(&url)
        .header("Content-Type", "application/jose+json")
        .body(serde_json::to_string_pretty(&jws)?)
        .send())?;
    Ok((
        response
            .headers()
            .get("replay-nonce")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        response.json()?,
    ))
}

fn complete_http_challenge(
    client: &Client,
    challenge_infos: Challenge,
    nonce: String,
    account_key: String,
    acc_url: String,
    private_key: Rsa<Private>,
) -> Result<String, Error> {
    let thumbprint = jwk(private_key.clone())?;
    let mut hasher = Sha256::new();
    hasher.update(&thumbprint.to_string().into_bytes());
    let thumbprint = hasher.finish();

    let challenge_content = format!("{}.{}", challenge_infos.token, b64(&thumbprint));

    let result = kick_off_http_chall(
        client,
        challenge_infos.clone(),
        nonce,
        acc_url,
        private_key.clone(),
    )
    .unwrap();
    std::thread::spawn(|| {
        rouille::start_server("0.0.0.0:80", move |request| {
            if request.raw_url() == format!("/.well-known/acme-challenge/{}", challenge_infos.token)
            {
                println!("Got Request!");
                rouille::Response::text(challenge_content.clone())
            } else {
                rouille::Response::empty_404()
            }
        });
    });
    std::thread::sleep(std::time::Duration::from_secs(5));
    Ok(result)
}

fn kick_off_http_chall(
    client: &Client,
    challenge_infos: Challenge,
    nonce: String,
    acc_url: String,
    private_key: Rsa<Private>,
) -> Result<String, Error> {
    let header = json!({
        "alg": "RS256",
        "kid": acc_url,
        "nonce": nonce,
        "url": challenge_infos.url
    });

    let payload = json!({});

    let jws = jws(payload, header, private_key, false)?;

    Ok(dbg!(client
        .post(&challenge_infos.url)
        .header("Content-Type", "application/jose+json")
        .body(serde_json::to_string_pretty(&jws)?)
        .send())?
    .headers()
    .get("replay-nonce")
    .unwrap()
    .to_str()
    .unwrap()
    .to_owned())
}

fn generate_rsa_keypair() -> Result<Rsa<Private>, Error> {
    Ok(Rsa::generate(KEY_WIDTH)?)
}

fn jwk(private_key: Rsa<Private>) -> Result<serde_json::Value, Error> {
    let e = b64(&private_key.e().to_vec());
    let n = b64(&private_key.n().to_vec());

    Ok(json!({
        "e": e,
        "n": n,
        "kty": "RSA",
    }))
}

fn jws(
    payload: serde_json::Value,
    header: serde_json::Value,
    private_key: Rsa<Private>,
    empty_payload: bool,
) -> Result<serde_json::Value, Error> {
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

    if !empty_payload {
        Ok(json!({
            "protected": header64,
            "payload": payload64,
            "signature": signature
        }))
    } else {
        Ok(json!({
            "protected": header64,
            "payload": "",
            "signature": signature
        }))
    }
}

fn b64(to_encode: &[u8]) -> String {
    encode_config(to_encode, base64::URL_SAFE_NO_PAD)
}

fn finalize_order(
    client: &Client,
    nonce: String,
    url: String,
    private_key: Rsa<Private>,
    kid: String,
) -> Result<(String, serde_json::Value), Error> {
    let header = json!({
    "alg": "RS256",
    "url": url,
    "kid": kid,
    "nonce": nonce,
    });

    let csr_key = generate_rsa_keypair()?;
    let csr = request_csr(csr_key.clone(), IDENTIFIER.to_owned());
    let csr_string = b64(&csr.to_der().unwrap());

    println!("{}", csr_string);

    let payload = json!({ "csr": csr_string });

    let jws = jws(payload, header, private_key, false).unwrap();

    let response = dbg!(client
        .post(&url)
        .header("Content-Type", "application/jose+json")
        .header("Accept", "application/pem-certificate-chain")
        .body(serde_json::to_string_pretty(&jws)?)
        .send())?;
    Ok((
        response
            .headers()
            .get("replay-nonce")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        response.json()?,
    ))
}

fn download_certificate(client: &Client, nonce: String, cert_url: String, acct_url: String, private_key: Rsa<Private>) -> Result<String, Error> {
    let header = json!({
        "alg": "RS256",
        "url": cert_url,
        "kid": acct_url,
        "nonce": dbg!(nonce),
    });
    let payload = json!("");

    let jws = dbg!(jws(payload, header, private_key, true)?);

    Ok(dbg!(client
        .post(&cert_url)
        .header("Content-Type", "application/jose+json")
        .body(serde_json::to_string_pretty(&jws)?)
        .send())?
    .text()?)
}

fn request_csr(private_key: Rsa<Private>, common_name: String) -> X509Req {
    let mut request = X509ReqBuilder::new().unwrap();
    let mut c_name = X509NameBuilder::new().unwrap();

    let pri_key =
        &openssl::pkey::PKey::private_key_from_pem(&private_key.private_key_to_pem().unwrap())
            .unwrap();
    let public_key =
        &openssl::pkey::PKey::public_key_from_pem(&private_key.public_key_to_pem().unwrap())
            .unwrap();

    c_name
        .append_entry_by_nid(Nid::COMMONNAME, &common_name)
        .unwrap();
    let name = c_name.build();
    request.set_pubkey(public_key).unwrap();
    request.set_subject_name(name.as_ref()).unwrap();
    request.sign(pri_key, MessageDigest::sha256()).unwrap();

    request.build()
}
