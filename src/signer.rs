use jws::Signer;
use serde_json::json;
use openssl::{pkey::Private, rsa::Padding, rsa::Rsa, sha::Sha256};

pub struct RS256Signer {
    key: Rsa<Private>,
}

impl RS256Signer {
    pub fn new(key: Rsa<Private>) -> Self {
        Self {
            key,
        }
    }
}

impl Signer for RS256Signer {
    fn set_header_params(&self, header: &mut jws::JsonObject) {
        header.insert(String::from("alg"), json!("RS256"));
    }

    fn compute_mac(&self, encoded_protected_header: &[u8], encoded_payload: &[u8]) -> jws::Result<Vec<u8>> {
        let p_key = openssl::pkey::PKey::from_rsa(self.key.clone()).unwrap();
        let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &p_key).unwrap();
        let full = [encoded_protected_header, &[b'.'], encoded_payload].concat();
        signer.update(&full).unwrap();
        Ok(signer.sign_to_vec().unwrap())
    }
}
