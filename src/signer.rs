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
        let mut sign = Sha256::new();

        sign.update(encoded_protected_header);
        sign.update(&[b'.']);
        sign.update(encoded_payload);

        let sha_val = sign.finish().to_vec();

        let mut result: Vec<u8> = vec![0; self.key.size() as usize];
        let _ = self.key.private_encrypt(&sha_val, &mut result, Padding::PKCS1).unwrap();

        Ok(result)
    }
}
