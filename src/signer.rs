use jws::Signer;
use serde_json::json;
use openssl::sha::Sha256;

pub struct RS256Signer<Key: AsRef<[u8]>> {
    key: Key
}

impl<Key: AsRef<[u8]>> RS256Signer<Key> {
    pub fn new(key: Key) -> Self {
        Self {
            key: key,
        }
    }
}

impl<Key: AsRef<[u8]>> Signer for RS256Signer<Key> {
    fn set_header_params(&self, header: &mut jws::JsonObject) {
        header.insert(String::from("alg"), json!("RS256"));
    }

    fn compute_mac(&self, encoded_protected_header: &[u8], encoded_payload: &[u8]) -> jws::Result<Vec<u8>> {
        let mut sign = Sha256::new();

        sign.update(encoded_protected_header);
        sign.update(&[b'.']);
        sign.update(encoded_payload);
        Ok(sign.finish().to_vec())
    }
}
