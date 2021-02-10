use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum StatusType {
    Valid,
    Pending,
    Invalid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetDirectory {
    #[serde(rename = "newNonce")]
    pub new_nonce: String,
    #[serde(rename = "newAccount")]
    pub new_account: String,
    #[serde(rename = "newOrder")]
    pub new_order: String,
    #[serde(rename = "revokeCert")]
    pub revoke_cert: String,
    #[serde(rename = "keyChange")]
    pub key_change: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterAccount {
    // Terms_of_Service_agreed:bool, contact:String
    pub payload: (bool, serde_json::Value),
    pub protected: serde_json::Value,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountCreated {
    pub contact: serde_json::Value,
    pub status: StatusType,
    pub orders: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct NewOrder {
    payload: serde_json::Value,
    protected: serde_json::Value,
    signature: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreatedNewOrder {
    status: StatusType,
    expires: String,
    identifiers: serde_json::Value,
    not_before: String,
    authorisations: serde_json::Value,
    finalize: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Authorisation {
    payload: Option<String>,
    protected: serde_json::Value,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChallengeAuthorisation {
    // type, value
    identifier: serde_json::Value,
    status: StatusType,
    expires: String,
    challenges: serde_json::Value,
    wildcard: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct FinalizeOrder {
    payload: serde_json::Value,
    protected: serde_json::Value,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UdatedOrderObject {
    status: StatusType,
    expires: String,
    identifiers: serde_json::Value,
    not_before: String,
    not_after: String,
    authorisations: serde_json::Value,
    finalize: String,
    certificate: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GetCertificate {
    payload: Option<String>,
    protected: serde_json::Value,
    signature: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct Certificate {}

#[derive(Debug, Serialize, Deserialize)]
struct Conformation {
    certificate: Certificate,
}
