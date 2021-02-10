use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Directory {
    //Page 23
    #[serde(rename = "newNonce")]
    pub new_nonce: String,
    #[serde(rename = "newAccount")]
    pub new_account: String,
    #[serde(rename="newOrder")]
    pub new_order: String,
    #[serde(rename="revokeCert")]
    pub revoke_cert: String,
    #[serde(rename="keyChange")]
    pub key_change: String,
    pub meta: Vec<serde_json::Value>,
    //optional termsOfService : URL
    //optional website : URL
    //optional caaIdentities : [URL]
    //optional externalAccountRequired: false
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountManagment{
    //Page 34
    contact: Option<Vec<String>>,
    terms_of_service_agreed: Option<bool>,
    only_return_existing: Option<bool>,
    external_account_binding: Option<serde_json::Value>,
    payload: (bool, serde_json::Value),
    protected: serde_json::Value,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    //Page 24
    status: String,
    contact: Option<Vec<String>>,
    terms_of_service_agreed: Option<bool>,
    external_account_binding: serde_json::Value, // Including this field in a
    //newAccount request indicates approval by the holder of an existing
    //non-ACME account to bind that account to this ACME account.  This
    //field is not updateable by the client (see Section 7.3.4).
    orders: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewOrder {
    //Page 44
    identifiers: serde_json::Value,
    not_after: Option<String>,
    not_before: Option<String>,
    payload: serde_json::Value,
    protected: serde_json::Value,
    signature: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Order {
    //Page 26
    status: String,
    expires: String,
    identifiers: serde_json::Value,
    not_before: Option<String>,
    not_after: Option<String>,
    error: Option<serde_json::Value>,
    authorisations: Vec<String>,
    finalize: String,
    certificate: Option<String>,

}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendAuthorisation {
    //Page 49
    identifiers: serde_json::Value,
    payload: Option<String>,
    protected: serde_json::Value,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Authorization {
    //Page 28
    // type, value
    identifier: serde_json::Value,
    status: String,
    expires: Option<String>,
    challenges: serde_json::Value,
    wildcard: Option<bool>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Challange{
    //Page 60
    url:String,
    status:String,
    validated:Option<String>,
    error:Option<serde_json::Value>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RespondingToChallange {
    //Page 54
    payload: serde_json::Value,
    protected: serde_json::Value,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UdatedOrderObject {
    status: String,
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
