use std::io;
use thiserror::Error;

use openssl::error::ErrorStack;
use reqwest::header::ToStrError;

/// An enumeration of all possible errors.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Error {
    #[error("The request specified an account that does not exist")]
    AccountDoesNotExist,
    #[error("The request specified a certificate to be revoked that has already been revoked")]
    AlreadyRevokedCertificate,
    #[error("The CSR is unacceptable (e.g., due to a short key)")]
    BadCSR,
    #[error("The client sent an unacceptable anti-replay nonce")]
    BadNonce,
    #[error("The JWS was signed by a public key the server does not support")]
    BadPublicKey,
    #[error("The revocation reason provided is not allowed by the server")]
    BadRevocationReason,
    #[error("The JWS was signed with an algorithm the server does not support")]
    BadSignatureAlgorithm,
    #[error("Certification Authority Authorization (CAA) records forbid the CA from issuing a certificate")]
    CaaError,
    #[error("Specific error conditions are indicated in the \"subproblems\" array")]
    Compound,
    #[error("The server could not connect to validation target")]
    Connection,
    #[error("There was a problem with a DNS query during identifier validation")]
    DnsError,
    #[error("The request must include a value for the \"externalAccountBinding\" field")]
    ExternalAccountRequired,
    #[error("Response received didn't match the challenge's requirements")]
    IncorrectResponse,
    #[error("A contact URL for an account was invalid")]
    InvalidContact,
    #[error("The request message was malformed")]
    MalformedRequest,
    #[error("The request attempted to finalize an order that is not ready to be finalized")]
    OrderNotReady,
    #[error("The request exceeds a rate limit")]
    RateLimited,
    #[error("The server will not issue certificates for the identifier")]
    RejectedIdentifier,
    #[error("The server experienced an internal error")]
    InternalServerError,
    #[error("The server received a TLS error during validation")]
    TlsError,
    #[error("The client lacks sufficient authorization")]
    Unauthorized,
    #[error("A contact URL for an account used an unsupported protocol scheme")]
    UnsupportedContact,
    #[error("An identifier is of an unsupported type")]
    UnsupportedIdentifier,
    #[error("Visit the \"instance\" URL and take actions specified there")]
    UserActionRequired,
    #[error("Error reading the string: {0}")]
    FromUtf8Error(#[from] std::str::Utf8Error),
    #[error("Error in reqwest: {0}")]
    FromReqwestError(#[from] reqwest::Error),
    #[error("Error in openssl: {0}")]
    FromRsaError(#[from] ErrorStack),
    #[error("Error while de/encoding json: {0}")]
    FromSerdeError(#[from] serde_json::Error),
    #[error("Error writing header value: {0}")]
    FromToStrError(#[from] ToStrError),
    #[error("IO error {0}")]
    FromIoError(#[from] io::Error),
    #[error("Currently just http challenges are allowed, so this error is raised if no http challenge is present")]
    NoHttpChallengePresent,
    #[error("There was no web server found")]
    NoWebServer,
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
