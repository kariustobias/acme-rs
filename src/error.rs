use openssl::error::ErrorStack;

#[derive(Debug)]
pub enum Error {
    FromReqwestError(reqwest::Error),
    FromUrlParseError(url::ParseError),
    FromRsaError(ErrorStack),
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Error::FromReqwestError(error)
    }
}

impl From<url::ParseError> for Error {
    fn from(error: url::ParseError) -> Self {
        Error::FromUrlParseError(error)
    }
}

impl From<ErrorStack> for Error {
    fn from(error: ErrorStack) -> Self {
        Error::FromRsaError(error)
    }
}
