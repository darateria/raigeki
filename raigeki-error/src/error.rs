use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO: {0}")]
    IOError(#[from] std::io::Error),
    #[error("maxminddb error: {0}")]
    MaxminddbError(#[from] maxminddb::MaxMindDBError),
    #[error("maxminddb: country by ip not found")]
    MaxminddbCountryNotFoundError,
    #[error("make http request: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("got unexpected status code: {0}")]
    ReqwestUnexpectedStatusCodeError(reqwest::StatusCode),
}

impl serde::Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}
