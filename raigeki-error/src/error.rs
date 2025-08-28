use std::net::IpAddr;

use thiserror::Error;
use memcache::MemcacheError; // Make sure to import the MemcacheError type

#[derive(Error, Debug)]
pub enum Error {
    #[error("Internal error: {0}")]
    InternalError(String),
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
    #[error("memcached: {0}")]
    MemcachedError(MemcacheError),
    #[error("invalid connection")]
    InvalidConnection,
    #[error("IP address is blocked ip={0}")]
    IpBlockedInCache(IpAddr),
    #[error("ASN is blocked ip={0}")]
    AsnBlocked(IpAddr),
    #[error("Country is blocked ip={0}")]
    CountryBlocked(IpAddr),
}

impl serde::Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}

impl From<memcache::MemcacheError> for Error {
    fn from(err: memcache::MemcacheError) -> Self {
        Error::MemcachedError(err)
    }
}