pub mod protocol;
pub use protocol::*;

#[derive(thiserror::Error, Debug)]
pub enum PacketError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("Invalid packet ID: {0}")]
    InvalidPacketId(i32),
    
    #[error("Packet too large: {0} bytes")]
    PacketTooLarge(usize),
}

pub type Result<T> = std::result::Result<T, PacketError>;