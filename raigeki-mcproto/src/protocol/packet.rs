use bytes::Bytes;

use crate::PacketError;


pub trait Packet: Sized {
    const PACKET_ID: i32;
    
    fn serialize(&self) -> Result<Bytes, PacketError>;
}