use crate::write_string;
use crate::protocol::types::write_varint;

#[derive(Debug, Clone, PartialEq)]
pub struct DisconnectPacket {
    pub reason: String,
}

impl DisconnectPacket {
    pub fn new(reason: String) -> Self {
        Self {
            reason: reason,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(5 + self.reason.len());

        write_varint(0x19, &mut packet);
        write_string(&self.reason, &mut packet);

        let mut framed = Vec::with_capacity(5 + packet.len());
        write_varint(packet.len() as i32, &mut framed);
        framed.extend_from_slice(&packet);


        framed
    }
}
