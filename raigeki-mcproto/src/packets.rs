use anyhow::Result;

use crate::packet::{Packet, PacketBuilder, PacketDirection, ProtocolState};

pub fn build_disconnect_packet(reason: &str) -> Result<Packet> {
    let mut builder = PacketBuilder::new(
        0x1A,
        ProtocolState::Play,
        PacketDirection::Clientbound,
    );
    
    builder.write_chat(reason)?;
    
    Ok(builder.build())
}