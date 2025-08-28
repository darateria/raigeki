pub mod play;
pub mod login;

pub trait PacketDirection {
    fn direction() -> PacketDirectionType;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirectionType {
    Clientbound,
    Serverbound,
}