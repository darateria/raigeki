use bytes::{BufMut, Bytes, BytesMut};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum PacketError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid packet data")]
    InvalidData,
}

pub type Result<T> = std::result::Result<T, PacketError>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProtocolState {
    Handshake,
    Status,
    Login,
    Play,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    pub packet_id: i32,
    pub state: ProtocolState,
    pub bound_to: PacketDirection,
    pub data: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketDirection {
    Clientbound,
    Serverbound,
}

pub struct PacketBuilder {
    packet_id: i32,
    state: ProtocolState,
    bound_to: PacketDirection,
    data: BytesMut,
}

#[allow(dead_code)]
impl PacketBuilder {
    pub fn new(packet_id: i32, state: ProtocolState, bound_to: PacketDirection) -> Self {
        Self {
            packet_id,
            state,
            bound_to,
            data: BytesMut::new(),
        }
    }

    pub fn build(self) -> Packet {
        Packet {
            packet_id: self.packet_id,
            state: self.state,
            bound_to: self.bound_to,
            data: self.data.freeze(),
        }
    }

    pub fn write_bool(&mut self, value: bool) -> &mut Self {
        self.data.put_u8(if value { 0x01 } else { 0x00 });
        self
    }

    pub fn write_byte(&mut self, value: i8) -> &mut Self {
        self.data.put_i8(value);
        self
    }

    pub fn write_ubyte(&mut self, value: u8) -> &mut Self {
        self.data.put_u8(value);
        self
    }

    pub fn write_short(&mut self, value: i16) -> &mut Self {
        self.data.put_i16(value);
        self
    }

    pub fn write_ushort(&mut self, value: u16) -> &mut Self {
        self.data.put_u16(value);
        self
    }

    pub fn write_int(&mut self, value: i32) -> &mut Self {
        self.data.put_i32(value);
        self
    }

    pub fn write_long(&mut self, value: i64) -> &mut Self {
        self.data.put_i64(value);
        self
    }

    pub fn write_float(&mut self, value: f32) -> &mut Self {
        self.data.put_f32(value);
        self
    }

    pub fn write_double(&mut self, value: f64) -> &mut Self {
        self.data.put_f64(value);
        self
    }

    pub fn write_varint(&mut self, mut value: i32) -> &mut Self {
        loop {
            if (value & !0x7F) == 0 {
                self.data.put_u8(value as u8);
                break;
            }
            self.data.put_u8((value as u8 & 0x7F) | 0x80);
            value >>= 7;
        }
        self
    }

    pub fn write_varlong(&mut self, mut value: i64) -> &mut Self {
        loop {
            if (value & !0x7F) == 0 {
                self.data.put_u8(value as u8);
                break;
            }
            self.data.put_u8((value as u8 & 0x7F) | 0x80);
            value >>= 7;
        }
        self
    }

    pub fn write_string(&mut self, value: &str) -> Result<&mut Self> {
        self.write_varint(value.len() as i32);
        self.data.put_slice(value.as_bytes());
        Ok(self)
    }

    pub fn write_chat(&mut self, text: &str) -> Result<&mut Self> {
        let chat_json = serde_json::json!({
            "text": text
        });
        self.write_string(&chat_json.to_string())
    }

    pub fn write_uuid(&mut self, uuid: Uuid) -> &mut Self {
        self.data.put_slice(uuid.as_bytes());
        self
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.data.put_slice(bytes);
        self
    }
}

impl Packet {
    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::new();
        
        let data_len = self.data.len() + varint_length(self.packet_id);
        write_varint(&mut buf, data_len as i32);
        write_varint(&mut buf, self.packet_id);
        buf.put_slice(&self.data);
        
        buf.freeze()
    }

    pub fn reader(&self) -> PacketReader {
        PacketReader {
            data: self.data.clone(),
            position: 0,
        }
    }
}

pub struct PacketReader {
    data: Bytes,
    position: usize,
}

impl PacketReader {
    pub fn read_bool(&mut self) -> Result<bool> {
        Ok(self.read_ubyte()? != 0)
    }

    pub fn read_byte(&mut self) -> Result<i8> {
        if self.position >= self.data.len() {
            return Err(PacketError::InvalidData);
        }
        let value = self.data[self.position];
        self.position += 1;
        Ok(value as i8)
    }

    pub fn read_ubyte(&mut self) -> Result<u8> {
        if self.position >= self.data.len() {
            return Err(PacketError::InvalidData);
        }
        let value = self.data[self.position];
        self.position += 1;
        Ok(value)
    }

    pub fn read_short(&mut self) -> Result<i16> {
        if self.position + 1 >= self.data.len() {
            return Err(PacketError::InvalidData);
        }
        let value = i16::from_be_bytes([
            self.data[self.position],
            self.data[self.position + 1],
        ]);
        self.position += 2;
        Ok(value)
    }

    pub fn read_ushort(&mut self) -> Result<u16> {
        if self.position + 1 >= self.data.len() {
            return Err(PacketError::InvalidData);
        }
        let value = u16::from_be_bytes([
            self.data[self.position],
            self.data[self.position + 1],
        ]);
        self.position += 2;
        Ok(value)
    }

    pub fn read_int(&mut self) -> Result<i32> {
        if self.position + 3 >= self.data.len() {
            return Err(PacketError::InvalidData);
        }
        let value = i32::from_be_bytes([
            self.data[self.position],
            self.data[self.position + 1],
            self.data[self.position + 2],
            self.data[self.position + 3],
        ]);
        self.position += 4;
        Ok(value)
    }

    pub fn read_long(&mut self) -> Result<i64> {
        if self.position + 7 >= self.data.len() {
            return Err(PacketError::InvalidData);
        }
        let value = i64::from_be_bytes([
            self.data[self.position],
            self.data[self.position + 1],
            self.data[self.position + 2],
            self.data[self.position + 3],
            self.data[self.position + 4],
            self.data[self.position + 5],
            self.data[self.position + 6],
            self.data[self.position + 7],
        ]);
        self.position += 8;
        Ok(value)
    }

    pub fn read_float(&mut self) -> Result<f32> {
        if self.position + 3 >= self.data.len() {
            return Err(PacketError::InvalidData);
        }
        let value = f32::from_be_bytes([
            self.data[self.position],
            self.data[self.position + 1],
            self.data[self.position + 2],
            self.data[self.position + 3],
        ]);
        self.position += 4;
        Ok(value)
    }

    pub fn read_double(&mut self) -> Result<f64> {
        if self.position + 7 >= self.data.len() {
            return Err(PacketError::InvalidData);
        }
        let value = f64::from_be_bytes([
            self.data[self.position],
            self.data[self.position + 1],
            self.data[self.position + 2],
            self.data[self.position + 3],
            self.data[self.position + 4],
            self.data[self.position + 5],
            self.data[self.position + 6],
            self.data[self.position + 7],
        ]);
        self.position += 8;
        Ok(value)
    }

    pub fn read_varint(&mut self) -> Result<i32> {
        let mut value = 0;
        let mut position = 0;
        
        loop {
            if self.position >= self.data.len() {
                return Err(PacketError::InvalidData);
            }
            
            let current_byte = self.data[self.position];
            self.position += 1;
            
            value |= ((current_byte & 0x7F) as i32) << position;
            
            if (current_byte & 0x80) == 0 {
                break;
            }
            
            position += 7;
            if position >= 32 {
                return Err(PacketError::InvalidData);
            }
        }
        
        Ok(value)
    }

    pub fn read_string(&mut self) -> Result<String> {
        let length = self.read_varint()? as usize;
        if self.position + length > self.data.len() {
            return Err(PacketError::InvalidData);
        }
        
        let string_data = &self.data[self.position..self.position + length];
        self.position += length;
        
        String::from_utf8(string_data.to_vec()).map_err(Into::into)
    }

    pub fn read_chat(&mut self) -> Result<String> {
        let json_str = self.read_string()?;
        let value: Value = serde_json::from_str(&json_str)?;
        
        if let Some(text) = value.get("text") {
            if let Some(text_str) = text.as_str() {
                return Ok(text_str.to_string());
            }
        }
        
        Ok(json_str) // Fallback to raw JSON
    }

    pub fn read_uuid(&mut self) -> Result<Uuid> {
        if self.position + 15 >= self.data.len() {
            return Err(PacketError::InvalidData);
        }
        
        let bytes = &self.data[self.position..self.position + 16];
        self.position += 16;
        
        Uuid::from_slice(bytes).map_err(|_| PacketError::InvalidData)
    }

    pub fn read_bytes(&mut self, length: usize) -> Result<Bytes> {
        if self.position + length > self.data.len() {
            return Err(PacketError::InvalidData);
        }
        
        let bytes = self.data.slice(self.position..self.position + length);
        self.position += length;
        
        Ok(bytes)
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.position
    }
}

// Helper functions
fn write_varint(buf: &mut BytesMut, mut value: i32) {
    loop {
        if (value & !0x7F) == 0 {
            buf.put_u8(value as u8);
            break;
        }
        buf.put_u8((value as u8 & 0x7F) | 0x80);
        value >>= 7;
    }
}

fn varint_length(mut value: i32) -> usize {
    let mut length = 0;
    loop {
        length += 1;
        if (value & !0x7F) == 0 {
            break;
        }
        value >>= 7;
    }
    length
}