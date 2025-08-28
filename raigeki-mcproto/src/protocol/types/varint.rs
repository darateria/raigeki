use std::io::Read;

use crate::PacketError;

pub fn read_varint<R: Read>(reader: &mut R) -> Result<i32, PacketError> {
    let mut result = 0;
    let mut shift = 0;
    let mut byte = [0u8; 1];

    loop {
        reader.read_exact(&mut byte)?;
        let value = byte[0] as i32;
        result |= (value & 0x7F) << shift;
        shift += 7;

        if (value & 0x80) == 0 {
            break;
        }

        if shift >= 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "VarInt too large",
            ).into());
        }
    }

    Ok(result)
}

pub fn write_varint(mut value: i32, out: &mut Vec<u8>) {
    loop {
        if (value & !0x7F) == 0 {
            out.push(value as u8);
            break;
        } else {
            out.push(((value & 0x7F) | 0x80) as u8);
            value = ((value as u32) >> 7) as i32;
        }
    }
}

pub fn varint_length(mut value: i32) -> usize {
    let mut length = 0;
    loop {
        length += 1;
        value = (value as u32 >> 7) as i32;
        if value == 0 {
            break;
        }
    }
    length
}