use super::varint::write_varint;

pub fn write_string(s: &str, out: &mut Vec<u8>) {
    write_varint(s.len() as i32, out);
    out.extend_from_slice(s.as_bytes());
}