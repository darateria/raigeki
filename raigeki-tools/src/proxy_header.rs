use std::net::IpAddr;

use raigeki_error::Error;

pub struct HAProxyInfo {
    pub src_addr: IpAddr,
    pub src_port: u16,
}

pub fn parse_haproxy_header(data: &[u8]) -> Result<HAProxyInfo, Error> {
    let header_str = std::str::from_utf8(data).map_err(|_| Error::InvalidHAProxyHeader)?;
    
    let parts: Vec<&str> = header_str.split_whitespace().collect();
    if parts.len() < 6 {
        return Err(Error::InvalidHAProxyHeader);
    }
    
    if parts[0] != "PROXY" {
        return Err(Error::InvalidHAProxyHeader);
    }
    
    let src_addr = parts[2].parse().map_err(|_| Error::InvalidHAProxyHeader)?;
    let src_port = parts[4].parse().map_err(|_| Error::InvalidHAProxyHeader)?;
    
    Ok(HAProxyInfo {
        src_addr,
        src_port,
    })
}

pub fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}