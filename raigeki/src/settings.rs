use std::env;

use dotenvy::dotenv;
use log::{error, info};

#[derive(Debug)]
pub struct Settings {
    pub auto_mmdb: bool,
    pub haproxy: bool,
    pub mmdb_asn: String,
    pub mmdb_city: String,
    pub l4_ip: String,
    pub l4_port: u16,
    pub outbound_ip: String,
    pub outbound_port: u16,
    pub blocked_asn: Vec<u32>,
    pub blocked_country: Vec<String>,
    pub rate_limit: isize,
    pub connect_rate_limit: isize,
    pub memcached_addrs: Vec<String>,
}

fn parse_env_to_bool(var_name: &str, default: bool) -> bool {
    match env::var(var_name) {
        Ok(value) => match value.to_lowercase().as_str() {
            "1" | "true" | "yes" => true,
            "0" | "false" | "no" => false,
            _ => default,
        },
        Err(_) => default,
    }
}

impl Settings {
    pub fn new() -> Self {
        let _ = dotenv();

        let auto_mmdb = parse_env_to_bool("MMDB_AUTOMODE", true);
        let haproxy = parse_env_to_bool("HAPROXY_HEADERS", false);
        let mmdb_asn = env::var("MMDB_ASN").unwrap_or_else(|_| "/tmp/geolite2-asn.mmdb".to_owned());
        let mmdb_city =
            env::var("MMDB_CITY").unwrap_or_else(|_| "/tmp/geolite2-city.mmdb".to_owned());

        let l4_ip = env::var("L4_IP").unwrap_or_else(|_| {
            info!("L4_IP not set, using default value");
            "0.0.0.0".to_string()
        });

        let l4_port = env::var("L4_PORT")
            .unwrap_or_else(|_| {
                info!("PORT not set, using default value");
                "1337".to_string()
            })
            .parse::<u16>()
            .unwrap_or_else(|_| {
                error!("Invalid PORT value, using default value");
                1337
            });

        let outbound_ip = env::var("OUTBOUND_IP").unwrap_or_else(|_| {
            info!("L4_IP not set, using default value");
            "0.0.0.0".to_string()
        });

        let outbound_port = env::var("OUTBOUND_PORT")
            .unwrap_or_else(|_| {
                info!("PORT not set, using default value");
                "1337".to_string()
            })
            .parse::<u16>()
            .unwrap_or_else(|_| {
                error!("Invalid PORT value, using default value");
                1337
            });

        let blocked_asn: Vec<u32> = env::var("BLOCKED_ASN")
            .unwrap_or_else(|_| {
                info!("BLOCKED_ASN not set, using empty list");
                String::new()
            })
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse::<u32>().unwrap_or_else(|_| {
                    error!("Invalid ASN id, using 0");
                    0
                })
            })
            .collect();

        let blocked_country = env::var("BLOCKED_COUNTRY")
            .unwrap_or_else(|_| {
                info!("BLOCKED_COUNTRY not set, using empty list");
                String::new()
            })
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let rate_limit = env::var("RATE_LIMIT")
            .unwrap_or_else(|_| {
                info!("RATE_LIMIT not set, using default value");
                "50".to_string()
            })
            .parse::<isize>()
            .unwrap_or_else(|_| {
                error!("Invalid RATE_LIMIT value, using default value");
                50
            });

        let connect_rate_limit = env::var("CONNECT_RATE_LIMIT")
            .unwrap_or_else(|_| {
                info!("CONNECT_RATE_LIMIT not set, using default value");
                "15".to_string()
            })
            .parse::<isize>()
            .unwrap_or_else(|_| {
                error!("Invalid CONNECT_RATE_LIMIT value, using default value");
                15
            });

        let memcached_addrs = env::var("MEMCACHED_ADDRS")
            .unwrap_or_else(|_| {
                info!("MEMCACHED_ADDRS not set, using default value");
                "0.0.0.0".to_string()
            })
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Settings {
            auto_mmdb,
            haproxy,
            mmdb_asn,
            mmdb_city,
            l4_ip,
            l4_port,
            outbound_ip,
            outbound_port,
            blocked_asn,
            blocked_country,
            rate_limit,
            connect_rate_limit,
            memcached_addrs,
        }
    }
}
