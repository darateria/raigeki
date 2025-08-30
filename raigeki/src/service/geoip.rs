use std::{
    net::IpAddr,
    sync::{Arc, RwLock},
    thread,
    time::Duration,
};

use log::info;
use maxminddb::{geoip2, Reader};
use raigeki_error::Error;
use raigeki_tools::download::download;

pub struct GeoIPService {
    ddb_asn: Arc<RwLock<Reader<Vec<u8>>>>,
    ddb_city: Arc<RwLock<Reader<Vec<u8>>>>,
    asn_blacklist: Vec<u32>,
    country_blacklist: Vec<String>,
}

impl GeoIPService {
    pub fn new(
        mmdb_asn_path: String,
        mmdb_city_path: String,
        asn_blacklist: Vec<u32>,
        country_blacklist: Vec<String>,
    ) -> Self {
        let ddb_asn = Arc::new(RwLock::new(
            maxminddb::Reader::open_readfile(&mmdb_asn_path).unwrap(),
        ));
        let ddb_city = Arc::new(RwLock::new(
            maxminddb::Reader::open_readfile(&mmdb_city_path).unwrap(),
        ));

        let ddb_asn_clone = Arc::clone(&ddb_asn);
        let ddb_city_clone = Arc::clone(&ddb_city);

        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(24 * 60 * 60));

                let new_ddb_asn = maxminddb::Reader::open_readfile(&mmdb_asn_path).unwrap();
                let new_ddb_city = maxminddb::Reader::open_readfile(&mmdb_city_path).unwrap();

                // Acquire write locks to update the readers
                {
                    let mut asn_lock = ddb_asn_clone.write().unwrap();
                    *asn_lock = new_ddb_asn;
                }

                {
                    let mut city_lock = ddb_city_clone.write().unwrap();
                    *city_lock = new_ddb_city;
                }
            }
        });

        GeoIPService {
            ddb_asn,
            ddb_city,
            asn_blacklist,
            country_blacklist,
        }
    }

    pub fn in_asn_blacklist(&self, ip: IpAddr) -> Result<bool, Error> {
        let binding = self.ddb_asn.read().unwrap();
        let info: geoip2::Asn = binding.lookup(ip)?;

        let asn_number = &info.autonomous_system_number.unwrap_or_default().to_owned();

        info!("ip: {}, asn: {}", ip, asn_number);

        if !self.asn_blacklist.contains(asn_number) {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn in_country_blacklist(&self, ip: IpAddr) -> Result<bool, Error> {
        let binding = self.ddb_city.read().unwrap();
        let info: geoip2::Country = binding.lookup(ip)?;

        let country = &info
            .country
            .ok_or(Error::MaxminddbCountryNotFoundError)?
            .iso_code
            .unwrap_or_default()
            .to_owned();

        info!("ip: {}, country: {}", ip, country);

        if !self.country_blacklist.contains(country) {
            return Ok(false);
        }

        Ok(true)
    }
}

const DDBM_ASN: &str = "https://git.io/GeoLite2-ASN.mmdb";
const DDBM_CITY: &str = "https://git.io/GeoLite2-City.mmdb";

pub fn download_ddbm(asn_path: &str, city_path: &str) -> Result<(), Error> {
    info!("start download ddbm");
    download(DDBM_ASN, asn_path)?;
    download(DDBM_CITY, city_path)?;
    info!("finish ddbm");

    Ok(())
}
