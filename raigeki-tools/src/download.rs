use std::{fs::File, io::copy, path::Path, time::Duration};

use log::{error, info};
use raigeki_error::Error;
use reqwest::blocking::Client;

pub fn download(addr: &str, path: &str) -> Result<(), Error> {
    let client = Client::builder()
        .timeout(Duration::from_secs(300))
        .build()?;
    
    let response = client.get(addr).send()?;

    if response.status().is_success() {
        let mut file = File::create(Path::new(path))?;

        let content = response.bytes()?;
        copy(&mut content.as_ref(), &mut file)?;

        info!("File downloaded to {}", path);
    } else {
        error!("Failed to download file: {}", response.status());
        return Err(Error::ReqwestUnexpectedStatusCodeError(response.status()));
    }

    Ok(())
}
