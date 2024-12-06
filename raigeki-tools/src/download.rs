use std::{fs::File, io::copy, path::Path};

use log::{error, info};
use raigeki_error::Error;
use reqwest::blocking::get;

pub fn download(addr: &str, path: &str) -> Result<(), Error> {
    let response = get(addr)?;

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
