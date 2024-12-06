use async_trait::async_trait;
use log::{debug, error, warn};
use once_cell::sync::Lazy;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::select;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use pingora::apps::ServerApp;
use pingora::protocols::{Stream, IO};
use pingora::server::ShutdownWatch;
use pingora::services::listening::Service;
use pingora_limits::rate::Rate;

use prometheus::{register_counter, register_int_counter, register_int_gauge, Counter, IntCounter, IntGauge};

use super::geoip;
use raigeki_error::Error;

static TOTAL_CONNS: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge!("total_connections", "total tcp connections").unwrap());

static INCOMING_BYTES_TOTAL: Lazy<IntCounter> =
    Lazy::new(|| register_int_counter!("incoming_bytes_total", "Total incoming bytes").unwrap());

static OUTGOING_BYTES_TOTAL: Lazy<IntCounter> =
    Lazy::new(|| register_int_counter!("outgoing_bytes_total", "Total outgoing bytes").unwrap());

static RATE_LIMITER: Lazy<Rate> = Lazy::new(|| Rate::new(Duration::from_secs(1)));

static REQUEST_TOTAL: Lazy<Counter> =
    Lazy::new(|| register_counter!("request_total", "Number of processed requests per seccond").unwrap());

pub fn forward_service(app: ForwardApp) -> Service<ForwardApp> {
    Service::new("Upstream Service".to_string(), app)
}

pub struct ForwardApp {
    geoip_service: Arc<geoip::GeoIPService>,
    outbound_addr: SocketAddr,
    mrps: isize,
}

impl ForwardApp {
    pub fn new(outbound_addr: SocketAddr, geoip_service: Arc<geoip::GeoIPService>, mrps: isize) -> Self {
        ForwardApp {
            outbound_addr,
            geoip_service,
            mrps,
        }
    }
}

#[async_trait]
impl ServerApp for ForwardApp {
    async fn process_new(
        self: &Arc<Self>,
        mut io: Stream,
        _shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let socket_digest = io.get_socket_digest();

        let incomming_addr = socket_digest
            .as_ref()
            .map(|d| d.peer_addr())
            .unwrap()
            .unwrap();
        debug!("{}", incomming_addr);

        let mut outbound = TcpStream::connect(self.outbound_addr).await.unwrap();

        if self
            .geoip_service
            .in_asn_blacklist(incomming_addr.as_inet().unwrap().ip())
            .is_err()
        {
            warn!("faild check ASN")
        }

        if self
            .geoip_service
            .in_country_blacklist(incomming_addr.as_inet().unwrap().ip())
            .is_err()
        {
            warn!("faild check country")
        }

        // TODO: mb ban list

        TOTAL_CONNS.inc();

        if self.handle_connection(&mut io, &mut outbound).await.is_err() {
            warn!("connection end with error")
        }

        TOTAL_CONNS.dec();

        None
    }
}

impl ForwardApp {
    async fn handle_connection(&self, io: &mut Box<dyn IO>, outbound: &mut TcpStream) -> Result<(), Error> {
        let mut buf_io = vec![0; 1024];
        let mut buf_outbound = vec![0; 1024];
    
        loop {
            select! {
                result = io.read(&mut buf_io) => {
                    match result {
                        Ok(n) if n > 0 => {
                            outbound.write_all(&buf_io[0..n]).await?;
                            outbound.flush().await?;
    
                            INCOMING_BYTES_TOTAL.inc_by(n as u64);
                            REQUEST_TOTAL.inc();
    
                            let curr_window_requests = RATE_LIMITER.observe(&io
                                .get_socket_digest()
                                .as_ref()
                                .map(|d| d.peer_addr())
                                .unwrap()
                                .unwrap(), 1);
                            
                            if curr_window_requests > self.mrps {
                                io.shutdown().await?;
                            }
                        }
                        Ok(_) => {
                            debug!("session closing");
                            return Ok(());
                        }
                        Err(e) => {
                            error!("Error reading from io: {:?}", e);
                            return Err(Error::IOError(e));
                        }
                    }
                }
    
                result = outbound.read(&mut buf_outbound) => {
                    match result {
                        Ok(n) if n > 0 => {
                            io.write_all(&buf_outbound[0..n]).await?;
                            io.flush().await?;
    
                            OUTGOING_BYTES_TOTAL.inc_by(n as u64);
                        }
                        Ok(_) => {
                            debug!("outbound connection closed");
                            return Ok(());
                        }
                        Err(e) => {
                            eprintln!("Error reading from outbound: {:?}", e);
                            return Err(Error::IOError(e));
                        }
                    }
                }
            }
        }
    }
}