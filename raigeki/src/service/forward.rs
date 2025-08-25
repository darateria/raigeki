use async_trait::async_trait;
use log::{debug, error, warn};
use once_cell::sync::Lazy;
use std::net::{IpAddr, SocketAddr, Ipv4Addr};
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

use crate::service::MemcachedStatus;

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

static INCOMING_CONNECTIONS_ATTEMPTS: Lazy<IntGauge> = 
    Lazy::new(|| register_int_gauge!("incoming_connections_attempts", "Total number of incoming connection attempts, including both successful and unsuccessful connections.").unwrap());

pub fn forward_service(app: ForwardApp) -> Service<ForwardApp> {
    Service::new("Upstream Service".to_string(), app)
}

pub struct ForwardApp {
    geoip_service: Arc<geoip::GeoIPService>,
    outbound_addr: SocketAddr,
    mrps: isize,
    memcached_client: memcache::Client,
    haproxy: bool,
}

impl ForwardApp {
    pub fn new(outbound_addr: SocketAddr, geoip_service: Arc<geoip::GeoIPService>, mrps: isize, memcached_client: memcache::Client, haproxy: bool) -> Self {
        ForwardApp {
            outbound_addr,
            geoip_service,
            mrps,
            memcached_client,
            haproxy
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
        INCOMING_CONNECTIONS_ATTEMPTS.inc();

        if !self.is_valid_connection(&mut io).await {
            return None;
        }

        let mut outbound = TcpStream::connect(self.outbound_addr).await.unwrap();

        TOTAL_CONNS.inc();

        if self.haproxy {
            if let Err(e) = self.write_haproxy_header(&mut outbound, &io).await {
                warn!("Failed to write HAProxy header: {:?}", e);
                io.shutdown().await.unwrap();
                return None;
            }
        }

        if self.handle_connection(&mut io, &mut outbound).await.is_err() {
            warn!("connection end with error")
        }

        TOTAL_CONNS.dec();

        None
    }
}

impl ForwardApp {
    async fn write_haproxy_header(&self, outbound: &mut TcpStream, io: &Stream) -> Result<(), Error> {
        let socket_digest = io.get_socket_digest();
        let (src_addr, src_port, dest_addr, dest_port) = match socket_digest {
            Some(digest) => {
                let peer_addr = digest.peer_addr().unwrap();
                let local_addr = digest.local_addr().unwrap();
                
                let (src_ip, src_port) = match peer_addr.as_inet().unwrap() {
                    SocketAddr::V4(addr) => (IpAddr::V4(*addr.ip()), addr.port()),
                    SocketAddr::V6(addr) => (IpAddr::V6(*addr.ip()), addr.port()),
                };
                
                let (dest_ip, dest_port) = match local_addr.as_inet().unwrap() {
                    SocketAddr::V4(addr) => (IpAddr::V4(*addr.ip()), addr.port()),
                    SocketAddr::V6(addr) => (IpAddr::V6(*addr.ip()), addr.port()),
                };
                
                (src_ip, src_port, dest_ip, dest_port)
            }
            None => {
                return Err(Error::InvalidConnection);
            }
        };

        let header = match (src_addr, dest_addr) {
            (IpAddr::V4(src_ip), IpAddr::V4(dest_ip)) => {
                format!(
                    "PROXY TCP4 {} {} {} {}\r\n",
                    src_ip, dest_ip, src_port, dest_port
                )
            }
            (IpAddr::V6(src_ip), IpAddr::V6(dest_ip)) => {
                format!(
                    "PROXY TCP6 {} {} {} {}\r\n",
                    src_ip, dest_ip, src_port, dest_port
                )
            }
            _ => {
                format!(
                    "PROXY TCP6 {} {} {} {}\r\n",
                    src_addr, dest_addr, src_port, dest_port
                )
            }
        };

        outbound.write_all(header.as_bytes()).await?;
        outbound.flush().await?;

        Ok(())
    }

    async fn is_valid_connection(&self, io: &mut Stream) -> bool {
        let socket_digest = io.get_socket_digest();
        let socket_addr = socket_digest
            .as_ref()
            .map(|d| d.peer_addr())
            .unwrap()
            .unwrap();
        let incomming_addr= socket_addr.as_inet().unwrap().ip();
        debug!("{}", socket_addr);

        let ip_status: i16 = self.memcached_client.get(&incomming_addr.to_string())
            .map_err(|e| {
                match e {
                    memcache::MemcacheError::CommandError(memcache::CommandError::KeyNotFound) => {
                        return Ok(());
                    },
                    _ => {}
                }
                Err(e)
            }).unwrap().unwrap_or_default();

        if incomming_addr == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)) {
            return true;
        }

        if ip_status == MemcachedStatus::IpBlocked as i16 {
            warn!("address {} reject from cache", incomming_addr);
            io.shutdown().await.unwrap();
            return false;
        }

        if self
            .geoip_service
            .in_asn_blacklist(incomming_addr)
            .unwrap_or(true)
        {
            warn!("address {} reject by asn", incomming_addr);
            self.memcached_client.set(&incomming_addr.to_string(), MemcachedStatus::IpBlocked as i16, 1 * 60 * 60).unwrap();
            io.shutdown().await.unwrap();
            return false;
        }

        if self
            .geoip_service
            .in_country_blacklist(incomming_addr)
            .unwrap_or(true)
        {
            warn!("address {} reject by country", incomming_addr);
            self.memcached_client.set(&incomming_addr.to_string(), MemcachedStatus::IpBlocked as i16, 1 * 60 * 60).unwrap();
            io.shutdown().await.unwrap();
            return false;
        }

        return true;
    }

    async fn handle_connection(&self, io: &mut Box<dyn IO>, outbound: &mut TcpStream) -> Result<(), Error> {
        let mut buf_io = vec![0; 1024];
        let mut buf_outbound = vec![0; 1024];

        let socket_digest = io.get_socket_digest();
        let socket_addr = socket_digest
            .as_ref()
            .map(|d| d.peer_addr())
            .unwrap()
            .unwrap();
        let incomming_addr= socket_addr.as_inet().unwrap().ip();
    
        loop {
            select! {
                result = io.read(&mut buf_io) => {
                    match result {
                        Ok(n) if n > 0 => {
                            outbound.write_all(&buf_io[0..n]).await?;
                            outbound.flush().await?;
    
                            INCOMING_BYTES_TOTAL.inc_by(n as u64);
                            REQUEST_TOTAL.inc();
    
                            let curr_window_requests = RATE_LIMITER.observe(&incomming_addr, 1);
                            
                            if curr_window_requests > self.mrps {
                                self.memcached_client.set(&incomming_addr.to_string(), MemcachedStatus::IpBlocked as i16, 1 * 60 * 60)?;
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