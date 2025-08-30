use async_trait::async_trait;
use log::{debug, error, warn};
use once_cell::sync::Lazy;
use raigeki_mcproto::login::DisconnectPacket as LoginDisconnectPacket;
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::select;

use pingora::apps::ServerApp;
use pingora::protocols::{Stream, IO};
use pingora::server::ShutdownWatch;
use pingora::services::listening::Service;
use pingora_limits::rate::Rate;

use prometheus::{
    register_counter_vec, register_int_counter, register_int_gauge, CounterVec, IntCounter,
    IntGauge,
};

use crate::service::MemcachedStatus;

use super::geoip;
use raigeki_error::Error;

pub static TOTAL_CONNS: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge!("total_connections", "total tcp connections").unwrap());

static INCOMING_BYTES_TOTAL: Lazy<IntCounter> =
    Lazy::new(|| register_int_counter!("incoming_bytes_total", "Total incoming bytes").unwrap());

static OUTGOING_BYTES_TOTAL: Lazy<IntCounter> =
    Lazy::new(|| register_int_counter!("outgoing_bytes_total", "Total outgoing bytes").unwrap());

pub static DDOS_MODE: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge!("ddos_mode", "DDoS protection mode").unwrap());

static RATE_LIMITER: Lazy<Rate> = Lazy::new(|| Rate::new(Duration::from_secs(60)));

pub static REQUEST_PER_IP: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "request_per_ip",
        "Number of processed requests from single ip",
        &["ip"]
    )
    .unwrap()
});

pub static REQUEST_TOTAL: Lazy<IntCounter> =
    Lazy::new(|| register_int_counter!("request_total", "Total requests processed").unwrap());

pub static INCOMING_CONNECTIONS_ATTEMPTS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("incoming_connections_attempts", "Total number of incoming connection attempts, including both successful and unsuccessful connections.").unwrap()
});

pub fn forward_service(app: ForwardApp) -> Service<ForwardApp> {
    Service::new("Raigeki Proxy Service".to_string(), app)
}

pub struct ForwardApp {
    geoip_service: Arc<geoip::GeoIPService>,
    outbound_addr: SocketAddr,
    mrpm: isize,
    memcached_client: memcache::Client,
    haproxy: bool,
}

impl ForwardApp {
    pub fn new(
        outbound_addr: SocketAddr,
        geoip_service: Arc<geoip::GeoIPService>,
        mrpm: isize,
        memcached_client: memcache::Client,
        haproxy: bool,
    ) -> Self {
        ForwardApp {
            outbound_addr,
            geoip_service,
            mrpm,
            memcached_client,
            haproxy,
        }
    }
}

#[async_trait]
impl ServerApp for ForwardApp {
    async fn process_new(
        self: &Arc<Self>,
        mut io: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        INCOMING_CONNECTIONS_ATTEMPTS.inc();

        if let Err(e) = self.is_valid_connection(&mut io).await {
            warn!("Failed validation: {:?}", e);

            let reason = json!({
                "text": e.to_string(),
                "color": "red",
                "bold": true,
            })
            .to_owned();

            let packet = LoginDisconnectPacket::new(reason.to_string());
            io.write_all(&packet.serialize()).await.ok()?;
            io.flush().await.ok()?;

            tokio::time::sleep(Duration::from_millis(50)).await;

            return None;
        }

        let mut outbound = TcpStream::connect(self.outbound_addr).await.ok()?;

        TOTAL_CONNS.inc();

        if self.haproxy {
            if let Err(e) = self.write_haproxy_header(&mut outbound, &io).await {
                warn!("Failed to write TCP Proxy header: {:?}", e);

                let reason = json!({
                    "text": e.to_string(),
                    "color": "red",
                    "bold": true,
                })
                .to_owned();

                let packet = LoginDisconnectPacket::new(reason.to_string());
                io.write_all(&packet.serialize()).await.ok()?;
                io.flush().await.ok()?;

                return None;
            }
        }

        if self
            .handle_connection(&mut io, &mut outbound, shutdown)
            .await
            .is_err()
        {
            warn!("Connection ended with error");
        }

        TOTAL_CONNS.dec();

        None
    }
}

impl ForwardApp {
    async fn write_haproxy_header(
        &self,
        outbound: &mut TcpStream,
        io: &Stream,
    ) -> Result<(), Error> {
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

    async fn is_valid_connection(&self, io: &mut Stream) -> Result<(), Error> {
        let socket_digest = io.get_socket_digest();
        let socket_addr = socket_digest
            .as_ref()
            .map(|d| d.peer_addr())
            .unwrap()
            .unwrap();

        let incoming_addr = socket_addr.as_inet().unwrap().ip();

        let ip_status: i16 = self
            .memcached_client
            .get(&incoming_addr.to_string())
            .map_err(|e| {
                match e {
                    memcache::MemcacheError::CommandError(memcache::CommandError::KeyNotFound) => {
                        return Ok(());
                    }
                    _ => {}
                }
                Err(Error::InternalError(e.to_string()))
            })
            .unwrap()
            .unwrap_or_default();

        if ip_status == MemcachedStatus::IpBlocked as i16 {
            warn!("Address {} reject from cache; IP banned", incoming_addr);
            return Err(Error::IpBlockedInCache(incoming_addr));
        }

        if ip_status == MemcachedStatus::IpWhiteList as i16 {
            warn!("Address {} reject from cache; IP banned", incoming_addr);
            return Ok(());
        }

        if self
            .geoip_service
            .in_asn_blacklist(incoming_addr)
            .unwrap_or(true)
        {
            warn!(
                "Address {} reject by asn; Please disable VPN",
                incoming_addr
            );
            self.memcached_client
                .set(
                    &incoming_addr.to_string(),
                    MemcachedStatus::IpBlocked as i16,
                    1 * 60 * 60,
                )
                .unwrap();
            return Err(Error::AsnBlocked(incoming_addr));
        }

        if DDOS_MODE.get() == 0 {
            return Ok(());
        }

        if self
            .geoip_service
            .in_country_blacklist(incoming_addr)
            .unwrap_or(true)
        {
            warn!("Address {} reject by country", incoming_addr);
            self.memcached_client
                .set(
                    &incoming_addr.to_string(),
                    MemcachedStatus::IpBlocked as i16,
                    1 * 60 * 60,
                )
                .unwrap();
            return Err(Error::CountryBlocked(incoming_addr));
        }

        return Ok(());
    }

    async fn handle_connection(
        &self,
        io: &mut Box<dyn IO>,
        outbound: &mut TcpStream,
        shutdown: &ShutdownWatch,
    ) -> Result<(), Error> {
        let mut buf_io = vec![0; 1024];
        let mut buf_outbound = vec![0; 1024];

        let socket_digest = io.get_socket_digest();
        let socket_addr = socket_digest
            .as_ref()
            .map(|d| d.peer_addr())
            .unwrap()
            .unwrap();
        let incoming_addr = socket_addr.as_inet().unwrap().ip();
        let ip_str = incoming_addr.to_string();

        let mut shutdown_clone = shutdown.clone();

        loop {
            select! {
                _ = shutdown_clone.changed() => {
                warn!("Shutdown signal received, closing connection from {}", ip_str);

                return Ok(());
            }

                result = io.read(&mut buf_io) => {
                    match result {
                        Ok(n) if n > 0 => {
                            outbound.write_all(&buf_io[0..n]).await?;
                            outbound.flush().await?;

                            // TODO: dpi
                            INCOMING_BYTES_TOTAL.inc_by(n as u64);
                            REQUEST_PER_IP.with_label_values(&[&ip_str]).inc();
                            REQUEST_TOTAL.inc();

                            let curr_window_requests = RATE_LIMITER.observe(&incoming_addr, 1);

                            if curr_window_requests > self.mrpm {
                                warn!("Address {} exceed max rpm; rpm={}", incoming_addr, curr_window_requests);
                                self.memcached_client.set(&incoming_addr.to_string(), MemcachedStatus::IpBlocked as i16, 1 * 60 * 60)?;
                                io.shutdown().await?;
                                return Ok(());
                            }
                        }
                        Ok(_) => {
                            debug!("Session closing");
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
                            debug!("Outbound connection closed");
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
