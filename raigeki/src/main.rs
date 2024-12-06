// Copyright 2024 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

use pingora::protocols::TcpKeepalive;
use pingora::server::Server;
use pingora::services::background::background_service;
use pingora::services::{listening::Service as ListeningService, Service};

use service::geoip::download_ddbm;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

mod service;
mod settings;

pub fn main() {
    env_logger::init();

    let settings = settings::Settings::new();

    if settings.auto_mmdb {
        download_ddbm(&settings.mmdb_asn, &settings.mmdb_city).unwrap()
    }

    let geoip_service = Arc::new(service::geoip::GeoIPService::new(
        settings.mmdb_asn,
        settings.mmdb_city,
        settings.blocked_asn,
        settings.blocked_country,
    ));

    let mut my_server = Server::new(None).unwrap();
    my_server.bootstrap();

    let mut options = pingora::listeners::TcpSocketOptions::default();
    options.tcp_fastopen = Some(10);
    options.tcp_keepalive = Some(TcpKeepalive {
        idle: Duration::from_secs(60),
        interval: Duration::from_secs(5),
        count: 5,
    });

    let forward_app = service::forward::ForwardApp::new(
        format!("{}:{}", settings.outbound_ip, settings.outbound_port)
            .parse::<SocketAddr>()
            .unwrap(),
        geoip_service,
        settings.rate_limit,
    );

    let mut forward_service = service::forward::forward_service(forward_app);
    forward_service.add_tcp(&format!("{}:{}", settings.l4_ip, settings.l4_port));

    let mut prometheus_service_http = ListeningService::prometheus_http_service();
    prometheus_service_http.add_tcp_with_settings("0.0.0.0:6150", options);

    let background_service = background_service("example", service::stats::ExportService::new());

    let services: Vec<Box<dyn Service>> = vec![
        Box::new(forward_service),
        Box::new(prometheus_service_http),
        Box::new(background_service),
    ];
    my_server.add_services(services);
    my_server.run_forever();
}
