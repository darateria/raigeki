use std::{sync::{Arc, Mutex}, time::Duration};

use async_trait::async_trait;
use log::{error, warn};
use once_cell::sync::Lazy;
use pingora::{server::ShutdownWatch, services::background::BackgroundService};
use prometheus::{register_gauge, register_int_gauge, Gauge, IntGauge};
use raigeki::pi::conn::DDoSDetector;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::time::interval;

use crate::service::forward::{INCOMING_CONNECTIONS_ATTEMPTS, REQUEST_TOTAL, TOTAL_CONNS};

static CPU_USAGE_TOTAL: Lazy<Gauge> =
    Lazy::new(|| register_gauge!("cpu_usage_total", "Raigeki proccess cpu usage").unwrap());

static RAM_USAGE_TOTAL: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge!("ram_usage_total", "Raigeki proccess ram usage").unwrap());

pub struct ExportService {
    pid: usize,
    system: Arc<Mutex<System>>,
    conn_inspector: Arc<Mutex<DDoSDetector>>,
}

impl ExportService {
    pub fn new() -> Self {
        let current_pid = std::process::id();
        let system = Arc::new(Mutex::new(System::new_all()));
        let conn_inspector = Arc::new(Mutex::new(DDoSDetector::new(50, 40.0, 3.0, 5.0)));

        ExportService { pid: current_pid as usize, system, conn_inspector}
    }
}

#[async_trait]
impl BackgroundService for ExportService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut period = interval(Duration::from_secs(10));
        let mut period_check_ddos = interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    // shutdown
                    break;
                }
                _ = period.tick() => {
                    let mut s = self.system.lock().unwrap();

                    s.refresh_processes_specifics(
                        ProcessesToUpdate::Some(&[self.pid.into()]),
                        true,
                        ProcessRefreshKind::nothing().with_cpu()
                    );

                    let proc = s.process(Pid::from(self.pid)).unwrap();

                    let cpu_usage = proc.cpu_usage() / num_cpus::get() as f32;

                    CPU_USAGE_TOTAL.set(cpu_usage as f64);
                    RAM_USAGE_TOTAL.set(proc.memory() as i64);

                    self.conn_inspector.lock().unwrap().add_metrics(raigeki::pi::conn::ConnectionMetrics {
                        total_conns: TOTAL_CONNS.get() as u64,
                        incoming_attempts: INCOMING_CONNECTIONS_ATTEMPTS.get() as u64,
                        request_total: REQUEST_TOTAL.get() as u64,
                    });
                }
                _ = period_check_ddos.tick() => {
                    match self.conn_inspector.lock().unwrap().analyze() {
                        Ok(is_ddos) => {
                            if is_ddos {
                                warn!("DDoS attack detected! Enabling DDoS protection mode.");
                                crate::service::forward::DDOS_MODE.set(1);
                            } else {
                                warn!("Disabling DDoS protection mode.");
                                crate::service::forward::DDOS_MODE.set(0);
                            }
                        }
                        Err(e) => {
                            error!("Failed to analyze connection metrics: {}", e);
                        }
                    }
                }
            }
        }
    }
}
