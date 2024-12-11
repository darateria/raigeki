use std::{sync::{Arc, Mutex}, time::Duration};

use async_trait::async_trait;
use once_cell::sync::Lazy;
use pingora::{server::ShutdownWatch, services::background::BackgroundService};
use prometheus::{register_gauge, register_int_gauge, Gauge, IntGauge};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::time::interval;

static CPU_USAGE_TOTAL: Lazy<Gauge> =
    Lazy::new(|| register_gauge!("cpu_usage_total", "Raigeki proccess cpu usage").unwrap());

static RAM_USAGE_TOTAL: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge!("ram_usage_total", "Raigeki proccess ram usage").unwrap());

pub struct ExportService {
    pid: usize,
    system: Arc<Mutex<System>>,
}

impl ExportService {
    pub fn new() -> Self {
        let current_pid = std::process::id();
        let system = Arc::new(Mutex::new(System::new_all()));

        ExportService { pid: current_pid as usize, system}
    }
}

#[async_trait]
impl BackgroundService for ExportService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut period = interval(Duration::from_secs(10));

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
                }
            }
        }
    }
}
