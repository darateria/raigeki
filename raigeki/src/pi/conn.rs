use std::collections::VecDeque;

use anyhow::Error;
use log::{info, warn};
use raigeki_error::Error::InsufficientData;

#[derive(Debug, Clone, Copy)]
pub struct ConnectionMetrics {
    pub total_conns: u64,
    pub incoming_attempts: u64,
    pub request_total: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct AggregatedMetrics {
    pub total_conns: u64,
    pub incoming_attempts: u64,
    pub success_rate: f64,
    pub request_total: u64,
}

#[derive(Debug)]
pub struct DDoSDetector {
    aggregated_history: VecDeque<AggregatedMetrics>,
    max_history_size: usize,
    sigma_threshold: f64,
    packet_flood_threshold: f64,
}

impl DDoSDetector {
    pub fn new(max_history_size: usize, sigma_threshold: f64, packet_flood_threshold: f64) -> Self {
        Self {
            aggregated_history: VecDeque::with_capacity(max_history_size),
            max_history_size,
            sigma_threshold,
            packet_flood_threshold,
        }
    }

    pub fn add_metrics(&mut self, metrics: ConnectionMetrics) {
        let mut agg_metrics = ConnectionMetrics {
            total_conns: metrics.total_conns,
            incoming_attempts: metrics.incoming_attempts,
            request_total: metrics.request_total,
        };

        if let Some(ref mut agg) = self.aggregated_history.back() {
            agg_metrics.total_conns = metrics.total_conns;
            agg_metrics.incoming_attempts = metrics.incoming_attempts - agg.incoming_attempts;
            agg_metrics.request_total = metrics.request_total - agg.request_total;
        }

        let success_rate = Self::calculate_success_rate(&agg_metrics);

        let aggregated = AggregatedMetrics {
            total_conns: agg_metrics.total_conns,
            incoming_attempts: agg_metrics.incoming_attempts,
            request_total: agg_metrics.request_total,
            success_rate,
        };

        // Добавляем в историю (FIFO)
        if self.aggregated_history.len() >= self.max_history_size {
            self.aggregated_history.pop_front();
        }
        self.aggregated_history.push_back(aggregated);
    }

    pub fn analyze(&self) -> Result<bool, Error> {
        if self.aggregated_history.len() < 2 {
            return Ok(false);
        }

        let current_agg = self.aggregated_history.back().unwrap();

        // Абсолютный порог флуда пакетов
        if self.is_packet_flood(current_agg) {
            warn!("Packet flood detected");
            return Ok(true);
        }

        // 2. Статистический анализ с использованием истории
        let historical_rates: Vec<f64> = self
            .aggregated_history
            .iter()
            .map(|m| m.incoming_attempts as f64)
            .collect();

        let historical_success_rates: Vec<f64> = self
            .aggregated_history
            .iter()
            .map(|m| m.success_rate)
            .collect();

        let historical_packets: Vec<f64> = self
            .aggregated_history
            .iter()
            .map(|m| m.request_total as f64)
            .collect();

        let mean_rate = statistical_mean(&historical_rates)?;
        let stddev_rate = standard_deviation(&historical_rates, mean_rate)?;

        let mean_success = statistical_mean(&historical_success_rates)?;
        let stddev_success = standard_deviation(&historical_success_rates, mean_success)?;

        let mean_packets = statistical_mean(&historical_packets)?;
        let stddev_packets = standard_deviation(&historical_packets, mean_packets)?;

        // 3. Проверка статистических аномалий
        let rate_anomaly =
            current_agg.incoming_attempts as f64 > mean_rate + self.sigma_threshold * stddev_rate;
        info!("rate_anomaly: {}, current: {}, mean: {:.2}, stddev: {:.2}",
            rate_anomaly, current_agg.incoming_attempts, mean_rate, stddev_rate);

        let success_anomaly =
            current_agg.success_rate < mean_success - self.sigma_threshold * stddev_success;
        info!("success_anomaly: {}, current: {:.2}%, mean: {:.2}%, stddev: {:.2}",
            success_anomaly, current_agg.success_rate, mean_success, stddev_success);

        let packet_anomaly =
            current_agg.request_total as f64 > mean_packets + self.sigma_threshold * stddev_packets;
        info!("packet_anomaly: {}, current: {}, mean: {:.2}, stddev: {:.2}",
            packet_anomaly, current_agg.request_total, mean_packets, stddev_packets);

        // FIXME: think about it rn disable. Too many false positives
        // if mean_success < self.critical_success_rate {
        //     warn!("Low success rate detected last: {:.2}%", mean_success);
        //     return Ok(true);
        // }

        // 4. Комбинированная проверка
        Ok(rate_anomaly
            || success_anomaly
            || packet_anomaly
            || self.check_combined_attack(current_agg)?)
    }

    fn is_packet_flood(&self, current_agg: &AggregatedMetrics) -> bool {
        if self.aggregated_history.is_empty() {
            return false;
        }

        // Берем медианное значение пакетов из истории
        let mut historical_packets: Vec<u64> = self
            .aggregated_history
            .iter()
            .map(|m| m.request_total)
            .collect();

        historical_packets.sort();
        let median_packets = historical_packets[historical_packets.len() / 2] as f64;

        // Текущее значение превышает медианное в N раз
        current_agg.request_total as f64 > median_packets * self.packet_flood_threshold
    }

    fn check_combined_attack(&self, current_agg: &AggregatedMetrics) -> Result<bool, Error> {
        // Обнаружение сложных атак, где есть несколько умеренных признаков
        if self.aggregated_history.len() < 3 {
            return Ok(false);
        }

        let mut attack_score = 0;

        // Умеренный рост попыток подключений (> 25%)
        if self.check_moderate_increase(
            current_agg.incoming_attempts as f32,
            |m| m.incoming_attempts as f32,
            1.5,
        )? {
            // old - 1.25
            warn!("Moderate increase in incoming attempts detected");
            attack_score += 1;
        }

        // Умеренное падение успешности (< 80% от нормы)
        if self.check_moderate_decrease(current_agg.success_rate, |m| m.success_rate, 0.6)? {
            // old - 0.8
            warn!("Moderate decrease in success rate detected");
            attack_score += 1;
        }

        // Умеренный рост пакетов (> 50%)
        if self.check_moderate_increase(
            current_agg.request_total as f32,
            |m| m.request_total as f32,
            2.0,
        )? {
            // old - 1.5
            warn!("Moderate increase in request total detected");
            attack_score += 1;
        }

        // Если есть 2 из 3 признаков умеренной атаки
        Ok(attack_score >= 2)
    }

    fn check_moderate_increase<T, F>(
        &self,
        current: T,
        selector: F,
        threshold: f64,
    ) -> Result<bool, Error>
    where
        T: Into<f64> + Copy,
        F: Fn(&AggregatedMetrics) -> T,
    {
        let historical_values: Vec<f64> = self
            .aggregated_history
            .iter()
            .map(|m| selector(m).into())
            .collect();

        let mean = statistical_mean(&historical_values)?;
        Ok(current.into() > mean * threshold)
    }

    fn check_moderate_decrease<T, F>(
        &self,
        current: T,
        selector: F,
        threshold: f64,
    ) -> Result<bool, Error>
    where
        T: Into<f64> + Copy,
        F: Fn(&AggregatedMetrics) -> T,
    {
        let historical_values: Vec<f64> = self
            .aggregated_history
            .iter()
            .map(|m| selector(m).into())
            .collect();

        let mean = statistical_mean(&historical_values)?;
        Ok(current.into() < mean * threshold)
    }

    fn calculate_success_rate(metrics: &ConnectionMetrics) -> f64 {
        if metrics.incoming_attempts == 0 {
            return 100.0;
        }

        (metrics.total_conns as f64 / metrics.incoming_attempts as f64) * 100.0
    }
}

fn statistical_mean(data: &[f64]) -> Result<f64, Error> {
    if data.is_empty() {
        return Err(Error::from(InsufficientData));
    }

    let sum: f64 = data.iter().sum();
    Ok(sum / data.len() as f64)
}

fn standard_deviation(data: &[f64], mean: f64) -> Result<f64, Error> {
    if data.len() < 2 {
        return Err(Error::from(InsufficientData));
    }

    let variance: f64 = data
        .iter()
        .map(|value| {
            let diff = mean - value;
            diff * diff
        })
        .sum::<f64>()
        / data.len() as f64;

    Ok(variance.sqrt())
}
