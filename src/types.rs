use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

#[derive(Serialize, Deserialize)]
pub struct WalletInfo {
    pub address: String,
    pub mnemonic: String,
    pub duration_seconds: u64,
    pub duration_human: String,
    pub timestamp: String,
    pub chain_type: String,
}

// Structure to track performance across threads
pub struct PerformanceTracker {
    pub address_counter: AtomicUsize,
    pub start_time: Instant,
}

impl PerformanceTracker {
    pub fn new() -> Self {
        PerformanceTracker {
            address_counter: AtomicUsize::new(0),
            start_time: Instant::now(),
        }
    }

    pub fn increment(&self) {
        self.address_counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_ops_per_second(&self) -> f64 {
        let count = self.address_counter.load(Ordering::Relaxed) as f64;
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            count / elapsed
        } else {
            0.0
        }
    }
}