//! Per-guest token bucket (R20).
use std::collections::HashMap;
use std::time::Instant;

pub struct RateLimit {
    rate: f64,
    burst: f64,
    buckets: HashMap<u32, (f64, Instant)>,
}

impl RateLimit {
    /// `per_min` tokens per minute, `burst` max.
    pub fn new(per_min: u32, burst: u32) -> Self {
        RateLimit { rate: per_min as f64 / 60.0, burst: burst as f64, buckets: HashMap::new() }
    }
    pub fn allow(&mut self, vmid: u32) -> bool {
        self.allow_at(vmid, Instant::now())
    }
    pub fn allow_at(&mut self, vmid: u32, t: Instant) -> bool {
        let (rate, burst) = (self.rate, self.burst);
        let b = self.buckets.entry(vmid).or_insert((burst, t));
        let el = t.saturating_duration_since(b.1).as_secs_f64();
        b.0 = (b.0 + el * rate).min(burst);
        b.1 = t;
        if b.0 >= 1.0 {
            b.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn throttles() {
        let mut r = super::RateLimit::new(60, 3);
        let t = std::time::Instant::now();
        assert!(r.allow_at(1, t) && r.allow_at(1, t) && r.allow_at(1, t));
        assert!(!r.allow_at(1, t));
        assert!(r.allow_at(2, t), "per guest");
        assert!(r.allow_at(1, t + std::time::Duration::from_secs(1)));
    }
}
