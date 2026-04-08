use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct SlidingWindowRateLimiter {
    limit: usize,
    window: Duration,
    events: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl SlidingWindowRateLimiter {
    pub fn new(limit: usize, window: Duration) -> Self {
        Self {
            limit,
            window,
            events: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow(&self, ip: IpAddr) -> bool {
        let mut events = self.events.lock().expect("rate limiter mutex poisoned");
        let now = Instant::now();

        let queue = events.entry(ip).or_default();
        while let Some(oldest) = queue.front() {
            if now.duration_since(*oldest) > self.window {
                queue.pop_front();
            } else {
                break;
            }
        }

        if queue.len() >= self.limit {
            return false;
        }

        queue.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn denies_after_limit() {
        let limiter = SlidingWindowRateLimiter::new(2, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(!limiter.allow(ip));
    }
}
