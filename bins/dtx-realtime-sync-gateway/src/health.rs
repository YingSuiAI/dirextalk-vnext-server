use std::time::{Duration, Instant};

pub const STALE_AFTER: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct OutboxHealth {
    last_success: Option<Instant>,
    consecutive_failures: u8,
}
impl OutboxHealth {
    pub const fn starting() -> Self {
        Self {
            last_success: None,
            consecutive_failures: 0,
        }
    }
    pub fn succeeded(&mut self, now: Instant) {
        self.last_success = Some(now);
        self.consecutive_failures = 0;
    }
    pub fn failed(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
    }
    pub fn ready(&self, now: Instant) -> bool {
        self.last_success
            .is_some_and(|success| now.duration_since(success) <= STALE_AFTER)
            && self.consecutive_failures < 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn starting_failure_stale_and_recovery_are_fail_closed() {
        let start = Instant::now();
        let mut health = OutboxHealth::starting();
        assert!(!health.ready(start));
        health.succeeded(start);
        assert!(health.ready(start));
        health.failed();
        health.failed();
        health.failed();
        assert!(!health.ready(start));
        health.succeeded(start);
        assert!(health.ready(start));
        assert!(!health.ready(start + STALE_AFTER + Duration::from_millis(1)));
    }
}
