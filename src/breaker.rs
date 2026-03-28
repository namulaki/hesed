use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;

pub type Limiter = Arc<RateLimiter<governor::state::NotKeyed, governor::state::InMemoryState, governor::clock::DefaultClock>>;

pub fn new_limiter(rps: u32, burst: u32) -> anyhow::Result<Limiter> {
    let rps = NonZeroU32::new(rps).ok_or_else(|| anyhow::anyhow!("rps must be > 0"))?;
    let burst = NonZeroU32::new(burst).ok_or_else(|| anyhow::anyhow!("burst must be > 0"))?;
    let quota = Quota::per_second(rps).allow_burst(burst);
    Ok(Arc::new(RateLimiter::direct(quota)))
}

/// Returns true if the request is allowed, false if rate-limited.
pub fn check(limiter: &Limiter) -> bool {
    limiter.check().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_limiter_valid() {
        let limiter = new_limiter(10, 20);
        assert!(limiter.is_ok());
    }

    #[test]
    fn create_limiter_zero_rps() {
        let limiter = new_limiter(0, 10);
        assert!(limiter.is_err());
    }

    #[test]
    fn create_limiter_zero_burst() {
        let limiter = new_limiter(10, 0);
        assert!(limiter.is_err());
    }

    #[test]
    fn check_allows_within_burst() {
        let limiter = new_limiter(100, 100).unwrap();
        // First request should always pass
        assert!(check(&limiter));
    }

    #[test]
    fn check_rate_limits_after_burst() {
        let limiter = new_limiter(1, 1).unwrap();
        // First should pass
        assert!(check(&limiter));
        // Immediately after, should be rate-limited
        assert!(!check(&limiter));
    }
}
