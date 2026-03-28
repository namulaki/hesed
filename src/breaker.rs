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
