//! no-std time provider

use alloc::sync::Arc;

use pki_types::UnixTime;

/// An object that provides the current time
#[derive(Clone)]
pub struct TimeProvider {
    inner: Arc<dyn GetCurrentTime>,
}

impl TimeProvider {
    /// Creates a new time provider
    pub fn new(time_getter: impl GetCurrentTime + 'static) -> Self {
        Self {
            inner: Arc::new(time_getter),
        }
    }

    /// A time provider that always fails
    pub fn none() -> Self {
        Self::new(NoTimeProvider)
    }

    pub(crate) fn get_current_time(&self) -> Result<UnixTime, ()> {
        self.inner.get_current_time()
    }
}

/// Get current time
pub trait GetCurrentTime: Send + Sync {
    /// Get current time
    fn get_current_time(&self) -> Result<UnixTime, ()>;
}

struct NoTimeProvider;

impl GetCurrentTime for NoTimeProvider {
    fn get_current_time(&self) -> Result<UnixTime, ()> {
        Err(())
    }
}
