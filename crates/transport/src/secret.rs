//! Native-only secret values with redacted formatting and best-effort zeroing.

use std::{fmt, sync::Arc};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// A 256-bit secret encoded as an HTTP/cookie-safe opaque token.
pub struct Secret {
    value: Zeroizing<String>,
}

impl Secret {
    /// Generate a new value with the operating-system cryptographic RNG.
    ///
    /// # Errors
    ///
    /// Returns the random-source error if 256 random bits cannot be obtained.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut())?;
        Ok(Self::from_bytes(*bytes))
    }

    /// Construct a value from exactly 256 bits.
    ///
    /// This is public so deterministic loopback-only acceptance fixtures can
    /// share a credential with a mock upstream. Production callers should use
    /// [`Self::generate`].
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            value: Zeroizing::new(format!("rp-{}", hex::encode(bytes))),
        }
    }

    /// Compare a candidate without a data-dependent early exit.
    #[must_use]
    pub fn matches(&self, candidate: &[u8]) -> bool {
        let expected = self.value.as_bytes();
        if expected.len() != candidate.len() {
            return false;
        }
        bool::from(expected.ct_eq(candidate))
    }

    pub(crate) fn expose(&self) -> &str {
        self.value.as_str()
    }

    /// Invoke trusted native code with the opaque value.
    ///
    /// The returned value from `callback` must not contain or retain the
    /// credential.
    pub fn with_exposed<T>(&self, callback: impl FnOnce(&str) -> T) -> T {
        callback(self.value.as_str())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}

/// Independent credentials held by the native transport.
#[derive(Clone)]
pub struct TransportSecrets {
    session: Arc<Secret>,
    upstream: Arc<Secret>,
    bootstrap: Arc<Secret>,
}

impl TransportSecrets {
    /// Generate independent session, upstream, and bootstrap credentials.
    ///
    /// # Errors
    ///
    /// Returns the random-source error if any credential cannot be generated.
    pub fn generate() -> Result<Self, getrandom::Error> {
        Ok(Self {
            session: Arc::new(Secret::generate()?),
            upstream: Arc::new(Secret::generate()?),
            bootstrap: Arc::new(Secret::generate()?),
        })
    }

    /// Construct an explicit trio, primarily for deterministic testkit use.
    #[must_use]
    pub fn new(session: Arc<Secret>, upstream: Arc<Secret>, bootstrap: Arc<Secret>) -> Self {
        Self {
            session,
            upstream,
            bootstrap,
        }
    }

    /// Return the native proxy-session credential.
    #[must_use]
    pub fn session(&self) -> Arc<Secret> {
        Arc::clone(&self.session)
    }

    /// Return the secret expected by the fixed upstream.
    #[must_use]
    pub fn upstream(&self) -> Arc<Secret> {
        Arc::clone(&self.upstream)
    }

    /// Return the one-time native bootstrap credential.
    #[must_use]
    pub fn bootstrap(&self) -> Arc<Secret> {
        Arc::clone(&self.bootstrap)
    }
}

impl fmt::Debug for TransportSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportSecrets")
            .field("session", &"[REDACTED]")
            .field("upstream", &"[REDACTED]")
            .field("bootstrap", &"[REDACTED]")
            .finish()
    }
}
