//! Security-critical authenticated loopback reverse transport.
//!
//! The proxy exposes a fresh browser origin and authenticates it with a
//! one-time native bootstrap followed by an HTTP-installed `HttpOnly` cookie.
//! It strips that credential before forwarding and injects the independent
//! upstream Shiny secret only after request admission succeeds.

mod admission;
mod cookie;
mod limits;
mod proxy;
mod replay_io;
mod request_body;
mod response_body;
mod response_decode;
mod response_guard_io;
mod secret;
mod websocket_io;
#[cfg(windows)]
mod windows_socket;

pub use limits::TransportLimits;
pub use proxy::{
    BOOTSTRAP_HEADER_NAME, HostResolution, ProxyAddress, ProxyConfig, ProxyError, RunningProxy,
    SESSION_COOKIE_NAME,
};
pub use secret::{Secret, TransportSecrets};
