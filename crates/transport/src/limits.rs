//! Bounded transport limits.

use std::time::Duration;

/// Resource and timing limits applied before and during proxying.
#[derive(Clone, Debug)]
pub struct TransportLimits {
    /// Maximum raw HTTP request-line length.
    pub max_request_line_bytes: usize,
    /// Maximum raw request-header block length.
    pub max_header_bytes: usize,
    /// Maximum number of request headers.
    pub max_headers: usize,
    /// Maximum declared or streamed request body length.
    pub max_request_body_bytes: usize,
    /// Maximum streamed response body length in the Phase 1 spike.
    pub max_response_body_bytes: usize,
    /// Maximum concurrently admitted TCP connections.
    pub max_connections: usize,
    /// Time allowed to receive a complete request header block.
    pub header_timeout: Duration,
    /// Time allowed to connect and receive an upstream response head.
    pub upstream_timeout: Duration,
    /// Maximum period with no successful read or write on an upgraded
    /// WebSocket tunnel.
    pub websocket_idle_timeout: Duration,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            max_request_line_bytes: 8 * 1024,
            max_header_bytes: 32 * 1024,
            max_headers: 96,
            max_request_body_bytes: 64 * 1024 * 1024,
            max_response_body_bytes: 256 * 1024 * 1024,
            max_connections: 64,
            header_timeout: Duration::from_secs(5),
            upstream_timeout: Duration::from_secs(10),
            websocket_idle_timeout: Duration::from_mins(5),
        }
    }
}
