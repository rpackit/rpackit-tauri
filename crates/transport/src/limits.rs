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
    /// Maximum gap between non-empty request-body data frames.
    pub request_body_idle_timeout: Duration,
    /// Maximum total time allowed to stream one request body.
    pub request_body_total_timeout: Duration,
    /// Minimum sustained request-body throughput in each complete rate window.
    ///
    /// A zero value disables only the rate floor; the byte, idle, and total
    /// limits still apply.
    pub min_request_body_bytes_per_second: u64,
    /// Window over which the minimum request-body throughput is measured.
    pub request_body_rate_window: Duration,
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
            request_body_idle_timeout: Duration::from_secs(15),
            request_body_total_timeout: Duration::from_mins(5),
            min_request_body_bytes_per_second: 1024,
            request_body_rate_window: Duration::from_secs(5),
            max_response_body_bytes: 256 * 1024 * 1024,
            max_connections: 64,
            header_timeout: Duration::from_secs(5),
            upstream_timeout: Duration::from_secs(10),
            websocket_idle_timeout: Duration::from_mins(5),
        }
    }
}

impl TransportLimits {
    pub(crate) fn is_valid(&self) -> bool {
        self.max_request_line_bytes > 0
            && self.max_request_line_bytes <= self.max_header_bytes
            && self.max_headers > 0
            && self.max_connections > 0
            && !self.header_timeout.is_zero()
            && !self.upstream_timeout.is_zero()
            && !self.request_body_idle_timeout.is_zero()
            && !self.request_body_total_timeout.is_zero()
            && (self.min_request_body_bytes_per_second == 0
                || (!self.request_body_rate_window.is_zero()
                    && self.request_body_rate_window <= self.request_body_total_timeout))
            && !self.websocket_idle_timeout.is_zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_are_internally_consistent() {
        assert!(TransportLimits::default().is_valid());
    }

    #[test]
    fn enabled_rate_floor_requires_a_nonzero_bounded_window() {
        let enabled = TransportLimits {
            request_body_rate_window: Duration::ZERO,
            ..TransportLimits::default()
        };
        assert!(!enabled.is_valid());

        let disabled = TransportLimits {
            min_request_body_bytes_per_second: 0,
            request_body_rate_window: Duration::ZERO,
            ..TransportLimits::default()
        };
        assert!(disabled.is_valid());
    }
}
