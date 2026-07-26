//! Bounded transport limits.

use std::time::Duration;

const MAX_RESPONSE_CONTENT_ENCODING_LAYERS: usize = 2;

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
    /// Maximum encoded upstream response body length.
    pub max_response_body_bytes: usize,
    /// Maximum response body length after all supported content codings are
    /// decoded.
    pub max_decoded_response_body_bytes: usize,
    /// Maximum number of non-identity response content-coding layers.
    ///
    /// A zero value rejects every encoded response while still allowing
    /// identity responses. Values above the hard two-layer safety ceiling are
    /// invalid.
    pub max_response_content_encodings: usize,
    /// Maximum gap between non-empty upstream response-body data frames.
    pub response_body_idle_timeout: Duration,
    /// Minimum sustained encoded response-body throughput in each complete
    /// rate window.
    ///
    /// A zero value disables only the rate floor; byte, decoding, and idle
    /// limits still apply.
    pub min_response_body_bytes_per_second: u64,
    /// Window over which the minimum encoded response-body throughput is
    /// measured.
    pub response_body_rate_window: Duration,
    /// Maximum concurrently admitted TCP connections.
    pub max_connections: usize,
    /// Time allowed to receive a complete request header block.
    pub header_timeout: Duration,
    /// Time allowed to connect and receive an upstream response head.
    pub upstream_timeout: Duration,
    /// Maximum period with no successful read or write on an upgraded
    /// WebSocket tunnel.
    pub websocket_idle_timeout: Duration,
    /// Maximum raw WebSocket tunnel throughput in each direction.
    ///
    /// The ceiling includes WebSocket framing bytes. A zero value disables
    /// only rate shaping; idle, connection, and task limits still apply.
    pub max_websocket_bytes_per_second: u64,
    /// Maximum initial burst duration for each independent WebSocket direction.
    pub websocket_rate_burst_window: Duration,
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
            max_decoded_response_body_bytes: 256 * 1024 * 1024,
            max_response_content_encodings: 2,
            response_body_idle_timeout: Duration::from_secs(15),
            min_response_body_bytes_per_second: 1024,
            response_body_rate_window: Duration::from_secs(5),
            max_connections: 64,
            header_timeout: Duration::from_secs(5),
            upstream_timeout: Duration::from_secs(10),
            websocket_idle_timeout: Duration::from_mins(5),
            max_websocket_bytes_per_second: 8 * 1024 * 1024,
            websocket_rate_burst_window: Duration::from_secs(1),
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
            && !self.response_body_idle_timeout.is_zero()
            && (self.min_response_body_bytes_per_second == 0
                || !self.response_body_rate_window.is_zero())
            && self.max_response_content_encodings <= MAX_RESPONSE_CONTENT_ENCODING_LAYERS
            && !self.websocket_idle_timeout.is_zero()
            && (self.max_websocket_bytes_per_second == 0
                || (!self.websocket_rate_burst_window.is_zero()
                    && self.websocket_rate_burst_window <= self.websocket_idle_timeout))
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

    #[test]
    fn enabled_response_rate_floor_requires_a_nonzero_window() {
        let enabled = TransportLimits {
            response_body_rate_window: Duration::ZERO,
            ..TransportLimits::default()
        };
        assert!(!enabled.is_valid());

        let disabled = TransportLimits {
            min_response_body_bytes_per_second: 0,
            response_body_rate_window: Duration::ZERO,
            ..TransportLimits::default()
        };
        assert!(disabled.is_valid());
    }

    #[test]
    fn response_content_coding_depth_has_a_hard_upper_bound() {
        let excessive = TransportLimits {
            max_response_content_encodings: MAX_RESPONSE_CONTENT_ENCODING_LAYERS + 1,
            ..TransportLimits::default()
        };
        assert!(!excessive.is_valid());
    }

    #[test]
    fn enabled_websocket_rate_ceiling_requires_a_nonzero_bounded_burst() {
        let zero = TransportLimits {
            websocket_rate_burst_window: Duration::ZERO,
            ..TransportLimits::default()
        };
        assert!(!zero.is_valid());

        let longer_than_idle = TransportLimits {
            websocket_idle_timeout: Duration::from_secs(1),
            websocket_rate_burst_window: Duration::from_secs(2),
            ..TransportLimits::default()
        };
        assert!(!longer_than_idle.is_valid());

        let disabled = TransportLimits {
            max_websocket_bytes_per_second: 0,
            websocket_rate_burst_window: Duration::ZERO,
            ..TransportLimits::default()
        };
        assert!(disabled.is_valid());
    }
}
