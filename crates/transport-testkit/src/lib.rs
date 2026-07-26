//! Loopback-only mock services for transport acceptance tests.
//!
//! Observations deliberately retain only booleans, counts, methods, and route
//! names. Neither native credential is ever serialized or formatted.

mod request_body_probe;
mod response_resource_probe;

pub use request_body_probe::{RequestBodyLimitEvidence, probe_request_body_limits};
pub use response_resource_probe::{ResponseResourceLimitEvidence, probe_response_resource_limits};

use std::{
    collections::BTreeMap,
    convert::Infallible,
    error::Error as StdError,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _, stream};
use http::{
    HeaderValue, Request, Response, StatusCode,
    header::{
        CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, LOCATION, ORIGIN, SET_COOKIE,
    },
};
use http_body::Frame;
use http_body_util::{BodyExt as _, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_tungstenite::{HyperWebsocket, tungstenite::Message};
use hyper_util::rt::TokioIo;
use rpackit_transport::{
    ProxyConfig, RunningProxy, SESSION_COOKIE_NAME, Secret, TransportLimits, TransportSecrets,
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    net::TcpStream,
    sync::{Mutex, Notify, watch},
    task::JoinHandle,
    time::timeout,
};

#[cfg(windows)]
use socket2::{Domain, Protocol, Socket, Type};
#[cfg(windows)]
use std::net::Ipv6Addr;
#[cfg(windows)]
use tokio::sync::oneshot;

type BoxError = Box<dyn StdError + Send + Sync>;
type TestBody = UnsyncBoxBody<Bytes, BoxError>;

const LISTENER_OVERLAP_REQUESTS: u32 = 8;
const MALFORMED_RESPONSE_CASE_NAMES: [&str; 16] = [
    "conflicting_content_length",
    "content_length_and_transfer_encoding",
    "unsupported_transfer_encoding",
    "chunked_not_final",
    "obsolete_header_folding",
    "whitespace_before_colon",
    "invalid_header_name",
    "bare_line_feeds",
    "invalid_status_code",
    "oversized_response_head",
    "too_many_headers",
    "duplicate_connection",
    "protected_connection_nomination",
    "ambiguous_location",
    "reserved_proxy_cookie",
    "unsolicited_protocol_switch",
];
const MALFORMED_WEBSOCKET_RESPONSE_CASE_NAMES: [&str; 16] = [
    "websocket_bare_line_feeds",
    "websocket_conflicting_content_length",
    "websocket_oversized_response_head",
    "websocket_too_many_headers",
    "websocket_content_length",
    "websocket_transfer_encoding",
    "websocket_duplicate_connection",
    "websocket_duplicate_upgrade",
    "websocket_wrong_upgrade",
    "websocket_missing_accept",
    "websocket_wrong_accept",
    "websocket_duplicate_accept",
    "websocket_unoffered_protocol",
    "websocket_duplicate_protocol",
    "websocket_unsolicited_extensions",
    "websocket_protected_connection_nomination",
];
const MALFORMED_HTTP_RESPONSE_CASES: usize = MALFORMED_RESPONSE_CASE_NAMES.len();
const MALFORMED_WEBSOCKET_RESPONSE_CASES: usize = MALFORMED_WEBSOCKET_RESPONSE_CASE_NAMES.len();
const MALFORMED_RESPONSE_CASES: usize =
    MALFORMED_HTTP_RESPONSE_CASES + MALFORMED_WEBSOCKET_RESPONSE_CASES;
const MALFORMED_RESPONSE_BODY_CASE_NAMES: [&str; 23] = [
    "declared_length_over_limit",
    "declared_trailer",
    "no_content_content_length",
    "no_content_transfer_encoding",
    "reset_content_nonzero_length",
    "reset_content_transfer_encoding",
    "truncated_content_length_empty",
    "truncated_content_length_partial",
    "invalid_chunk_size",
    "overflowing_chunk_size",
    "truncated_chunk_data",
    "missing_chunk_data_crlf",
    "missing_terminal_chunk",
    "malformed_trailer",
    "protected_trailer",
    "oversized_trailer",
    "too_many_trailers",
    "chunked_body_over_limit",
    "close_delimited_body_over_limit",
    "no_content_malicious_body",
    "reset_content_close_delimited_body",
    "bytes_after_terminal_chunk",
    "bytes_after_content_length",
];
const MALFORMED_RESPONSE_BODY_CASES: usize = MALFORMED_RESPONSE_BODY_CASE_NAMES.len();
const MALFORMED_RESPONSE_MARKER: &[u8] = b"rpackit-malformed-upstream-marker";
const MALFORMED_RESPONSE_MARKER_TEXT: &str = "rpackit-malformed-upstream-marker";
const WEBSOCKET_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const WEBSOCKET_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
const SAFE_WEBSOCKET_FRAME: &[u8] = b"\x81\x0dsafe-ws-frame";
const ATTACKER_WEBSOCKET_FRAME: &[u8] = b"\x81\x21rpackit-malformed-upstream-marker";
const WEBSOCKET_CONNECTION_HEADER: (&str, &str) = ("Connection", "Upgrade");
const WEBSOCKET_UPGRADE_HEADER: (&str, &str) = ("Upgrade", "websocket");
const WEBSOCKET_ACCEPT_HEADER: (&str, &str) = ("Sec-WebSocket-Accept", WEBSOCKET_ACCEPT);
const ATTACKER_CANARY_HEADER: (&str, &str) =
    ("X-Rpackit-Attacker-Canary", MALFORMED_RESPONSE_MARKER_TEXT);

/// Boolean-only browser acceptance report submitted by the mock application.
///
/// Separate booleans are intentional: the report is a stable, secret-free
/// evidence checklist rather than application state.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserReport {
    /// CSS resource completed.
    pub css_loaded: bool,
    /// JavaScript resource executed.
    pub script_loaded: bool,
    /// Image resource completed.
    pub image_loaded: bool,
    /// Same-origin GET fetch completed.
    pub fetch_get: bool,
    /// Same-origin unsafe POST fetch completed.
    pub fetch_post: bool,
    /// A streamed response arrived in more than one read.
    pub stream_read: bool,
    /// A real WebSocket completed an echo round trip.
    pub websocket_echo: bool,
    /// JavaScript could see the reserved proxy cookie name.
    pub proxy_cookie_visible: bool,
    /// JavaScript found a value shaped like either native secret.
    pub secret_shape_visible: bool,
    /// The external redirect collector completed a credential-free request.
    pub external_redirect_completed: bool,
    /// A child-host request reached the collector.
    pub child_host_request_completed: bool,
}

/// Secret-free request evidence captured by the mock Shiny upstream.
#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct UpstreamSnapshot {
    /// Accepted TCP connections.
    pub connections: u64,
    /// Parsed HTTP requests.
    pub requests: u64,
    /// Requests carrying exactly one valid protected upstream header.
    pub protected_header_valid: u64,
    /// Requests with any protected-header multiplicity other than one.
    pub protected_header_invalid_count: u64,
    /// Requests in which the native proxy-session cookie leaked upstream.
    pub proxy_cookie_leaks: u64,
    /// Requests in which a browser-supplied forwarding header survived.
    pub forwarding_header_leaks: u64,
    /// WebSocket requests in which a browser extension offer survived.
    pub websocket_extension_leaks: u64,
    /// Requests in which the one-time bootstrap header survived.
    pub bootstrap_header_leaks: u64,
    /// Requests whose rewritten Origin matched the fixed upstream.
    pub valid_rewritten_origins: u64,
    /// Per-route observations.
    pub routes: BTreeMap<String, u64>,
    /// Most recent real-browser report, if submitted.
    pub browser_report: Option<BrowserReport>,
}

/// Secret-free external redirect-collector evidence.
#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct CollectorSnapshot {
    /// Requests received.
    pub requests: u64,
    /// Requests receiving the native proxy-session cookie.
    pub proxy_cookie_leaks: u64,
    /// Requests receiving the protected upstream header.
    pub protected_header_leaks: u64,
    /// Requests receiving the one-time bootstrap header.
    pub bootstrap_header_leaks: u64,
    /// Requests produced by the external redirect route.
    pub external_redirect_requests: u64,
    /// Requests made to a child of the random proxy hostname.
    pub child_host_requests: u64,
}

/// Secret-free evidence for one single-stack wildcard-listener overlap probe.
#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct ListenerFamilyOverlapEvidence {
    /// Whether `SO_REUSEADDR` allowed the wildcard listener to bind.
    ///
    /// A successful wildcard bind is evidence, not a failed gate by itself.
    pub wildcard_bind_succeeded: bool,
    /// Number of real requests attempted against the exact loopback address.
    pub requests_attempted: u32,
    /// Requests for which the exact proxy returned its expected `401`.
    pub proxy_unauthorized_responses: u32,
    /// Connections accepted by the wildcard listener.
    pub wildcard_accepts: u64,
    /// Whether the probe ran to completion.
    pub probe_completed: bool,
    /// Whether every request reached the exact proxy and none reached the
    /// wildcard listener.
    pub exact_proxy_won: bool,
}

impl ListenerFamilyOverlapEvidence {
    /// Return true only when the recorded result and its raw counters prove
    /// the full repeated-request invariant.
    #[must_use]
    pub const fn proves_exact_proxy_ownership(&self) -> bool {
        self.probe_completed
            && self.requests_attempted == LISTENER_OVERLAP_REQUESTS
            && self.proxy_unauthorized_responses == self.requests_attempted
            && self.wildcard_accepts == 0
            && self.exact_proxy_won
    }
}

/// Secret-free evidence for one IPv6 dual-stack wildcard contender tested
/// against both exact loopback listeners.
#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct ListenerDualStackOverlapEvidence {
    /// Whether `SO_REUSEADDR` allowed the dual-stack wildcard to bind.
    ///
    /// A successful wildcard bind is evidence, not a failed gate by itself.
    pub wildcard_bind_succeeded: bool,
    /// Real requests attempted against the exact IPv4 loopback listener.
    pub ipv4_requests_attempted: u32,
    /// Exact-proxy `401` responses observed over IPv4.
    pub ipv4_proxy_unauthorized_responses: u32,
    /// Real requests attempted against the exact IPv6 loopback listener.
    pub ipv6_requests_attempted: u32,
    /// Exact-proxy `401` responses observed over IPv6.
    pub ipv6_proxy_unauthorized_responses: u32,
    /// Connections accepted by the dual-stack wildcard listener.
    pub wildcard_accepts: u64,
    /// Whether both target probes and the accept monitor completed.
    pub probe_completed: bool,
    /// Whether every IPv4 and IPv6 request reached the exact proxies and none
    /// reached the dual-stack wildcard.
    pub exact_proxies_won: bool,
}

impl ListenerDualStackOverlapEvidence {
    /// Return true only when the raw per-target counters prove the complete
    /// dual-stack contender invariant.
    #[must_use]
    pub const fn proves_exact_proxy_ownership(&self) -> bool {
        self.probe_completed
            && self.ipv4_requests_attempted == LISTENER_OVERLAP_REQUESTS
            && self.ipv4_proxy_unauthorized_responses == self.ipv4_requests_attempted
            && self.ipv6_requests_attempted == LISTENER_OVERLAP_REQUESTS
            && self.ipv6_proxy_unauthorized_responses == self.ipv6_requests_attempted
            && self.wildcard_accepts == 0
            && self.exact_proxies_won
    }
}

/// Secret-free evidence for three Windows wildcard contenders and four exact
/// loopback traffic paths.
#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct ListenerOverlapEvidence {
    /// Whether every Windows contender and target probe completed.
    pub windows_probe_completed: bool,
    /// IPv4 wildcard contender against exact IPv4.
    pub ipv4_wildcard: ListenerFamilyOverlapEvidence,
    /// IPv6 v6-only wildcard contender against exact IPv6.
    pub ipv6_v6_only_wildcard: ListenerFamilyOverlapEvidence,
    /// IPv6 dual-stack wildcard contender against exact IPv4 and exact IPv6
    /// while the same contender remains alive.
    pub ipv6_dual_stack_wildcard: ListenerDualStackOverlapEvidence,
}

impl ListenerOverlapEvidence {
    /// Return true only when all three contenders and all four target paths
    /// prove exact-proxy ownership from their raw counters.
    #[must_use]
    pub const fn all_variants_prove_exact_proxy_ownership(&self) -> bool {
        self.windows_probe_completed
            && self.ipv4_wildcard.proves_exact_proxy_ownership()
            && self.ipv6_v6_only_wildcard.proves_exact_proxy_ownership()
            && self.ipv6_dual_stack_wildcard.proves_exact_proxy_ownership()
    }
}

/// Secret-free evidence for the malformed upstream response-head gate.
///
/// The gate includes parser-invalid framing and syntax as well as
/// parser-valid response fields and WebSocket handshakes that the proxy itself
/// must reject. Valid ordinary HTTP and WebSocket baselines are exercised so
/// an unreachable upstream or an incorrectly routed upgrade cannot produce a
/// false pass.
#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct MalformedUpstreamEvidence {
    /// Whether a known-valid ordinary HTTP response traversed the raw harness.
    pub valid_baseline_passed: bool,
    /// Whether a valid `101` and one raw WebSocket frame traversed the harness.
    pub valid_websocket_baseline_passed: bool,
    /// Number of ordinary HTTP negative variants attempted.
    pub http_cases_attempted: u32,
    /// Ordinary HTTP variants converted to the exact fixed `502`.
    pub http_fail_closed_responses: u32,
    /// Number of WebSocket negative variants attempted.
    pub websocket_cases_attempted: u32,
    /// WebSocket variants converted to the exact fixed `502`.
    pub websocket_fail_closed_responses: u32,
    /// Total number of negative response variants attempted.
    pub cases_attempted: u32,
    /// Total variants converted to the exact fixed secret-free `502`.
    pub fail_closed_responses: u32,
    /// Requests carrying exactly one valid protected upstream credential.
    pub upstream_requests_with_valid_secret: u32,
    /// WebSocket requests with an exact protected upstream request shape.
    pub upstream_websocket_requests_valid: u32,
    /// Negative WebSocket responses that switched the downstream connection.
    pub unexpected_downstream_upgrades: u32,
    /// Negative responses in which the malicious header/frame marker appeared.
    pub attacker_markers_forwarded: u32,
    /// Per-case fail-closed observations keyed by a non-secret case name.
    pub cases: BTreeMap<String, bool>,
    /// Whether every raw upstream task and proxy shutdown completed.
    pub probe_completed: bool,
}

impl MalformedUpstreamEvidence {
    /// Return true only when the raw counters and every named result prove the
    /// complete response-head matrix.
    #[must_use]
    pub fn all_response_heads_fail_closed(&self) -> bool {
        self.probe_completed
            && self.valid_baseline_passed
            && self.valid_websocket_baseline_passed
            && usize::try_from(self.http_cases_attempted) == Ok(MALFORMED_HTTP_RESPONSE_CASES)
            && self.http_fail_closed_responses == self.http_cases_attempted
            && usize::try_from(self.websocket_cases_attempted)
                == Ok(MALFORMED_WEBSOCKET_RESPONSE_CASES)
            && self.websocket_fail_closed_responses == self.websocket_cases_attempted
            && usize::try_from(self.cases_attempted) == Ok(MALFORMED_RESPONSE_CASES)
            && self.cases_attempted == self.http_cases_attempted + self.websocket_cases_attempted
            && self.fail_closed_responses == self.cases_attempted
            && self.upstream_requests_with_valid_secret == self.cases_attempted + 2
            && self.upstream_websocket_requests_valid == self.websocket_cases_attempted + 1
            && self.unexpected_downstream_upgrades == 0
            && self.attacker_markers_forwarded == 0
            && self.cases.len() == MALFORMED_RESPONSE_CASES
            && MALFORMED_RESPONSE_CASE_NAMES
                .iter()
                .all(|name| self.cases.get(*name) == Some(&true))
            && MALFORMED_WEBSOCKET_RESPONSE_CASE_NAMES
                .iter()
                .all(|name| self.cases.get(*name) == Some(&true))
    }
}

/// Secret-free evidence for malformed, truncated, and unsafe upstream bodies.
///
/// Cases detected before downstream response-head release must become the
/// exact fixed `502`. Errors discovered while a body is already streaming
/// must close before downstream head serialization or with incomplete
/// downstream framing and `Connection: close`, except that a close-delimited
/// limit cutoff is necessarily complete at the close delimiter. Bytes after a
/// complete upstream message must remain isolated from the one downstream
/// response.
#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct MalformedUpstreamBodyEvidence {
    /// Whether a fragmented fixed-length baseline arrived exactly.
    pub valid_content_length_baseline_passed: bool,
    /// Whether a fragmented chunked baseline arrived exactly.
    pub valid_chunked_baseline_passed: bool,
    /// Whether a close-delimited baseline arrived exactly.
    pub valid_close_delimited_baseline_passed: bool,
    /// Whether a HEAD response preserved hypothetical length without content.
    pub valid_head_nonzero_length_baseline_passed: bool,
    /// Whether a 304 preserved hypothetical length without content.
    pub valid_not_modified_nonzero_length_baseline_passed: bool,
    /// Whether a 204 without framing remained bodyless.
    pub valid_no_content_baseline_passed: bool,
    /// Whether a 205 with `Content-Length: 0` remained bodyless.
    pub valid_reset_content_zero_length_baseline_passed: bool,
    /// Number of named negative cases attempted.
    pub cases_attempted: u32,
    /// Cases rejected with the exact fixed `502` before body streaming.
    pub exact_bad_gateway_responses: u32,
    /// Streaming failures closed before a head or with incomplete framing.
    pub stream_fail_closed_terminations: u32,
    /// Close-delimited over-limit bodies cut off without forwarding content.
    pub close_delimited_limit_terminations: u32,
    /// Body-forbidden status responses that exposed no malicious content.
    pub bodyless_status_terminations: u32,
    /// Response-splitting attempts isolated to the first complete response.
    pub isolated_complete_responses: u32,
    /// Negative cases that terminated before the bounded client timeout.
    pub bounded_terminations: u32,
    /// Upstream requests carrying exactly one valid synthetic credential.
    pub upstream_requests_with_valid_secret: u32,
    /// Keep-alive clients that attempted a second authenticated request.
    pub second_downstream_requests_attempted: u32,
    /// Body-probe sockets physically closed before proxy shutdown.
    pub downstream_connections_physically_closed: u32,
    /// Body-probe sockets that received a second HTTP response.
    pub second_downstream_responses: u32,
    /// Negative responses in which an attacker marker reached downstream.
    pub attacker_markers_forwarded: u32,
    /// Negative responses lacking header close, physical close, or isolation.
    pub reusable_downstream_responses: u32,
    /// Per-case fail-closed observations keyed by a non-secret case name.
    pub cases: BTreeMap<String, bool>,
    /// Whether every raw upstream task and proxy shutdown completed.
    pub probe_completed: bool,
}

impl MalformedUpstreamBodyEvidence {
    /// Return true only when all baselines, counters, and named cases prove the
    /// body and trailer boundary.
    #[must_use]
    pub fn all_response_bodies_fail_closed(&self) -> bool {
        self.probe_completed
            && self.valid_content_length_baseline_passed
            && self.valid_chunked_baseline_passed
            && self.valid_close_delimited_baseline_passed
            && self.valid_head_nonzero_length_baseline_passed
            && self.valid_not_modified_nonzero_length_baseline_passed
            && self.valid_no_content_baseline_passed
            && self.valid_reset_content_zero_length_baseline_passed
            && usize::try_from(self.cases_attempted) == Ok(MALFORMED_RESPONSE_BODY_CASES)
            && self.bounded_terminations == self.cases_attempted
            && self.upstream_requests_with_valid_secret == self.cases_attempted + 7
            && self.second_downstream_requests_attempted == self.cases_attempted + 7
            && self.downstream_connections_physically_closed == self.cases_attempted + 7
            && self.second_downstream_responses == 0
            && self.attacker_markers_forwarded == 0
            && self.reusable_downstream_responses == 0
            && self.exact_bad_gateway_responses == 6
            && self.stream_fail_closed_terminations == 12
            && self.close_delimited_limit_terminations == 1
            && self.bodyless_status_terminations == 2
            && self.isolated_complete_responses == 2
            && self.exact_bad_gateway_responses
                + self.stream_fail_closed_terminations
                + self.close_delimited_limit_terminations
                + self.bodyless_status_terminations
                + self.isolated_complete_responses
                == self.cases_attempted
            && self.cases.len() == MALFORMED_RESPONSE_BODY_CASES
            && MALFORMED_RESPONSE_BODY_CASE_NAMES
                .iter()
                .all(|name| self.cases.get(*name) == Some(&true))
    }
}

/// Exercise valid and hostile upstream response bodies over real loopback
/// sockets and the production ordinary-HTTP forwarding path.
///
/// # Errors
///
/// Returns an I/O error if a loopback socket cannot be created, a raw upstream
/// task fails, or an isolated proxy cannot start or shut down.
pub async fn probe_malformed_upstream_response_bodies() -> io::Result<MalformedUpstreamBodyEvidence>
{
    let mut evidence = MalformedUpstreamBodyEvidence::default();
    let mut cases = valid_response_body_cases();
    cases.extend(malformed_response_body_cases());

    for (index, case) in cases.into_iter().enumerate() {
        let result = run_raw_body_case(index, case).await?;
        if result.valid_secret {
            evidence.upstream_requests_with_valid_secret += 1;
        }
        if result.downstream.second_request_attempted {
            evidence.second_downstream_requests_attempted += 1;
        }
        if result.downstream.physical_closed {
            evidence.downstream_connections_physically_closed += 1;
        }
        if result.downstream.second_response_received {
            evidence.second_downstream_responses += 1;
        }
        if result.negative {
            record_negative_body_result(&mut evidence, &result);
        } else {
            record_valid_body_result(&mut evidence, &result);
        }
    }

    evidence.probe_completed = true;
    Ok(evidence)
}

fn record_valid_body_result(
    evidence: &mut MalformedUpstreamBodyEvidence,
    result: &RawBodyProbeResult,
) {
    let passed = body_probe_connection_is_closed(result)
        && match result.name {
            "valid_head_nonzero_length" => {
                valid_downstream_no_body(&result.downstream.response, "HTTP/1.1 200 OK", "4096")
            }
            "valid_not_modified_nonzero_length" => valid_downstream_no_body(
                &result.downstream.response,
                "HTTP/1.1 304 Not Modified",
                "4096",
            ),
            "valid_no_content" => valid_downstream_bodyless_status(
                &result.downstream.response,
                "HTTP/1.1 204 No Content",
            ),
            "valid_reset_content_zero_length" => valid_downstream_no_body(
                &result.downstream.response,
                "HTTP/1.1 205 Reset Content",
                "0",
            ),
            _ => valid_downstream_http_body(&result.downstream.response, result.expected_body),
        };
    match result.name {
        "valid_content_length_body" => {
            evidence.valid_content_length_baseline_passed = passed;
        }
        "valid_chunked_body" => {
            evidence.valid_chunked_baseline_passed = passed;
        }
        "valid_close_delimited_body" => {
            evidence.valid_close_delimited_baseline_passed = passed;
        }
        "valid_head_nonzero_length" => {
            evidence.valid_head_nonzero_length_baseline_passed = passed;
        }
        "valid_not_modified_nonzero_length" => {
            evidence.valid_not_modified_nonzero_length_baseline_passed = passed;
        }
        "valid_no_content" => {
            evidence.valid_no_content_baseline_passed = passed;
        }
        "valid_reset_content_zero_length" => {
            evidence.valid_reset_content_zero_length_baseline_passed = passed;
        }
        _ => {}
    }
}

fn record_negative_body_result(
    evidence: &mut MalformedUpstreamBodyEvidence,
    result: &RawBodyProbeResult,
) {
    evidence.cases_attempted += 1;
    if result.downstream.physical_closed {
        evidence.bounded_terminations += 1;
    }
    let marker_forwarded = result
        .downstream
        .response
        .windows(MALFORMED_RESPONSE_MARKER.len())
        .any(|window| window == MALFORMED_RESPONSE_MARKER);
    if marker_forwarded {
        evidence.attacker_markers_forwarded += 1;
    }
    let connection_closes = body_probe_connection_is_closed(result);
    if !connection_closes {
        evidence.reusable_downstream_responses += 1;
    }

    let outcome_passed = match result.expectation {
        RawBodyExpectation::ExactBadGateway => {
            let passed = is_exact_fixed_bad_gateway(&result.downstream.response);
            if passed {
                evidence.exact_bad_gateway_responses += 1;
            }
            passed
        }
        RawBodyExpectation::StreamFailClosed => {
            let passed = downstream_stream_failure_fail_closed(&result.downstream.response);
            if passed {
                evidence.stream_fail_closed_terminations += 1;
            }
            passed
        }
        RawBodyExpectation::CloseDelimitedLimit => {
            let passed =
                valid_downstream_http_body(&result.downstream.response, result.expected_body);
            if passed {
                evidence.close_delimited_limit_terminations += 1;
            }
            passed
        }
        RawBodyExpectation::BodylessStatus(status) => {
            let passed = valid_downstream_bodyless_status(&result.downstream.response, status);
            if passed {
                evidence.bodyless_status_terminations += 1;
            }
            passed
        }
        RawBodyExpectation::IsolatedComplete => {
            let passed =
                valid_downstream_http_body(&result.downstream.response, result.expected_body);
            if passed {
                evidence.isolated_complete_responses += 1;
            }
            passed
        }
    };
    let passed = connection_closes && !marker_forwarded && outcome_passed;
    evidence.cases.insert(result.name.to_owned(), passed);
}

fn body_probe_connection_is_closed(result: &RawBodyProbeResult) -> bool {
    result.downstream.second_request_attempted
        && result.downstream.physical_closed
        && !result.downstream.second_response_received
        && downstream_connection_closes(&result.downstream.response)
}

/// Exercise malformed upstream response heads through real loopback sockets
/// and both production proxy forwarding paths.
///
/// Ordinary cases cover conflicting framing, invalid transfer codings,
/// obsolete folding, invalid field syntax, response-head limits, ambiguous
/// hop-by-hop fields, protected connection nominations, ambiguous redirects,
/// unsafe cookies, and an unsolicited protocol switch. WebSocket cases cover
/// raw syntax and limits plus framing forbidden on `101`, ambiguous or
/// incorrect handshake fields, unoffered negotiation, extensions, and
/// protected connection nominations. Each negative response must become the
/// exact fixed `502`, must not switch the downstream connection, and must not
/// forward an attacker-controlled header canary or WebSocket frame.
///
/// # Errors
///
/// Returns an I/O error if a loopback socket cannot be created, a raw upstream
/// task fails, or an isolated proxy cannot start or shut down.
pub async fn probe_malformed_upstream_response_heads() -> io::Result<MalformedUpstreamEvidence> {
    let mut evidence = MalformedUpstreamEvidence::default();
    let mut cases = Vec::with_capacity(MALFORMED_RESPONSE_CASES + 2);
    cases.push(RawUpstreamCase {
        name: "valid_http_baseline",
        response: b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\nConnection: close\r\n\r\nsafe-baseline"
            .to_vec(),
        negative: false,
        kind: RawProbeKind::Http,
    });
    cases.extend(malformed_response_cases());
    cases.push(RawUpstreamCase {
        name: "valid_websocket_baseline",
        response: raw_response(
            "101 Switching Protocols",
            &[
                WEBSOCKET_CONNECTION_HEADER,
                WEBSOCKET_UPGRADE_HEADER,
                WEBSOCKET_ACCEPT_HEADER,
            ],
            SAFE_WEBSOCKET_FRAME,
        ),
        negative: false,
        kind: RawProbeKind::WebSocket,
    });
    cases.extend(malformed_websocket_response_cases());

    for (index, case) in cases.into_iter().enumerate() {
        let RawProbeResult {
            name,
            negative,
            kind,
            response,
            observation,
        } = run_raw_upstream_case(index, case).await?;
        if observation.valid_secret {
            evidence.upstream_requests_with_valid_secret += 1;
        }
        if observation.valid_websocket_request {
            evidence.upstream_websocket_requests_valid += 1;
        }

        match (negative, kind, response) {
            (false, RawProbeKind::Http, Ok(response)) => {
                evidence.valid_baseline_passed = valid_http_baseline(&response);
            }
            (false, RawProbeKind::WebSocket, Ok(response)) => {
                evidence.valid_websocket_baseline_passed = valid_websocket_baseline(&response);
            }
            (true, kind, Ok(response)) => {
                evidence.cases_attempted += 1;
                match kind {
                    RawProbeKind::Http => evidence.http_cases_attempted += 1,
                    RawProbeKind::WebSocket => evidence.websocket_cases_attempted += 1,
                }
                let marker_forwarded = response
                    .windows(MALFORMED_RESPONSE_MARKER.len())
                    .any(|window| window == MALFORMED_RESPONSE_MARKER);
                if marker_forwarded {
                    evidence.attacker_markers_forwarded += 1;
                }
                let switched_protocols =
                    kind == RawProbeKind::WebSocket && downstream_switched_protocols(&response);
                if switched_protocols {
                    evidence.unexpected_downstream_upgrades += 1;
                }
                let passed = is_exact_fixed_bad_gateway(&response)
                    && !marker_forwarded
                    && !switched_protocols;
                if passed {
                    evidence.fail_closed_responses += 1;
                    match kind {
                        RawProbeKind::Http => evidence.http_fail_closed_responses += 1,
                        RawProbeKind::WebSocket => {
                            evidence.websocket_fail_closed_responses += 1;
                        }
                    }
                }
                evidence.cases.insert(name.to_owned(), passed);
            }
            (true, kind, Err(_)) => {
                evidence.cases_attempted += 1;
                match kind {
                    RawProbeKind::Http => evidence.http_cases_attempted += 1,
                    RawProbeKind::WebSocket => evidence.websocket_cases_attempted += 1,
                }
                evidence.cases.insert(name.to_owned(), false);
            }
            (false, _, Err(_)) => {}
        }
    }
    evidence.probe_completed = true;
    Ok(evidence)
}

async fn run_raw_upstream_case(index: usize, case: RawUpstreamCase) -> io::Result<RawProbeResult> {
    let RawUpstreamCase {
        name,
        response,
        negative,
        kind,
    } = case;
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    let upstream_address = listener.local_addr()?;
    let byte = u8::try_from(index + 16)
        .map_err(|_| io::Error::other("malformed response case index overflow"))?;
    let session = Arc::new(Secret::from_bytes([byte; 32]));
    let upstream = Arc::new(Secret::from_bytes([byte.wrapping_add(1); 32]));
    let bootstrap = Arc::new(Secret::from_bytes([byte.wrapping_add(2); 32]));
    let server_secret = Arc::clone(&upstream);
    let server = tokio::spawn(async move {
        serve_one_raw_upstream_response(listener, server_secret, upstream_address, kind, response)
            .await
            .map_err(|error| io::Error::new(error.kind(), format!("{name}: {error}")))
    });
    let hostname = format!("rpackit-{}.localhost", hex::encode([byte; 16]));
    let config = ProxyConfig::explicit(
        upstream_address,
        hostname,
        TransportSecrets::new(Arc::clone(&session), upstream, bootstrap),
    )
    .map_err(io::Error::other)?;
    let proxy = RunningProxy::start(config)
        .await
        .map_err(io::Error::other)?;
    let response = request_authenticated_probe(&proxy, &session, kind, negative).await;
    proxy.shutdown().await.map_err(io::Error::other)?;
    let observation = server
        .await
        .map_err(|_| io::Error::other("raw upstream task terminated"))??;
    Ok(RawProbeResult {
        name,
        negative,
        kind,
        response,
        observation,
    })
}

#[derive(Clone, Copy)]
enum RawBodyExpectation {
    ExactBadGateway,
    StreamFailClosed,
    CloseDelimitedLimit,
    BodylessStatus(&'static str),
    IsolatedComplete,
}

struct RawBodyCase {
    name: &'static str,
    request_method: &'static str,
    fragments: Vec<Vec<u8>>,
    negative: bool,
    expectation: RawBodyExpectation,
    expected_body: &'static [u8],
    max_response_body_bytes: usize,
}

struct RawBodyProbeResult {
    name: &'static str,
    negative: bool,
    expectation: RawBodyExpectation,
    expected_body: &'static [u8],
    downstream: BodyClientObservation,
    valid_secret: bool,
}

async fn run_raw_body_case(index: usize, case: RawBodyCase) -> io::Result<RawBodyProbeResult> {
    let RawBodyCase {
        name,
        request_method,
        fragments,
        negative,
        expectation,
        expected_body,
        max_response_body_bytes,
    } = case;
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    let upstream_address = listener.local_addr()?;
    let byte = u8::try_from(index + 96)
        .map_err(|_| io::Error::other("malformed body case index overflow"))?;
    let session = Arc::new(Secret::from_bytes([byte; 32]));
    let upstream = Arc::new(Secret::from_bytes([byte.wrapping_add(1); 32]));
    let bootstrap = Arc::new(Secret::from_bytes([byte.wrapping_add(2); 32]));
    let server_secret = Arc::clone(&upstream);
    let server = tokio::spawn(async move {
        serve_one_raw_upstream_body(listener, server_secret, fragments)
            .await
            .map_err(|error| io::Error::new(error.kind(), format!("{name}: {error}")))
    });
    let hostname = format!("rpackit-{}.localhost", hex::encode([byte; 16]));
    let limits = TransportLimits {
        max_response_body_bytes,
        ..TransportLimits::default()
    };
    let config = ProxyConfig::explicit(
        upstream_address,
        hostname,
        TransportSecrets::new(Arc::clone(&session), upstream, bootstrap),
    )
    .map_err(io::Error::other)?
    .with_limits(limits);
    let proxy = RunningProxy::start(config)
        .await
        .map_err(io::Error::other)?;
    let client = request_authenticated_body_probe(&proxy, &session, request_method).await?;
    proxy.shutdown().await.map_err(io::Error::other)?;
    let valid_secret = server
        .await
        .map_err(|_| io::Error::other("raw upstream body task terminated"))??;
    Ok(RawBodyProbeResult {
        name,
        negative,
        expectation,
        expected_body,
        downstream: client,
        valid_secret,
    })
}

async fn serve_one_raw_upstream_body(
    listener: TcpListener,
    expected_secret: Arc<Secret>,
    fragments: Vec<Vec<u8>>,
) -> io::Result<bool> {
    let (mut socket, peer) = timeout(Duration::from_secs(2), listener.accept())
        .await
        .map_err(|_| io::Error::other("raw upstream body accept timed out"))??;
    if !peer.ip().is_loopback() {
        return Err(io::Error::other(
            "raw upstream body received a non-loopback peer",
        ));
    }
    let request = read_bounded_header(&mut socket).await?;
    let valid_secret =
        single_header_matches(&request, b"shiny-shared-secret", expected_secret.as_ref());
    for fragment in fragments {
        if socket.write_all(&fragment).await.is_err() {
            break;
        }
        tokio::task::yield_now().await;
    }
    let _ = socket.shutdown().await;
    Ok(valid_secret)
}

struct BodyClientObservation {
    response: Vec<u8>,
    physical_closed: bool,
    second_request_attempted: bool,
    second_response_received: bool,
}

async fn request_authenticated_body_probe(
    proxy: &RunningProxy,
    session: &Secret,
    method: &str,
) -> io::Result<BodyClientObservation> {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), proxy.address().port());
    let (request, second_request) = session.with_exposed(|value| {
        let authority = proxy.address().authority();
        (
            format!(
                "{method} /malformed-upstream-body-probe HTTP/1.1\r\nHost: {authority}\r\nCookie: {SESSION_COOKIE_NAME}={value}\r\nConnection: keep-alive\r\n\r\n"
            ),
            format!(
                "GET /malformed-upstream-body-probe-second HTTP/1.1\r\nHost: {authority}\r\nCookie: {SESSION_COOKIE_NAME}={value}\r\nConnection: keep-alive\r\n\r\n"
            ),
        )
    });
    let mut socket = TcpStream::connect(address).await?;
    socket.write_all(request.as_bytes()).await?;
    let mut response = Vec::with_capacity(1024);
    let mut physical_closed = false;
    let mut second_request_attempted = false;
    let _bounded = matches!(
        timeout(Duration::from_secs(3), async {
            let mut buffer = [0_u8; 4096];
            loop {
                if response.len() >= 512 * 1024 {
                    return Err(io::Error::other(
                        "downstream body probe exceeded response limit",
                    ));
                }
                if !second_request_attempted
                    && response.windows(4).any(|window| window == b"\r\n\r\n")
                {
                    second_request_attempted = true;
                    let _ = socket.write_all(second_request.as_bytes()).await;
                }
                match socket.read(&mut buffer).await {
                    Ok(0) | Err(_) => {
                        physical_closed = true;
                        if !second_request_attempted {
                            second_request_attempted = true;
                            let _ = socket.write_all(second_request.as_bytes()).await;
                        }
                        return Ok(());
                    }
                    Ok(read) => response.extend_from_slice(&buffer[..read]),
                }
            }
        })
        .await,
        Ok(Ok(()))
    );
    if !second_request_attempted {
        second_request_attempted = true;
        let _ = timeout(
            Duration::from_secs(1),
            socket.write_all(second_request.as_bytes()),
        )
        .await;
    }
    let second_response_received = raw_http_response_count(&response) > 1;
    Ok(BodyClientObservation {
        response,
        physical_closed,
        second_request_attempted,
        second_response_received,
    })
}

fn valid_response_body_cases() -> Vec<RawBodyCase> {
    const FIXED_BODY: &[u8] = b"safe-content-length";
    const CHUNKED_BODY: &[u8] = b"safe-chunked-body";
    const CLOSE_BODY: &[u8] = b"safe-close-body";

    let fixed = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        FIXED_BODY.len(),
        String::from_utf8_lossy(FIXED_BODY)
    )
    .into_bytes();
    let chunked = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nsafe\r\n8\r\n-chunked\r\n5\r\n-body\r\n0\r\n\r\n"
        .to_vec();
    let close =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nsafe-close-body"
            .to_vec();
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n".to_vec();
    let not_modified =
        b"HTTP/1.1 304 Not Modified\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n".to_vec();
    let no_content = b"HTTP/1.1 204 No Content\r\n\r\n".to_vec();
    let reset_content =
        b"HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();

    vec![
        RawBodyCase {
            name: "valid_content_length_body",
            request_method: "GET",
            fragments: split_wire(&fixed, 3),
            negative: false,
            expectation: RawBodyExpectation::IsolatedComplete,
            expected_body: FIXED_BODY,
            max_response_body_bytes: 1024,
        },
        RawBodyCase {
            name: "valid_chunked_body",
            request_method: "GET",
            fragments: split_wire(&chunked, 2),
            negative: false,
            expectation: RawBodyExpectation::IsolatedComplete,
            expected_body: CHUNKED_BODY,
            max_response_body_bytes: 1024,
        },
        RawBodyCase {
            name: "valid_close_delimited_body",
            request_method: "GET",
            fragments: split_wire(&close, 5),
            negative: false,
            expectation: RawBodyExpectation::IsolatedComplete,
            expected_body: CLOSE_BODY,
            max_response_body_bytes: 1024,
        },
        RawBodyCase {
            name: "valid_head_nonzero_length",
            request_method: "HEAD",
            fragments: split_wire(&head, 3),
            negative: false,
            expectation: RawBodyExpectation::IsolatedComplete,
            expected_body: b"",
            max_response_body_bytes: 8,
        },
        RawBodyCase {
            name: "valid_not_modified_nonzero_length",
            request_method: "GET",
            fragments: split_wire(&not_modified, 3),
            negative: false,
            expectation: RawBodyExpectation::IsolatedComplete,
            expected_body: b"",
            max_response_body_bytes: 8,
        },
        RawBodyCase {
            name: "valid_no_content",
            request_method: "GET",
            fragments: split_wire(&no_content, 3),
            negative: false,
            expectation: RawBodyExpectation::IsolatedComplete,
            expected_body: b"",
            max_response_body_bytes: 8,
        },
        RawBodyCase {
            name: "valid_reset_content_zero_length",
            request_method: "GET",
            fragments: split_wire(&reset_content, 3),
            negative: false,
            expectation: RawBodyExpectation::IsolatedComplete,
            expected_body: b"",
            max_response_body_bytes: 8,
        },
    ]
}

#[allow(clippy::too_many_lines)]
fn malformed_response_body_cases() -> Vec<RawBodyCase> {
    let case = |name, response: Vec<u8>, expectation, expected_body, max_response_body_bytes| {
        RawBodyCase {
            name,
            request_method: "GET",
            fragments: split_wire(&response, 7),
            negative: true,
            expectation,
            expected_body,
            max_response_body_bytes,
        }
    };
    let mut oversized_trailer =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nsafe\r\n0\r\nX-Oversized: "
            .to_vec();
    oversized_trailer.extend(std::iter::repeat_n(b'a', 33 * 1024));
    oversized_trailer.extend_from_slice(MALFORMED_RESPONSE_MARKER);
    oversized_trailer.extend_from_slice(b"\r\n\r\n");
    let mut too_many_trailers =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nsafe\r\n0\r\n"
            .to_vec();
    for _ in 0..TransportLimits::default().max_headers {
        too_many_trailers.extend_from_slice(b"X-Filler: a\r\n");
    }
    too_many_trailers.extend_from_slice(
        format!("X-Rpackit-Attacker-Canary: {MALFORMED_RESPONSE_MARKER_TEXT}\r\n\r\n").as_bytes(),
    );

    vec![
        case(
            "declared_length_over_limit",
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: close\r\n\r\n{MALFORMED_RESPONSE_MARKER_TEXT}"
            )
            .into_bytes(),
            RawBodyExpectation::ExactBadGateway,
            b"",
            8,
        ),
        case(
            "declared_trailer",
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Rpackit-Attacker-Canary\r\nConnection: close\r\n\r\n0\r\nX-Rpackit-Attacker-Canary: {MALFORMED_RESPONSE_MARKER_TEXT}\r\n\r\n"
            )
            .into_bytes(),
            RawBodyExpectation::ExactBadGateway,
            b"",
            1024,
        ),
        case(
            "no_content_content_length",
            format!(
                "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n{MALFORMED_RESPONSE_MARKER_TEXT}"
            )
            .into_bytes(),
            RawBodyExpectation::ExactBadGateway,
            b"",
            1024,
        ),
        case(
            "no_content_transfer_encoding",
            format!(
                "HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n{MALFORMED_RESPONSE_MARKER_TEXT}"
            )
            .into_bytes(),
            RawBodyExpectation::ExactBadGateway,
            b"",
            1024,
        ),
        case(
            "reset_content_nonzero_length",
            format!(
                "HTTP/1.1 205 Reset Content\r\nContent-Length: 1\r\n\r\n{MALFORMED_RESPONSE_MARKER_TEXT}"
            )
            .into_bytes(),
            RawBodyExpectation::ExactBadGateway,
            b"",
            1024,
        ),
        case(
            "reset_content_transfer_encoding",
            format!(
                "HTTP/1.1 205 Reset Content\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n{MALFORMED_RESPONSE_MARKER_TEXT}"
            )
            .into_bytes(),
            RawBodyExpectation::ExactBadGateway,
            b"",
            1024,
        ),
        case(
            "truncated_content_length_empty",
            b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\n".to_vec(),
            RawBodyExpectation::StreamFailClosed,
            b"",
            1024,
        ),
        case(
            "truncated_content_length_partial",
            b"HTTP/1.1 200 OK\r\nContent-Length: 32\r\nConnection: close\r\n\r\nsafe-prefix"
                .to_vec(),
            RawBodyExpectation::StreamFailClosed,
            b"",
            1024,
        ),
        case(
            "invalid_chunk_size",
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nnot-hex\r\n{MALFORMED_RESPONSE_MARKER_TEXT}\r\n0\r\n\r\n"
            )
            .into_bytes(),
            RawBodyExpectation::StreamFailClosed,
            b"",
            1024,
        ),
        case(
            "overflowing_chunk_size",
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nFFFFFFFFFFFFFFFFF\r\n{MALFORMED_RESPONSE_MARKER_TEXT}\r\n"
            )
            .into_bytes(),
            RawBodyExpectation::StreamFailClosed,
            b"",
            1024,
        ),
        case(
            "truncated_chunk_data",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n20\r\nsafe-prefix"
                .to_vec(),
            RawBodyExpectation::StreamFailClosed,
            b"",
            1024,
        ),
        case(
            "missing_chunk_data_crlf",
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nsafeX\r\n{MALFORMED_RESPONSE_MARKER_TEXT}\r\n0\r\n\r\n"
            )
            .into_bytes(),
            RawBodyExpectation::StreamFailClosed,
            b"",
            1024,
        ),
        case(
            "missing_terminal_chunk",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nsafe\r\n"
                .to_vec(),
            RawBodyExpectation::StreamFailClosed,
            b"",
            1024,
        ),
        case(
            "malformed_trailer",
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nsafe\r\n0\r\nBad Trailer: {MALFORMED_RESPONSE_MARKER_TEXT}\r\n\r\n"
            )
            .into_bytes(),
            RawBodyExpectation::StreamFailClosed,
            b"",
            1024,
        ),
        case(
            "protected_trailer",
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nsafe\r\n0\r\nShiny-Shared-Secret: {MALFORMED_RESPONSE_MARKER_TEXT}\r\n\r\n"
            )
            .into_bytes(),
            RawBodyExpectation::StreamFailClosed,
            b"",
            1024,
        ),
        case(
            "oversized_trailer",
            oversized_trailer,
            RawBodyExpectation::StreamFailClosed,
            b"",
            64 * 1024,
        ),
        case(
            "too_many_trailers",
            too_many_trailers,
            RawBodyExpectation::StreamFailClosed,
            b"",
            64 * 1024,
        ),
        case(
            "chunked_body_over_limit",
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nsafe\r\n{:x}\r\n{MALFORMED_RESPONSE_MARKER_TEXT}\r\n0\r\n\r\n",
                MALFORMED_RESPONSE_MARKER.len()
            )
            .into_bytes(),
            RawBodyExpectation::StreamFailClosed,
            b"",
            4,
        ),
        case(
            "close_delimited_body_over_limit",
            format!(
                "HTTP/1.1 200 OK\r\n\r\n{MALFORMED_RESPONSE_MARKER_TEXT}"
            )
            .into_bytes(),
            RawBodyExpectation::CloseDelimitedLimit,
            b"",
            0,
        ),
        case(
            "no_content_malicious_body",
            format!("HTTP/1.1 204 No Content\r\n\r\n{MALFORMED_RESPONSE_MARKER_TEXT}")
                .into_bytes(),
            RawBodyExpectation::BodylessStatus("HTTP/1.1 204 No Content"),
            b"",
            1024,
        ),
        case(
            "reset_content_close_delimited_body",
            format!(
                "HTTP/1.1 205 Reset Content\r\n\r\n{MALFORMED_RESPONSE_MARKER_TEXT}"
            )
            .into_bytes(),
            RawBodyExpectation::BodylessStatus("HTTP/1.1 205 Reset Content"),
            b"",
            1024,
        ),
        case(
            "bytes_after_terminal_chunk",
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nsafe\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{MALFORMED_RESPONSE_MARKER_TEXT}",
                MALFORMED_RESPONSE_MARKER.len()
            )
            .into_bytes(),
            RawBodyExpectation::IsolatedComplete,
            b"safe",
            1024,
        ),
        case(
            "bytes_after_content_length",
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nsafeHTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{MALFORMED_RESPONSE_MARKER_TEXT}",
                MALFORMED_RESPONSE_MARKER.len()
            )
            .into_bytes(),
            RawBodyExpectation::IsolatedComplete,
            b"safe",
            1024,
        ),
    ]
}

fn split_wire(wire: &[u8], fragment_size: usize) -> Vec<Vec<u8>> {
    wire.chunks(fragment_size).map(<[u8]>::to_vec).collect()
}

fn raw_http_response_count(response: &[u8]) -> usize {
    response
        .windows(b"HTTP/1.1 ".len())
        .filter(|window| *window == b"HTTP/1.1 ")
        .count()
}

fn parse_raw_response(response: &[u8]) -> Option<(&str, BTreeMap<String, String>, &[u8])> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)?;
    let head = std::str::from_utf8(&response[..header_end - 4]).ok()?;
    let mut lines = head.split("\r\n");
    let status = lines.next()?;
    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() || line.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
            return None;
        }
        let (name, value) = line.split_once(':')?;
        if name.is_empty()
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
        {
            return None;
        }
        if headers
            .insert(name.to_ascii_lowercase(), value.trim_ascii().to_owned())
            .is_some()
        {
            return None;
        }
    }
    Some((status, headers, &response[header_end..]))
}

fn valid_downstream_http_body(response: &[u8], expected_body: &[u8]) -> bool {
    let Some((status, headers, wire_body)) = parse_raw_response(response) else {
        return false;
    };
    status == "HTTP/1.1 200 OK"
        && downstream_connection_header_closes(&headers)
        && decode_downstream_body(&headers, wire_body).as_deref() == Some(expected_body)
}

fn valid_downstream_no_body(
    response: &[u8],
    expected_status: &str,
    expected_content_length: &str,
) -> bool {
    let Some((status, headers, wire_body)) = parse_raw_response(response) else {
        return false;
    };
    status == expected_status
        && downstream_connection_header_closes(&headers)
        && headers
            .get("content-length")
            .is_some_and(|length| length == expected_content_length)
        && !headers.contains_key("transfer-encoding")
        && wire_body.is_empty()
}

fn valid_downstream_bodyless_status(response: &[u8], expected_status: &str) -> bool {
    let Some((status, headers, wire_body)) = parse_raw_response(response) else {
        return false;
    };
    status == expected_status
        && downstream_connection_header_closes(&headers)
        && headers
            .get("content-length")
            .is_none_or(|length| length == "0")
        && !headers.contains_key("transfer-encoding")
        && wire_body.is_empty()
}

fn downstream_connection_closes(response: &[u8]) -> bool {
    if response.is_empty() {
        return true;
    }
    parse_raw_response(response)
        .is_none_or(|(_, headers, _)| downstream_connection_header_closes(&headers))
}

fn downstream_connection_header_closes(headers: &BTreeMap<String, String>) -> bool {
    headers.get("connection").is_some_and(|value| {
        value
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("close"))
    })
}

fn downstream_stream_failure_fail_closed(response: &[u8]) -> bool {
    if response.is_empty() {
        return true;
    }
    let Some((status, headers, wire_body)) = parse_raw_response(response) else {
        return true;
    };
    if status != "HTTP/1.1 200 OK" || !downstream_connection_header_closes(&headers) {
        return false;
    }
    decode_downstream_body(&headers, wire_body).is_none()
}

fn decode_downstream_body(headers: &BTreeMap<String, String>, wire_body: &[u8]) -> Option<Vec<u8>> {
    match (
        headers.get("content-length"),
        headers.get("transfer-encoding"),
    ) {
        (Some(length), None) => {
            let length = length.parse::<usize>().ok()?;
            (wire_body.len() == length).then(|| wire_body.to_vec())
        }
        (None, Some(encoding)) if encoding.eq_ignore_ascii_case("chunked") => {
            decode_chunked_body(wire_body)
        }
        (Some(_) | None, Some(_)) => None,
        (None, None) => Some(wire_body.to_vec()),
    }
}

fn decode_chunked_body(mut wire: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let line_end = wire.windows(2).position(|window| window == b"\r\n")?;
        let size_text = std::str::from_utf8(&wire[..line_end]).ok()?;
        if size_text.is_empty() || size_text.contains(';') {
            return None;
        }
        let size = usize::from_str_radix(size_text, 16).ok()?;
        wire = &wire[line_end + 2..];
        if size == 0 {
            return (wire == b"\r\n").then_some(decoded);
        }
        if wire.len() < size + 2 || &wire[size..size + 2] != b"\r\n" {
            return None;
        }
        decoded.extend_from_slice(&wire[..size]);
        wire = &wire[size + 2..];
    }
}

fn headers_match_exact(headers: &BTreeMap<String, String>, expected: &[(&str, &str)]) -> bool {
    headers.len() == expected.len()
        && expected
            .iter()
            .all(|(name, value)| headers.get(*name).is_some_and(|actual| actual == value))
}

fn is_exact_fixed_bad_gateway(response: &[u8]) -> bool {
    let Some((status, headers, body)) = parse_raw_response(response) else {
        return false;
    };
    status == "HTTP/1.1 502 Bad Gateway"
        && headers_match_exact(
            &headers,
            &[
                ("cache-control", "no-store"),
                ("connection", "close"),
                ("content-length", "17"),
                ("content-type", "text/plain; charset=utf-8"),
            ],
        )
        && body == b"Upstream rejected"
}

fn valid_http_baseline(response: &[u8]) -> bool {
    let Some((status, headers, body)) = parse_raw_response(response) else {
        return false;
    };
    status == "HTTP/1.1 200 OK"
        && headers_match_exact(
            &headers,
            &[
                ("connection", "close"),
                ("content-length", "13"),
                ("content-type", "text/plain"),
            ],
        )
        && body == b"safe-baseline"
}

fn valid_websocket_baseline(response: &[u8]) -> bool {
    let Some((status, headers, bytes_after_head)) = parse_raw_response(response) else {
        return false;
    };
    status == "HTTP/1.1 101 Switching Protocols"
        && headers_match_exact(
            &headers,
            &[
                ("connection", "Upgrade"),
                ("sec-websocket-accept", WEBSOCKET_ACCEPT),
                ("upgrade", "websocket"),
            ],
        )
        && bytes_after_head == SAFE_WEBSOCKET_FRAME
}

fn downstream_switched_protocols(response: &[u8]) -> bool {
    response.starts_with(b"HTTP/1.1 101 ")
}

#[cfg(test)]
mod response_oracle_tests {
    use super::*;

    #[test]
    fn fixed_bad_gateway_requires_the_exact_static_header_set() {
        let exact = b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: 17\r\n\r\nUpstream rejected";
        assert!(is_exact_fixed_bad_gateway(exact));

        let attacker_header = b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: 17\r\nX-Rpackit-Attacker-Canary: rpackit-malformed-upstream-marker\r\n\r\nUpstream rejected";
        assert!(!is_exact_fixed_bad_gateway(attacker_header));

        let dynamic_date = b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: 17\r\nDate: Sun, 26 Jul 2026 00:00:00 GMT\r\n\r\nUpstream rejected";
        assert!(!is_exact_fixed_bad_gateway(dynamic_date));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RawProbeKind {
    Http,
    WebSocket,
}

struct RawUpstreamCase {
    name: &'static str,
    response: Vec<u8>,
    negative: bool,
    kind: RawProbeKind,
}

struct RawUpstreamObservation {
    valid_secret: bool,
    valid_websocket_request: bool,
}

struct RawProbeResult {
    name: &'static str,
    negative: bool,
    kind: RawProbeKind,
    response: io::Result<Vec<u8>>,
    observation: RawUpstreamObservation,
}

fn malformed_response_cases() -> Vec<RawUpstreamCase> {
    let fixed = |name, response: &'static [u8]| RawUpstreamCase {
        name,
        response: response.to_vec(),
        negative: true,
        kind: RawProbeKind::Http,
    };
    let mut oversized =
        b"HTTP/1.1 200 OK\r\nX-Oversized: rpackit-malformed-upstream-marker".to_vec();
    oversized.extend(std::iter::repeat_n(b'a', 33 * 1024));
    oversized.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
    let mut too_many_headers = format!(
        "HTTP/1.1 200 OK\r\n{}: {}\r\n",
        ATTACKER_CANARY_HEADER.0, ATTACKER_CANARY_HEADER.1
    )
    .into_bytes();
    for _ in 0..97 {
        too_many_headers.extend_from_slice(b"X-Filler: a\r\n");
    }
    too_many_headers.extend_from_slice(b"Content-Length: 0\r\n\r\n");

    vec![
        fixed(
            "conflicting_content_length",
            b"HTTP/1.1 200 OK\r\nX-Rpackit-Attacker-Canary: rpackit-malformed-upstream-marker\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\nrpackit-malformed-upstream-marker",
        ),
        fixed(
            "content_length_and_transfer_encoding",
            b"HTTP/1.1 200 OK\r\nX-Rpackit-Attacker-Canary: rpackit-malformed-upstream-marker\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nrpackit-malformed-upstream-marker",
        ),
        fixed(
            "unsupported_transfer_encoding",
            b"HTTP/1.1 200 OK\r\nX-Rpackit-Attacker-Canary: rpackit-malformed-upstream-marker\r\nTransfer-Encoding: gzip\r\n\r\nrpackit-malformed-upstream-marker",
        ),
        fixed(
            "chunked_not_final",
            b"HTTP/1.1 200 OK\r\nX-Rpackit-Attacker-Canary: rpackit-malformed-upstream-marker\r\nTransfer-Encoding: chunked, gzip\r\n\r\nrpackit-malformed-upstream-marker",
        ),
        fixed(
            "obsolete_header_folding",
            b"HTTP/1.1 200 OK\r\nX-Rpackit-Attacker-Canary: rpackit-malformed-upstream-marker\r\nX-Test: accepted\r\n folded\r\nContent-Length: 0\r\n\r\nrpackit-malformed-upstream-marker",
        ),
        fixed(
            "whitespace_before_colon",
            b"HTTP/1.1 200 OK\r\nX-Rpackit-Attacker-Canary: rpackit-malformed-upstream-marker\r\nX-Test : accepted\r\nContent-Length: 0\r\n\r\nrpackit-malformed-upstream-marker",
        ),
        fixed(
            "invalid_header_name",
            b"HTTP/1.1 200 OK\r\nX-Rpackit-Attacker-Canary: rpackit-malformed-upstream-marker\r\nBad Header: accepted\r\nContent-Length: 0\r\n\r\nrpackit-malformed-upstream-marker",
        ),
        fixed(
            "bare_line_feeds",
            b"HTTP/1.1 200 OK\nX-Rpackit-Attacker-Canary: rpackit-malformed-upstream-marker\nContent-Length: 0\n\nrpackit-malformed-upstream-marker",
        ),
        fixed(
            "invalid_status_code",
            b"HTTP/1.1 099 Invalid\r\nX-Rpackit-Attacker-Canary: rpackit-malformed-upstream-marker\r\nContent-Length: 0\r\n\r\nrpackit-malformed-upstream-marker",
        ),
        RawUpstreamCase {
            name: "oversized_response_head",
            response: oversized,
            negative: true,
            kind: RawProbeKind::Http,
        },
        RawUpstreamCase {
            name: "too_many_headers",
            response: too_many_headers,
            negative: true,
            kind: RawProbeKind::Http,
        },
        fixed(
            "duplicate_connection",
            b"HTTP/1.1 200 OK\r\nX-Rpackit-Attacker-Canary: rpackit-malformed-upstream-marker\r\nConnection: keep-alive\r\nConnection: close\r\nContent-Length: 0\r\n\r\nrpackit-malformed-upstream-marker",
        ),
        fixed(
            "protected_connection_nomination",
            b"HTTP/1.1 200 OK\r\nX-Rpackit-Attacker-Canary: rpackit-malformed-upstream-marker\r\nConnection: Shiny-Shared-Secret\r\nShiny-Shared-Secret: rpackit-malformed-upstream-marker\r\nContent-Length: 0\r\n\r\nrpackit-malformed-upstream-marker",
        ),
        fixed(
            "ambiguous_location",
            b"HTTP/1.1 302 Found\r\nX-Rpackit-Attacker-Canary: rpackit-malformed-upstream-marker\r\nLocation: /safe\r\nLocation: http://rpackit-malformed-upstream-marker.invalid/\r\nContent-Length: 0\r\n\r\nrpackit-malformed-upstream-marker",
        ),
        fixed(
            "reserved_proxy_cookie",
            b"HTTP/1.1 204 No Content\r\nX-Rpackit-Attacker-Canary: rpackit-malformed-upstream-marker\r\nSet-Cookie: rpackit_proxy_v1=rpackit-malformed-upstream-marker; Path=/\r\n\r\nrpackit-malformed-upstream-marker",
        ),
        fixed(
            "unsolicited_protocol_switch",
            b"HTTP/1.1 101 Switching Protocols\r\nX-Rpackit-Attacker-Canary: rpackit-malformed-upstream-marker\r\nConnection: upgrade\r\nUpgrade: rpackit-malformed-upstream-marker\r\n\r\nrpackit-malformed-upstream-marker",
        ),
    ]
}

fn malformed_websocket_response_cases() -> Vec<RawUpstreamCase> {
    let mut cases = malformed_websocket_framing_cases();
    cases.extend(malformed_websocket_handshake_cases());
    cases.extend(malformed_websocket_negotiation_cases());
    cases
}

fn websocket_negative_raw_case(name: &'static str, response: Vec<u8>) -> RawUpstreamCase {
    RawUpstreamCase {
        name,
        response,
        negative: true,
        kind: RawProbeKind::WebSocket,
    }
}

fn websocket_negative_case(name: &'static str, headers: &[(&str, &str)]) -> RawUpstreamCase {
    websocket_negative_raw_case(name, negative_websocket_response(headers))
}

fn malformed_websocket_framing_cases() -> Vec<RawUpstreamCase> {
    let mut bare_line_feeds = format!(
        "HTTP/1.1 101 Switching Protocols\nConnection: Upgrade\nUpgrade: websocket\nSec-WebSocket-Accept: {WEBSOCKET_ACCEPT}\n{}: {}\n\n",
        ATTACKER_CANARY_HEADER.0, ATTACKER_CANARY_HEADER.1
    )
    .into_bytes();
    bare_line_feeds.extend_from_slice(ATTACKER_WEBSOCKET_FRAME);

    let mut oversized = raw_response_prefix(
        "101 Switching Protocols",
        &[
            WEBSOCKET_CONNECTION_HEADER,
            WEBSOCKET_UPGRADE_HEADER,
            WEBSOCKET_ACCEPT_HEADER,
            ATTACKER_CANARY_HEADER,
        ],
    );
    oversized.extend_from_slice(b"X-Oversized: ");
    oversized.extend(std::iter::repeat_n(b'a', 33 * 1024));
    oversized.extend_from_slice(b"\r\n\r\n");
    oversized.extend_from_slice(ATTACKER_WEBSOCKET_FRAME);

    let mut too_many_headers = raw_response_prefix(
        "101 Switching Protocols",
        &[
            WEBSOCKET_CONNECTION_HEADER,
            WEBSOCKET_UPGRADE_HEADER,
            WEBSOCKET_ACCEPT_HEADER,
            ATTACKER_CANARY_HEADER,
        ],
    );
    for _ in 0..97 {
        too_many_headers.extend_from_slice(b"X-Filler: a\r\n");
    }
    too_many_headers.extend_from_slice(b"\r\n");
    too_many_headers.extend_from_slice(ATTACKER_WEBSOCKET_FRAME);

    vec![
        websocket_negative_raw_case("websocket_bare_line_feeds", bare_line_feeds),
        websocket_negative_case(
            "websocket_conflicting_content_length",
            &[
                WEBSOCKET_CONNECTION_HEADER,
                WEBSOCKET_UPGRADE_HEADER,
                WEBSOCKET_ACCEPT_HEADER,
                ("Content-Length", "0"),
                ("Content-Length", "1"),
            ],
        ),
        websocket_negative_raw_case("websocket_oversized_response_head", oversized),
        websocket_negative_raw_case("websocket_too_many_headers", too_many_headers),
        websocket_negative_case(
            "websocket_content_length",
            &[
                WEBSOCKET_CONNECTION_HEADER,
                WEBSOCKET_UPGRADE_HEADER,
                WEBSOCKET_ACCEPT_HEADER,
                ("Content-Length", "0"),
            ],
        ),
        websocket_negative_case(
            "websocket_transfer_encoding",
            &[
                WEBSOCKET_CONNECTION_HEADER,
                WEBSOCKET_UPGRADE_HEADER,
                WEBSOCKET_ACCEPT_HEADER,
                ("Transfer-Encoding", "chunked"),
            ],
        ),
    ]
}

fn malformed_websocket_handshake_cases() -> Vec<RawUpstreamCase> {
    vec![
        websocket_negative_case(
            "websocket_duplicate_connection",
            &[
                ("Connection", "Upgrade"),
                ("Connection", "close"),
                WEBSOCKET_UPGRADE_HEADER,
                WEBSOCKET_ACCEPT_HEADER,
            ],
        ),
        websocket_negative_case(
            "websocket_duplicate_upgrade",
            &[
                WEBSOCKET_CONNECTION_HEADER,
                ("Upgrade", "websocket"),
                ("Upgrade", "rpackit-malformed-upstream-marker"),
                WEBSOCKET_ACCEPT_HEADER,
            ],
        ),
        websocket_negative_case(
            "websocket_wrong_upgrade",
            &[
                WEBSOCKET_CONNECTION_HEADER,
                ("Upgrade", "rpackit-malformed-upstream-marker"),
                WEBSOCKET_ACCEPT_HEADER,
            ],
        ),
        websocket_negative_case(
            "websocket_missing_accept",
            &[WEBSOCKET_CONNECTION_HEADER, WEBSOCKET_UPGRADE_HEADER],
        ),
        websocket_negative_case(
            "websocket_wrong_accept",
            &[
                WEBSOCKET_CONNECTION_HEADER,
                WEBSOCKET_UPGRADE_HEADER,
                ("Sec-WebSocket-Accept", MALFORMED_RESPONSE_MARKER_TEXT),
            ],
        ),
        websocket_negative_case(
            "websocket_duplicate_accept",
            &[
                WEBSOCKET_CONNECTION_HEADER,
                WEBSOCKET_UPGRADE_HEADER,
                WEBSOCKET_ACCEPT_HEADER,
                ("Sec-WebSocket-Accept", MALFORMED_RESPONSE_MARKER_TEXT),
            ],
        ),
    ]
}

fn malformed_websocket_negotiation_cases() -> Vec<RawUpstreamCase> {
    vec![
        websocket_negative_case(
            "websocket_unoffered_protocol",
            &[
                WEBSOCKET_CONNECTION_HEADER,
                WEBSOCKET_UPGRADE_HEADER,
                WEBSOCKET_ACCEPT_HEADER,
                ("Sec-WebSocket-Protocol", MALFORMED_RESPONSE_MARKER_TEXT),
            ],
        ),
        websocket_negative_case(
            "websocket_duplicate_protocol",
            &[
                WEBSOCKET_CONNECTION_HEADER,
                WEBSOCKET_UPGRADE_HEADER,
                WEBSOCKET_ACCEPT_HEADER,
                ("Sec-WebSocket-Protocol", "first"),
                ("Sec-WebSocket-Protocol", MALFORMED_RESPONSE_MARKER_TEXT),
            ],
        ),
        websocket_negative_case(
            "websocket_unsolicited_extensions",
            &[
                WEBSOCKET_CONNECTION_HEADER,
                WEBSOCKET_UPGRADE_HEADER,
                WEBSOCKET_ACCEPT_HEADER,
                ("Sec-WebSocket-Extensions", MALFORMED_RESPONSE_MARKER_TEXT),
            ],
        ),
        websocket_negative_case(
            "websocket_protected_connection_nomination",
            &[
                ("Connection", "Upgrade, Shiny-Shared-Secret"),
                WEBSOCKET_UPGRADE_HEADER,
                WEBSOCKET_ACCEPT_HEADER,
                ("Shiny-Shared-Secret", MALFORMED_RESPONSE_MARKER_TEXT),
            ],
        ),
    ]
}

fn raw_response(status: &str, headers: &[(&str, &str)], bytes_after_head: &[u8]) -> Vec<u8> {
    let mut response = raw_response_prefix(status, headers);
    response.extend_from_slice(b"\r\n");
    response.extend_from_slice(bytes_after_head);
    response
}

fn raw_response_prefix(status: &str, headers: &[(&str, &str)]) -> Vec<u8> {
    let mut response = format!("HTTP/1.1 {status}\r\n").into_bytes();
    for (name, value) in headers {
        response.extend_from_slice(name.as_bytes());
        response.extend_from_slice(b": ");
        response.extend_from_slice(value.as_bytes());
        response.extend_from_slice(b"\r\n");
    }
    response
}

fn negative_websocket_response(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut all_headers = Vec::with_capacity(headers.len() + 1);
    all_headers.extend_from_slice(headers);
    all_headers.push(ATTACKER_CANARY_HEADER);
    raw_response(
        "101 Switching Protocols",
        &all_headers,
        ATTACKER_WEBSOCKET_FRAME,
    )
}

async fn serve_one_raw_upstream_response(
    listener: TcpListener,
    expected_secret: Arc<Secret>,
    upstream_address: SocketAddr,
    kind: RawProbeKind,
    response: Vec<u8>,
) -> io::Result<RawUpstreamObservation> {
    let (mut socket, peer) = timeout(Duration::from_secs(2), listener.accept())
        .await
        .map_err(|_| io::Error::other("raw upstream accept timed out"))??;
    if !peer.ip().is_loopback() {
        return Err(io::Error::other(
            "raw upstream received a non-loopback peer",
        ));
    }
    let request = read_bounded_header(&mut socket).await?;
    let valid_secret =
        single_header_matches(&request, b"shiny-shared-secret", expected_secret.as_ref());
    let valid_websocket_request = kind == RawProbeKind::WebSocket
        && valid_secret
        && valid_upstream_websocket_request(&request, upstream_address);
    socket.write_all(&response).await?;
    socket.shutdown().await?;
    Ok(RawUpstreamObservation {
        valid_secret,
        valid_websocket_request,
    })
}

async fn request_authenticated_probe(
    proxy: &RunningProxy,
    session: &Secret,
    kind: RawProbeKind,
    negative: bool,
) -> io::Result<Vec<u8>> {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), proxy.address().port());
    let request = session.with_exposed(|value| {
        if kind == RawProbeKind::WebSocket {
            format!(
                "GET /malformed-upstream-probe HTTP/1.1\r\nHost: {}\r\nOrigin: {}\r\nCookie: {SESSION_COOKIE_NAME}={value}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {WEBSOCKET_KEY}\r\n\r\n",
                proxy.address().authority(),
                proxy.address().origin(),
            )
        } else {
            format!(
                "GET /malformed-upstream-probe HTTP/1.1\r\nHost: {}\r\nCookie: {SESSION_COOKIE_NAME}={value}\r\nConnection: close\r\n\r\n",
                proxy.address().authority()
            )
        }
    });
    let mut socket = TcpStream::connect(address).await?;
    socket.write_all(request.as_bytes()).await?;
    if kind == RawProbeKind::WebSocket && !negative {
        return read_websocket_baseline_response(&mut socket).await;
    }
    let mut response = Vec::with_capacity(1024);
    match timeout(Duration::from_secs(3), socket.read_to_end(&mut response)).await {
        Ok(result) => {
            result?;
        }
        Err(_) if !response.is_empty() => {}
        Err(_) => return Err(io::Error::other("proxy response timed out")),
    }
    Ok(response)
}

async fn read_websocket_baseline_response(socket: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut response = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 1024];
    loop {
        if let Some(header_end) = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
            && response.len() >= header_end + SAFE_WEBSOCKET_FRAME.len()
        {
            return Ok(response);
        }
        if response.len() >= 32 * 1024 {
            return Err(io::Error::other(
                "downstream WebSocket baseline exceeded response limit",
            ));
        }
        let read = timeout(Duration::from_secs(3), socket.read(&mut buffer))
            .await
            .map_err(|_| io::Error::other("WebSocket baseline response timed out"))??;
        if read == 0 {
            return Ok(response);
        }
        response.extend_from_slice(&buffer[..read]);
    }
}

fn valid_upstream_websocket_request(request: &[u8], upstream_address: SocketAddr) -> bool {
    let expected_origin = format!("http://{upstream_address}");
    request.starts_with(b"GET /malformed-upstream-probe HTTP/1.1\r\n")
        && single_header_equals(request, b"connection", b"upgrade", true)
        && single_header_equals(request, b"upgrade", b"websocket", true)
        && single_header_equals(request, b"sec-websocket-version", b"13", false)
        && single_header_equals(
            request,
            b"sec-websocket-key",
            WEBSOCKET_KEY.as_bytes(),
            false,
        )
        && single_header_equals(request, b"origin", expected_origin.as_bytes(), false)
        && raw_header_values(request, b"content-length").is_empty()
        && raw_header_values(request, b"transfer-encoding").is_empty()
}

async fn read_bounded_header(socket: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut request = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        if request.len() >= 32 * 1024 {
            return Err(io::Error::other("raw upstream request head exceeded limit"));
        }
        let read = timeout(Duration::from_secs(2), socket.read(&mut buffer))
            .await
            .map_err(|_| io::Error::other("raw upstream request read timed out"))??;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "raw upstream request ended before its header",
            ));
        }
        request.extend_from_slice(&buffer[..read]);
    }
    Ok(request)
}

fn single_header_matches(request: &[u8], name: &[u8], expected: &Secret) -> bool {
    let values = raw_header_values(request, name);
    values.len() == 1 && expected.matches(values[0])
}

fn single_header_equals(
    request: &[u8],
    name: &[u8],
    expected: &[u8],
    case_insensitive: bool,
) -> bool {
    let values = raw_header_values(request, name);
    values.len() == 1
        && if case_insensitive {
            values[0].eq_ignore_ascii_case(expected)
        } else {
            values[0] == expected
        }
}

fn raw_header_values<'a>(request: &'a [u8], name: &[u8]) -> Vec<&'a [u8]> {
    request
        .split(|byte| *byte == b'\n')
        .filter_map(|line| line.strip_suffix(b"\r"))
        .filter_map(|line| {
            let separator = line.iter().position(|byte| *byte == b':')?;
            Some((&line[..separator], &line[separator + 1..]))
        })
        .filter(|(observed, _)| observed.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim_ascii())
        .collect()
}

/// Probe the Windows `SO_EXCLUSIVEADDRUSE` exact-listener boundary against a
/// same-port wildcard listener configured with `SO_REUSEADDR`.
///
/// The wildcard bind result is recorded independently. The security result
/// depends on repeated exact-loopback requests returning the proxy's fixed
/// unauthenticated `401` while the wildcard listener accepts zero
/// connections.
///
/// # Errors
///
/// Returns an I/O error if a probe socket cannot be configured, a successfully
/// bound wildcard cannot listen, or its accept monitor cannot be joined.
#[cfg(windows)]
pub async fn probe_listener_overlap(proxy: &RunningProxy) -> io::Result<ListenerOverlapEvidence> {
    let port = proxy.address().port();
    let ipv4_wildcard = probe_listener_family(
        proxy,
        Domain::IPV4,
        None,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
    )
    .await?;
    let ipv6_v6_only_wildcard = probe_listener_family(
        proxy,
        Domain::IPV6,
        Some(true),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
    )
    .await?;
    let ipv6_dual_stack_wildcard = probe_dual_stack_listener(
        proxy,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
    )
    .await?;
    Ok(ListenerOverlapEvidence {
        windows_probe_completed: ipv4_wildcard.probe_completed
            && ipv6_v6_only_wildcard.probe_completed
            && ipv6_dual_stack_wildcard.probe_completed,
        ipv4_wildcard,
        ipv6_v6_only_wildcard,
        ipv6_dual_stack_wildcard,
    })
}

/// Return unproven evidence when the Windows-only probe is compiled elsewhere.
///
/// # Errors
///
/// This non-Windows stub cannot fail; the `Result` keeps the cross-platform
/// call site identical to the Windows probe.
#[cfg(not(windows))]
pub fn probe_listener_overlap(
    _proxy: &RunningProxy,
) -> std::future::Ready<io::Result<ListenerOverlapEvidence>> {
    std::future::ready(Ok(ListenerOverlapEvidence::default()))
}

#[cfg(windows)]
async fn probe_listener_family(
    proxy: &RunningProxy,
    domain: Domain,
    only_v6: Option<bool>,
    exact_address: SocketAddr,
    wildcard_address: SocketAddr,
) -> io::Result<ListenerFamilyOverlapEvidence> {
    let wildcard_listener = bind_reusing_wildcard(domain, only_v6, wildcard_address)?;
    let wildcard_bind_succeeded = wildcard_listener.is_some();
    let (stop, monitor) = wildcard_listener.map_or((None, None), |listener| {
        let (stop, receiver) = oneshot::channel();
        (
            Some(stop),
            Some(tokio::spawn(monitor_wildcard_accepts(listener, receiver))),
        )
    });

    let mut proxy_unauthorized_responses = 0;
    for _ in 0..LISTENER_OVERLAP_REQUESTS {
        if exact_proxy_returns_unauthorized(proxy, exact_address).await {
            proxy_unauthorized_responses += 1;
        }
    }

    if let Some(stop) = stop {
        let _ = stop.send(());
    }
    let (wildcard_accepts, probe_completed) = if let Some(monitor) = monitor {
        match monitor.await {
            Ok(Ok(accepts)) => (accepts, true),
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                return Err(io::Error::other(
                    "wildcard listener monitor task terminated",
                ));
            }
        }
    } else {
        (0, true)
    };
    let exact_proxy_won = probe_completed
        && proxy_unauthorized_responses == LISTENER_OVERLAP_REQUESTS
        && wildcard_accepts == 0;
    Ok(ListenerFamilyOverlapEvidence {
        wildcard_bind_succeeded,
        requests_attempted: LISTENER_OVERLAP_REQUESTS,
        proxy_unauthorized_responses,
        wildcard_accepts,
        probe_completed,
        exact_proxy_won,
    })
}

#[cfg(windows)]
async fn probe_dual_stack_listener(
    proxy: &RunningProxy,
    exact_ipv4: SocketAddr,
    exact_ipv6: SocketAddr,
    wildcard_address: SocketAddr,
) -> io::Result<ListenerDualStackOverlapEvidence> {
    let wildcard_listener = bind_reusing_wildcard(Domain::IPV6, Some(false), wildcard_address)?;
    let wildcard_bind_succeeded = wildcard_listener.is_some();
    let (stop, monitor) = wildcard_listener.map_or((None, None), |listener| {
        let (stop, receiver) = oneshot::channel();
        (
            Some(stop),
            Some(tokio::spawn(monitor_wildcard_accepts(listener, receiver))),
        )
    });

    let mut ipv4_proxy_unauthorized_responses = 0;
    for _ in 0..LISTENER_OVERLAP_REQUESTS {
        if exact_proxy_returns_unauthorized(proxy, exact_ipv4).await {
            ipv4_proxy_unauthorized_responses += 1;
        }
    }
    let mut ipv6_proxy_unauthorized_responses = 0;
    for _ in 0..LISTENER_OVERLAP_REQUESTS {
        if exact_proxy_returns_unauthorized(proxy, exact_ipv6).await {
            ipv6_proxy_unauthorized_responses += 1;
        }
    }

    if let Some(stop) = stop {
        let _ = stop.send(());
    }
    let (wildcard_accepts, probe_completed) = finish_wildcard_monitor(monitor).await?;
    let exact_proxies_won = probe_completed
        && ipv4_proxy_unauthorized_responses == LISTENER_OVERLAP_REQUESTS
        && ipv6_proxy_unauthorized_responses == LISTENER_OVERLAP_REQUESTS
        && wildcard_accepts == 0;
    Ok(ListenerDualStackOverlapEvidence {
        wildcard_bind_succeeded,
        ipv4_requests_attempted: LISTENER_OVERLAP_REQUESTS,
        ipv4_proxy_unauthorized_responses,
        ipv6_requests_attempted: LISTENER_OVERLAP_REQUESTS,
        ipv6_proxy_unauthorized_responses,
        wildcard_accepts,
        probe_completed,
        exact_proxies_won,
    })
}

#[cfg(windows)]
fn bind_reusing_wildcard(
    domain: Domain,
    only_v6: Option<bool>,
    wildcard_address: SocketAddr,
) -> io::Result<Option<TcpListener>> {
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if let Some(only_v6) = only_v6 {
        socket.set_only_v6(only_v6)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    if let Err(error) = socket.bind(&wildcard_address.into()) {
        if expected_wildcard_bind_rejection(&error) {
            return Ok(None);
        }
        return Err(error);
    }
    socket.listen(128)?;
    let listener: std::net::TcpListener = socket.into();
    Ok(Some(TcpListener::from_std(listener)?))
}

#[cfg(windows)]
fn expected_wildcard_bind_rejection(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
    )
}

#[cfg(windows)]
async fn finish_wildcard_monitor(
    monitor: Option<JoinHandle<io::Result<u64>>>,
) -> io::Result<(u64, bool)> {
    if let Some(monitor) = monitor {
        match monitor.await {
            Ok(Ok(accepts)) => Ok((accepts, true)),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(io::Error::other(
                "wildcard listener monitor task terminated",
            )),
        }
    } else {
        Ok((0, true))
    }
}

#[cfg(windows)]
async fn monitor_wildcard_accepts(
    listener: TcpListener,
    mut stop: oneshot::Receiver<()>,
) -> io::Result<u64> {
    let mut accepts = 0_u64;
    loop {
        tokio::select! {
            _ = &mut stop => {
                loop {
                    match timeout(Duration::from_millis(25), listener.accept()).await {
                        Ok(Ok((_socket, _peer))) => accepts += 1,
                        Ok(Err(error)) => return Err(error),
                        Err(_) => return Ok(accepts),
                    }
                }
            }
            accepted = listener.accept() => {
                let (_socket, _peer) = accepted?;
                accepts += 1;
            }
        }
    }
}

#[cfg(windows)]
async fn exact_proxy_returns_unauthorized(proxy: &RunningProxy, exact_address: SocketAddr) -> bool {
    let request = format!(
        "GET /api/data HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        proxy.address().authority()
    );
    let observed = timeout(Duration::from_secs(1), async {
        let mut socket = TcpStream::connect(exact_address).await?;
        socket.write_all(request.as_bytes()).await?;
        let mut response = Vec::with_capacity(512);
        socket.take(4096).read_to_end(&mut response).await?;
        Ok::<_, io::Error>(response)
    })
    .await;
    matches!(
        observed,
        Ok(Ok(response)) if response.starts_with(b"HTTP/1.1 401 ")
    )
}

#[derive(Default)]
struct UpstreamState {
    connections: AtomicU64,
    requests: AtomicU64,
    protected_header_valid: AtomicU64,
    protected_header_invalid_count: AtomicU64,
    proxy_cookie_leaks: AtomicU64,
    forwarding_header_leaks: AtomicU64,
    websocket_extension_leaks: AtomicU64,
    bootstrap_header_leaks: AtomicU64,
    valid_rewritten_origins: AtomicU64,
    routes: Mutex<BTreeMap<String, u64>>,
    browser_report: Mutex<Option<BrowserReport>>,
    report_notify: Notify,
}

#[derive(Default)]
struct CollectorState {
    requests: AtomicU64,
    proxy_cookie_leaks: AtomicU64,
    protected_header_leaks: AtomicU64,
    bootstrap_header_leaks: AtomicU64,
    external_redirect_requests: AtomicU64,
    child_host_requests: AtomicU64,
}

/// Running external redirect collector.
pub struct ExternalCollector {
    address: SocketAddr,
    state: Arc<CollectorState>,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<Result<(), io::Error>>,
}

impl ExternalCollector {
    /// Start on a fresh IPv4 loopback port.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the listener cannot bind or report its address.
    pub async fn start() -> io::Result<Self> {
        let listener =
            TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
        let address = listener.local_addr()?;
        let state = Arc::new(CollectorState::default());
        let (shutdown, receiver) = watch::channel(false);
        let task = tokio::spawn(run_collector(listener, Arc::clone(&state), receiver));
        Ok(Self {
            address,
            state,
            shutdown,
            task,
        })
    }

    /// Fixed loopback address.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Current secret-free evidence.
    #[must_use]
    pub fn snapshot(&self) -> CollectorSnapshot {
        CollectorSnapshot {
            requests: self.state.requests.load(Ordering::Relaxed),
            proxy_cookie_leaks: self.state.proxy_cookie_leaks.load(Ordering::Relaxed),
            protected_header_leaks: self.state.protected_header_leaks.load(Ordering::Relaxed),
            bootstrap_header_leaks: self.state.bootstrap_header_leaks.load(Ordering::Relaxed),
            external_redirect_requests: self
                .state
                .external_redirect_requests
                .load(Ordering::Relaxed),
            child_host_requests: self.state.child_host_requests.load(Ordering::Relaxed),
        }
    }

    /// Stop the collector.
    ///
    /// # Errors
    ///
    /// Returns an I/O error from the listener task, or if that task terminates
    /// unexpectedly.
    pub async fn shutdown(self) -> io::Result<()> {
        let _ = self.shutdown.send(true);
        self.task
            .await
            .map_err(|_| io::Error::other("collector task terminated"))?
    }
}

/// Running mock Shiny upstream.
pub struct MockUpstream {
    address: SocketAddr,
    state: Arc<UpstreamState>,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<Result<(), io::Error>>,
}

impl MockUpstream {
    /// Start on a fresh IPv4 loopback port.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the listener cannot bind or report its address.
    pub async fn start(
        expected_secret: Arc<Secret>,
        external_collector: SocketAddr,
    ) -> io::Result<Self> {
        let listener =
            TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
        let address = listener.local_addr()?;
        let state = Arc::new(UpstreamState::default());
        let (shutdown, receiver) = watch::channel(false);
        let task = tokio::spawn(run_upstream(
            listener,
            Arc::clone(&state),
            expected_secret,
            external_collector,
            receiver,
        ));
        Ok(Self {
            address,
            state,
            shutdown,
            task,
        })
    }

    /// Fixed upstream address.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Wait until a browser report is available.
    pub async fn wait_for_browser_report(&self) -> BrowserReport {
        loop {
            if let Some(report) = self.state.browser_report.lock().await.clone() {
                return report;
            }
            self.state.report_notify.notified().await;
        }
    }

    /// Current secret-free evidence.
    pub async fn snapshot(&self) -> UpstreamSnapshot {
        UpstreamSnapshot {
            connections: self.state.connections.load(Ordering::Relaxed),
            requests: self.state.requests.load(Ordering::Relaxed),
            protected_header_valid: self.state.protected_header_valid.load(Ordering::Relaxed),
            protected_header_invalid_count: self
                .state
                .protected_header_invalid_count
                .load(Ordering::Relaxed),
            proxy_cookie_leaks: self.state.proxy_cookie_leaks.load(Ordering::Relaxed),
            forwarding_header_leaks: self.state.forwarding_header_leaks.load(Ordering::Relaxed),
            websocket_extension_leaks: self.state.websocket_extension_leaks.load(Ordering::Relaxed),
            bootstrap_header_leaks: self.state.bootstrap_header_leaks.load(Ordering::Relaxed),
            valid_rewritten_origins: self.state.valid_rewritten_origins.load(Ordering::Relaxed),
            routes: self.state.routes.lock().await.clone(),
            browser_report: self.state.browser_report.lock().await.clone(),
        }
    }

    /// Stop the upstream.
    ///
    /// # Errors
    ///
    /// Returns an I/O error from the listener task, or if that task terminates
    /// unexpectedly.
    pub async fn shutdown(self) -> io::Result<()> {
        let _ = self.shutdown.send(true);
        self.task
            .await
            .map_err(|_| io::Error::other("mock upstream task terminated"))?
    }
}

async fn run_collector(
    listener: TcpListener,
    state: Arc<CollectorState>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (socket, peer) = accepted?;
                if !peer.ip().is_loopback() {
                    continue;
                }
                let request_state = Arc::clone(&state);
                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        let state = Arc::clone(&request_state);
                        async move {
                            Ok::<_, Infallible>(handle_collector(&request, &state))
                        }
                    });
                    let _ = http1::Builder::new()
                        .keep_alive(false)
                        .serve_connection(TokioIo::new(socket), service)
                        .await;
                });
            }
        }
    }
}

fn handle_collector(request: &Request<Incoming>, state: &CollectorState) -> Response<TestBody> {
    state.requests.fetch_add(1, Ordering::Relaxed);
    if cookie_header_contains_reserved(request.headers()) {
        state.proxy_cookie_leaks.fetch_add(1, Ordering::Relaxed);
    }
    if request.headers().contains_key("shiny-shared-secret") {
        state.protected_header_leaks.fetch_add(1, Ordering::Relaxed);
    }
    if request.headers().contains_key("x-rpackit-bootstrap") {
        state.bootstrap_header_leaks.fetch_add(1, Ordering::Relaxed);
    }
    if request.uri().path() == "/collect" {
        state
            .external_redirect_requests
            .fetch_add(1, Ordering::Relaxed);
    }
    if request.uri().path() == "/child-cookie-check" {
        state.child_host_requests.fetch_add(1, Ordering::Relaxed);
    }
    response(StatusCode::NO_CONTENT, "", "text/plain")
}

async fn run_upstream(
    listener: TcpListener,
    state: Arc<UpstreamState>,
    expected_secret: Arc<Secret>,
    external_collector: SocketAddr,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let upstream_address = listener.local_addr()?;
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (socket, peer) = accepted?;
                if !peer.ip().is_loopback() {
                    continue;
                }
                state.connections.fetch_add(1, Ordering::Relaxed);
                let request_state = Arc::clone(&state);
                let request_secret = Arc::clone(&expected_secret);
                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        let state = Arc::clone(&request_state);
                        let secret = Arc::clone(&request_secret);
                        async move {
                            Ok::<_, Infallible>(
                                handle_upstream(
                                    request,
                                    state,
                                    secret,
                                    upstream_address,
                                    external_collector,
                                ).await
                            )
                        }
                    });
                    let _ = http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(TokioIo::new(socket), service)
                        .with_upgrades()
                        .await;
                });
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn handle_upstream(
    mut request: Request<Incoming>,
    state: Arc<UpstreamState>,
    expected_secret: Arc<Secret>,
    upstream_address: SocketAddr,
    external_collector: SocketAddr,
) -> Response<TestBody> {
    state.requests.fetch_add(1, Ordering::Relaxed);
    let protected: Vec<&HeaderValue> = request
        .headers()
        .get_all("shiny-shared-secret")
        .iter()
        .collect();
    if protected.len() == 1 && expected_secret.matches(protected[0].as_bytes()) {
        state.protected_header_valid.fetch_add(1, Ordering::Relaxed);
    } else {
        state
            .protected_header_invalid_count
            .fetch_add(1, Ordering::Relaxed);
        return response(
            StatusCode::UNAUTHORIZED,
            "upstream authentication failed",
            "text/plain",
        );
    }
    if cookie_header_contains_reserved(request.headers()) {
        state.proxy_cookie_leaks.fetch_add(1, Ordering::Relaxed);
    }
    if request.headers().keys().any(|name| {
        let name = name.as_str();
        name == "forwarded"
            || name == "x-real-ip"
            || name.starts_with("x-forwarded-")
            || name.starts_with("x-original-")
    }) {
        state
            .forwarding_header_leaks
            .fetch_add(1, Ordering::Relaxed);
    }
    if request.headers().contains_key("sec-websocket-extensions") {
        state
            .websocket_extension_leaks
            .fetch_add(1, Ordering::Relaxed);
    }
    if request.headers().contains_key("x-rpackit-bootstrap") {
        state.bootstrap_header_leaks.fetch_add(1, Ordering::Relaxed);
    }
    if request
        .headers()
        .get(ORIGIN)
        .is_some_and(|origin| origin.as_bytes() == format!("http://{upstream_address}").as_bytes())
    {
        state
            .valid_rewritten_origins
            .fetch_add(1, Ordering::Relaxed);
    }

    let route = request.uri().path().to_owned();
    {
        let mut routes = state.routes.lock().await;
        *routes.entry(route.clone()).or_insert(0) += 1;
    }

    match route.as_str() {
        "/" => root_response(external_collector),
        "/assets/site.css" => response(
            StatusCode::OK,
            "body{font-family:system-ui,sans-serif}",
            "text/css",
        ),
        "/assets/app.js" => response(StatusCode::OK, APP_SCRIPT, "text/javascript"),
        "/assets/pixel.svg" => response(
            StatusCode::OK,
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1\" height=\"1\"/>",
            "image/svg+xml",
        ),
        "/api/data" => response(StatusCode::OK, "{\"ok\":true}", "application/json"),
        "/api/submit" => response(StatusCode::NO_CONTENT, "", "text/plain"),
        "/api/body-probe" => match request.body_mut().collect().await {
            Ok(_) => response(StatusCode::NO_CONTENT, "", "text/plain"),
            Err(_) => response(StatusCode::BAD_REQUEST, "body rejected", "text/plain"),
        },
        "/api/stream" => stream_response(),
        "/redirect/internal" => redirect_response(&format!("http://{upstream_address}/api/data")),
        "/redirect/external" => redirect_response(&format!("http://{external_collector}/collect")),
        "/cookies/app" => cookie_response("application_cookie=ok; Domain=127.0.0.1; HttpOnly"),
        "/cookies/reserved" => cookie_response(&format!("{SESSION_COOKIE_NAME}=bad; Path=/")),
        "/cookies/bad-domain" => cookie_response("application_cookie=bad; Domain=example.test"),
        "/headers/protected" => protected_response_headers(),
        "/__rpackit_report" => {
            let body = request.body_mut().collect().await;
            match body
                .ok()
                .and_then(|collected| serde_json::from_slice(collected.to_bytes().as_ref()).ok())
            {
                Some(report) => {
                    *state.browser_report.lock().await = Some(report);
                    state.report_notify.notify_waiters();
                    response(StatusCode::NO_CONTENT, "", "text/plain")
                }
                None => response(StatusCode::BAD_REQUEST, "invalid report", "text/plain"),
            }
        }
        "/ws" | "/ws-cookie"
            if hyper_tungstenite::is_upgrade_request(&request)
                && (route == "/ws"
                    || request.headers().get(COOKIE)
                        == Some(&HeaderValue::from_static("app_ws=ok"))) =>
        {
            match hyper_tungstenite::upgrade(&mut request, None) {
                Ok((upgrade_response, websocket)) => {
                    tokio::spawn(async move {
                        let _ = echo_websocket(websocket).await;
                    });
                    map_hyper_tungstenite_response(upgrade_response)
                }
                Err(_) => response(StatusCode::BAD_REQUEST, "invalid websocket", "text/plain"),
            }
        }
        _ => response(StatusCode::NOT_FOUND, "not found", "text/plain"),
    }
}

async fn echo_websocket(websocket: HyperWebsocket) -> Result<(), BoxError> {
    let mut websocket = websocket.await?;
    while let Some(message) = websocket.next().await {
        let message = message?;
        match message {
            Message::Text(_) | Message::Binary(_) => websocket.send(message).await?,
            Message::Close(frame) => {
                websocket.close(frame).await?;
                break;
            }
            _ => {}
        }
    }
    Ok(())
}

fn root_response(external_collector: SocketAddr) -> Response<TestBody> {
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><link id=\"test-css\" rel=\"stylesheet\" href=\"/assets/site.css\"><meta name=\"external-collector\" content=\"http://{external_collector}\"><title>Transport acceptance</title></head><body><img id=\"test-image\" src=\"/assets/pixel.svg\" alt=\"\"><script src=\"/assets/app.js\"></script></body></html>"
    );
    let mut response = response(StatusCode::OK, &html, "text/html");
    response.headers_mut().insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&format!(
            "default-src 'self'; connect-src 'self' http://{external_collector} http://*.localhost:{}; img-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            external_collector.port()
        ))
        .unwrap_or_else(|_| HeaderValue::from_static("default-src 'self'")),
    );
    response
}

fn response(status: StatusCode, body: &str, content_type: &'static str) -> Response<TestBody> {
    let mut response = Response::new(full_body(Bytes::copy_from_slice(body.as_bytes())));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn redirect_response(location: &str) -> Response<TestBody> {
    let mut response = response(StatusCode::FOUND, "", "text/plain");
    if let Ok(location) = HeaderValue::from_str(location) {
        response.headers_mut().insert(LOCATION, location);
    }
    response
}

fn cookie_response(cookie: &str) -> Response<TestBody> {
    let mut response = response(StatusCode::NO_CONTENT, "", "text/plain");
    if let Ok(cookie) = HeaderValue::from_str(cookie) {
        response.headers_mut().append(SET_COOKIE, cookie);
    }
    response
}

fn protected_response_headers() -> Response<TestBody> {
    let mut response = response(StatusCode::NO_CONTENT, "", "text/plain");
    response.headers_mut().insert(
        "shiny-shared-secret",
        HeaderValue::from_static("reflected-upstream-field"),
    );
    response.headers_mut().insert(
        "x-rpackit-bootstrap",
        HeaderValue::from_static("reflected-bootstrap-field"),
    );
    response
}

fn stream_response() -> Response<TestBody> {
    let frames = stream::unfold(0_u8, |step| async move {
        match step {
            0 => Some((
                Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"first\n"))),
                1,
            )),
            1 => {
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                Some((Ok(Frame::data(Bytes::from_static(b"second\n"))), 2))
            }
            _ => None,
        }
    });
    let body = StreamBody::new(frames)
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync();
    let mut response = Response::new(body);
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    response
}

fn map_hyper_tungstenite_response<B>(response: Response<B>) -> Response<TestBody> {
    let (parts, _body) = response.into_parts();
    Response::from_parts(parts, full_body(Bytes::new()))
}

fn full_body(bytes: Bytes) -> TestBody {
    Full::new(bytes)
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}

fn cookie_header_contains_reserved(headers: &http::HeaderMap) -> bool {
    headers.get_all("cookie").iter().any(|value| {
        value.to_str().is_ok_and(|text| {
            text.split(';').any(|segment| {
                segment
                    .trim()
                    .split_once('=')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case(SESSION_COOKIE_NAME))
            })
        })
    })
}

const APP_SCRIPT: &str = r#"
(() => {
  const result = {
    cssLoaded: false,
    scriptLoaded: true,
    imageLoaded: false,
    fetchGet: false,
    fetchPost: false,
    streamRead: false,
    websocketEcho: false,
    proxyCookieVisible: false,
    secretShapeVisible: false,
    externalRedirectCompleted: false,
    childHostRequestCompleted: false
  };

  const finish = async () => {
    result.cssLoaded = Boolean(document.getElementById("test-css")?.sheet);
    result.imageLoaded = Boolean(document.getElementById("test-image")?.complete);
    result.proxyCookieVisible = document.cookie
      .split(";")
      .some(part => part.trim().toLowerCase().startsWith("rpackit_proxy_v1="));
    result.secretShapeVisible = /rp-[0-9a-f]{64}/i.test(
      document.documentElement.outerHTML + document.cookie + location.href
    );
    await fetch("/__rpackit_report", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(result)
    });
  };

  window.addEventListener("load", async () => {
    try {
      result.fetchGet = (await fetch("/api/data")).ok;
      result.fetchPost = (await fetch("/api/submit", {method: "POST", body: "ok"})).ok;
      const stream = await fetch("/api/stream");
      const reader = stream.body.getReader();
      let reads = 0;
      while (!(await reader.read()).done) reads += 1;
      result.streamRead = reads >= 2;
      await new Promise(resolve => {
        const socket = new WebSocket(
          `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`
        );
        const timer = setTimeout(resolve, 3000);
        socket.onopen = () => socket.send("echo");
        socket.onmessage = event => {
          result.websocketEcho = event.data === "echo";
          clearTimeout(timer);
          socket.close();
          resolve();
        };
        socket.onerror = () => {
          clearTimeout(timer);
          resolve();
        };
      });
      try {
        await fetch("/redirect/external", {mode: "no-cors", redirect: "follow"});
        result.externalRedirectCompleted = true;
      } catch (_) {
        result.externalRedirectCompleted = false;
      }
      try {
        const collector = new URL(
          document.querySelector('meta[name="external-collector"]').content
        );
        const child = `http://child.${location.hostname}:${collector.port}/child-cookie-check`;
        await fetch(child, {mode: "no-cors", credentials: "include"});
        result.childHostRequestCompleted = true;
      } catch (_) {
        result.childHostRequestCompleted = false;
      }
    } finally {
      await finish();
    }
  });
})();
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn collector_records_only_boolean_leakage_evidence() {
        let collector = ExternalCollector::start().await;
        assert!(collector.is_ok());
        if let Ok(collector) = collector {
            assert_eq!(collector.snapshot(), CollectorSnapshot::default());
            assert!(collector.shutdown().await.is_ok());
        }
    }

    #[test]
    fn browser_report_rejects_unknown_fields() {
        let report = serde_json::from_str::<BrowserReport>(
            r#"{"cssLoaded":false,"scriptLoaded":false,"imageLoaded":false,"fetchGet":false,"fetchPost":false,"streamRead":false,"websocketEcho":false,"proxyCookieVisible":false,"secretShapeVisible":false,"externalRedirectCompleted":false,"childHostRequestCompleted":false,"secret":"bad"}"#,
        );
        assert!(report.is_err());
    }

    #[test]
    fn listener_overlap_pass_requires_all_three_contenders_and_four_paths() {
        let passing_family = ListenerFamilyOverlapEvidence {
            wildcard_bind_succeeded: true,
            requests_attempted: 8,
            proxy_unauthorized_responses: 8,
            wildcard_accepts: 0,
            probe_completed: true,
            exact_proxy_won: true,
        };
        let passing_dual_stack = ListenerDualStackOverlapEvidence {
            wildcard_bind_succeeded: true,
            ipv4_requests_attempted: 8,
            ipv4_proxy_unauthorized_responses: 8,
            ipv6_requests_attempted: 8,
            ipv6_proxy_unauthorized_responses: 8,
            wildcard_accepts: 0,
            probe_completed: true,
            exact_proxies_won: true,
        };
        let mut evidence = ListenerOverlapEvidence {
            windows_probe_completed: true,
            ipv4_wildcard: passing_family.clone(),
            ipv6_v6_only_wildcard: passing_family,
            ipv6_dual_stack_wildcard: passing_dual_stack,
        };
        assert!(evidence.all_variants_prove_exact_proxy_ownership());

        evidence.ipv6_v6_only_wildcard.wildcard_accepts = 1;
        evidence.ipv6_v6_only_wildcard.exact_proxy_won = false;
        assert!(!evidence.all_variants_prove_exact_proxy_ownership());
        evidence.ipv6_v6_only_wildcard.wildcard_accepts = 0;
        evidence.ipv6_v6_only_wildcard.exact_proxy_won = true;
        evidence
            .ipv6_dual_stack_wildcard
            .ipv4_proxy_unauthorized_responses = 7;
        assert!(!evidence.all_variants_prove_exact_proxy_ownership());
        evidence
            .ipv6_dual_stack_wildcard
            .ipv4_proxy_unauthorized_responses = 8;
        evidence.windows_probe_completed = false;
        assert!(!evidence.all_variants_prove_exact_proxy_ownership());
    }

    #[cfg(windows)]
    #[test]
    fn only_expected_windows_bind_conflicts_count_as_safe_rejection() {
        assert!(expected_wildcard_bind_rejection(&io::Error::from(
            io::ErrorKind::AddrInUse
        )));
        assert!(expected_wildcard_bind_rejection(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
        assert!(!expected_wildcard_bind_rejection(&io::Error::other(
            "unexpected wildcard bind failure"
        )));
    }
}
