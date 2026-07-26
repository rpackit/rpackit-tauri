//! Secret-free real-loopback evidence for upstream response resource limits.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_compression::tokio::write::GzipEncoder;
use rpackit_transport::{ProxyConfig, RunningProxy, Secret, TransportLimits, TransportSecrets};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    time::timeout,
};

use crate::{
    BodyClientObservation, downstream_connection_closes, is_exact_fixed_bad_gateway,
    parse_raw_response, raw_header_values, raw_response, raw_response_prefix,
    request_authenticated_body_probe, single_header_matches,
};

const NEGATIVE_CASES: u32 = 5;
const TOTAL_CASES: u32 = NEGATIVE_CASES + 2;
const ENCODED_EXPANSION_LIMIT: usize = 1024;
const DECODED_EXPANSION_LIMIT: usize = 32;
const MARKER: &[u8] = b"rpackit-response-resource-marker";

/// Secret-free evidence for response idle, sustained-rate, decoding, and
/// decoded-size enforcement.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct ResponseResourceLimitEvidence {
    /// Whether an immediate identity response completed exactly.
    pub valid_identity_baseline_passed: bool,
    /// Whether a valid gzip response decoded to the exact expected content.
    pub valid_gzip_baseline_passed: bool,
    /// Whether transformed representation metadata was removed downstream.
    pub decoded_representation_metadata_stripped: bool,
    /// Whether a response with an excessive non-empty-frame gap was cut off.
    pub idle_limit_passed: bool,
    /// Whether a response below its complete-window rate floor was cut off.
    pub minimum_rate_limit_passed: bool,
    /// Whether decoded output crossing its independent cap was cut off.
    pub decompressed_size_limit_passed: bool,
    /// Whether malformed gzip content terminated without exposing its marker.
    pub malformed_encoding_passed: bool,
    /// Whether an unsupported content coding became the exact fixed `502`.
    pub unsupported_encoding_passed: bool,
    /// Compressed byte length of the expansion fixture.
    pub compressed_expansion_encoded_bytes: u64,
    /// Decoded byte length of the expansion fixture.
    pub compressed_expansion_decoded_bytes: u64,
    /// Decoded payload bytes observed before the expansion cutoff.
    pub decompressed_bytes_forwarded: u64,
    /// Number of named negative cases attempted.
    pub cases_attempted: u32,
    /// Negative downstream connections that physically terminated boundedly.
    pub bounded_terminations: u32,
    /// Upstream requests carrying exactly one valid synthetic credential.
    pub upstream_requests_with_valid_secret: u32,
    /// Upstream requests with invalid credential multiplicity or content.
    pub upstream_requests_with_invalid_secret: u32,
    /// Requests in which the proxy-session cookie leaked upstream.
    pub proxy_cookie_leaks: u32,
    /// Requests in which the one-time bootstrap header leaked upstream.
    pub bootstrap_header_leaks: u32,
    /// Negative responses in which an attacker marker reached downstream.
    pub attacker_markers_forwarded: u32,
    /// Whether every isolated fixture and proxy shutdown completed.
    pub probe_completed: bool,
}

impl ResponseResourceLimitEvidence {
    /// Return true only when both baselines, all five independent failures,
    /// fixture bounds, authentication, leakage, and termination counters pass.
    #[must_use]
    pub const fn all_response_resource_limits_fail_closed(&self) -> bool {
        self.probe_completed
            && self.valid_identity_baseline_passed
            && self.valid_gzip_baseline_passed
            && self.decoded_representation_metadata_stripped
            && self.idle_limit_passed
            && self.minimum_rate_limit_passed
            && self.decompressed_size_limit_passed
            && self.malformed_encoding_passed
            && self.unsupported_encoding_passed
            && self.compressed_expansion_encoded_bytes > 0
            && self.compressed_expansion_encoded_bytes <= ENCODED_EXPANSION_LIMIT as u64
            && self.compressed_expansion_decoded_bytes > DECODED_EXPANSION_LIMIT as u64
            && self.decompressed_bytes_forwarded <= DECODED_EXPANSION_LIMIT as u64
            && self.cases_attempted == NEGATIVE_CASES
            && self.bounded_terminations == self.cases_attempted
            && self.upstream_requests_with_valid_secret == TOTAL_CASES
            && self.upstream_requests_with_invalid_secret == 0
            && self.proxy_cookie_leaks == 0
            && self.bootstrap_header_leaks == 0
            && self.attacker_markers_forwarded == 0
    }
}

/// Run identity and gzip baselines plus independent idle, below-rate,
/// decompression-expansion, malformed-gzip, and unsupported-coding cases
/// through isolated production proxies and real loopback sockets.
///
/// # Errors
///
/// Returns an I/O error when any isolated listener, client, proxy, codec, or
/// bounded shutdown fails.
#[allow(clippy::too_many_lines)]
pub async fn probe_response_resource_limits() -> io::Result<ResponseResourceLimitEvidence> {
    const IDENTITY_BODY: &[u8] = b"safe identity response";
    const GZIP_BODY: &[u8] = b"safe gzip response";

    let identity = run_case(
        176,
        TransportLimits {
            min_response_body_bytes_per_second: 0,
            ..TransportLimits::default()
        },
        vec![(Duration::ZERO, content_length_response(IDENTITY_BODY, &[]))],
    )
    .await?;

    let gzip_body = gzip(GZIP_BODY).await?;
    let gzip_baseline = run_case(
        177,
        TransportLimits {
            min_response_body_bytes_per_second: 0,
            ..TransportLimits::default()
        },
        vec![(
            Duration::ZERO,
            content_length_response(
                &gzip_body,
                &[
                    ("Content-Encoding", "gzip"),
                    ("ETag", "\"encoded-etag\""),
                    ("Accept-Ranges", "bytes"),
                    ("Digest", "sha-256=safe-placeholder"),
                ],
            ),
        )],
    )
    .await?;

    let idle_first = response_prefix_with_body(4 + MARKER.len(), &[], b"safe");
    let idle = run_case(
        178,
        TransportLimits {
            response_body_idle_timeout: Duration::from_millis(100),
            min_response_body_bytes_per_second: 0,
            response_body_rate_window: Duration::from_millis(200),
            ..TransportLimits::default()
        },
        vec![
            (Duration::ZERO, idle_first),
            (Duration::from_millis(400), MARKER.to_vec()),
        ],
    )
    .await?;

    let rate_length = 4 + 4 + MARKER.len();
    let rate = run_case(
        179,
        TransportLimits {
            response_body_idle_timeout: Duration::from_secs(1),
            min_response_body_bytes_per_second: 1_000,
            response_body_rate_window: Duration::from_millis(200),
            ..TransportLimits::default()
        },
        vec![
            (
                Duration::ZERO,
                response_prefix_with_body(rate_length, &[], b"safe"),
            ),
            (Duration::from_millis(60), b"x".to_vec()),
            (Duration::from_millis(60), b"x".to_vec()),
            (Duration::from_millis(60), b"x".to_vec()),
            (Duration::from_millis(60), b"x".to_vec()),
            (Duration::from_millis(300), MARKER.to_vec()),
        ],
    )
    .await?;

    let mut expansion_body = vec![b'a'; 4096];
    expansion_body.extend_from_slice(MARKER);
    let compressed_expansion = gzip(&expansion_body).await?;
    let expansion = run_case(
        180,
        TransportLimits {
            max_response_body_bytes: ENCODED_EXPANSION_LIMIT,
            max_decoded_response_body_bytes: DECODED_EXPANSION_LIMIT,
            min_response_body_bytes_per_second: 0,
            ..TransportLimits::default()
        },
        vec![(
            Duration::ZERO,
            content_length_response(&compressed_expansion, &[("Content-Encoding", "gzip")]),
        )],
    )
    .await?;

    let malformed = run_case(
        181,
        TransportLimits {
            min_response_body_bytes_per_second: 0,
            ..TransportLimits::default()
        },
        vec![(
            Duration::ZERO,
            content_length_response(MARKER, &[("Content-Encoding", "gzip")]),
        )],
    )
    .await?;

    let unsupported = run_case(
        182,
        TransportLimits {
            min_response_body_bytes_per_second: 0,
            ..TransportLimits::default()
        },
        vec![(
            Duration::ZERO,
            content_length_response(MARKER, &[("Content-Encoding", "compress")]),
        )],
    )
    .await?;

    Ok(summarize(
        &identity,
        &gzip_baseline,
        &idle,
        &rate,
        &expansion,
        &malformed,
        &unsupported,
        compressed_expansion.len(),
        expansion_body.len(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn summarize(
    identity: &CaseObservation,
    gzip_baseline: &CaseObservation,
    idle: &CaseObservation,
    rate: &CaseObservation,
    expansion: &CaseObservation,
    malformed: &CaseObservation,
    unsupported: &CaseObservation,
    expansion_encoded_bytes: usize,
    expansion_decoded_bytes: usize,
) -> ResponseResourceLimitEvidence {
    let (gzip_body_passed, metadata_stripped) =
        decoded_gzip_baseline(&gzip_baseline.downstream.response);
    let negative = [idle, rate, expansion, malformed, unsupported];
    let decompressed_bytes_forwarded =
        downstream_payload_bytes(&expansion.downstream.response).unwrap_or(u64::MAX);
    let mut evidence = ResponseResourceLimitEvidence {
        valid_identity_baseline_passed: crate::valid_downstream_http_body(
            &identity.downstream.response,
            b"safe identity response",
        ),
        valid_gzip_baseline_passed: gzip_body_passed,
        decoded_representation_metadata_stripped: metadata_stripped,
        idle_limit_passed: safe_stream_cutoff(idle),
        minimum_rate_limit_passed: safe_stream_cutoff(rate),
        decompressed_size_limit_passed: safe_stream_cutoff(expansion)
            && decompressed_bytes_forwarded <= DECODED_EXPANSION_LIMIT as u64,
        malformed_encoding_passed: safe_stream_cutoff(malformed),
        unsupported_encoding_passed: is_exact_fixed_bad_gateway(&unsupported.downstream.response),
        compressed_expansion_encoded_bytes: u64::try_from(expansion_encoded_bytes)
            .unwrap_or(u64::MAX),
        compressed_expansion_decoded_bytes: u64::try_from(expansion_decoded_bytes)
            .unwrap_or(u64::MAX),
        decompressed_bytes_forwarded,
        cases_attempted: NEGATIVE_CASES,
        bounded_terminations: negative
            .iter()
            .filter(|case| case.downstream.physical_closed)
            .count()
            .try_into()
            .unwrap_or(u32::MAX),
        probe_completed: true,
        ..ResponseResourceLimitEvidence::default()
    };
    for case in [
        identity,
        gzip_baseline,
        idle,
        rate,
        expansion,
        malformed,
        unsupported,
    ] {
        evidence.upstream_requests_with_valid_secret += u32::from(case.valid_secret);
        evidence.upstream_requests_with_invalid_secret += u32::from(!case.valid_secret);
        evidence.proxy_cookie_leaks += u32::from(case.proxy_cookie_leaked);
        evidence.bootstrap_header_leaks += u32::from(case.bootstrap_header_leaked);
    }
    evidence.attacker_markers_forwarded = negative
        .iter()
        .filter(|case| {
            case.downstream
                .response
                .windows(MARKER.len())
                .any(|window| window == MARKER)
        })
        .count()
        .try_into()
        .unwrap_or(u32::MAX);
    evidence
}

fn decoded_gzip_baseline(response: &[u8]) -> (bool, bool) {
    let Some((status, headers, wire_body)) = parse_raw_response(response) else {
        return (false, false);
    };
    let body = crate::decode_downstream_body(&headers, wire_body);
    let metadata_stripped = !headers.contains_key("content-encoding")
        && !headers.contains_key("content-length")
        && !headers.contains_key("etag")
        && !headers.contains_key("accept-ranges")
        && !headers.contains_key("digest");
    (
        status == "HTTP/1.1 200 OK"
            && downstream_connection_closes(response)
            && body.as_deref() == Some(b"safe gzip response"),
        metadata_stripped,
    )
}

fn safe_stream_cutoff(case: &CaseObservation) -> bool {
    case.downstream.physical_closed
        && case.downstream.second_request_attempted
        && !case.downstream.second_response_received
        && downstream_connection_closes(&case.downstream.response)
        && !case
            .downstream
            .response
            .windows(MARKER.len())
            .any(|window| window == MARKER)
}

fn downstream_payload_bytes(response: &[u8]) -> Option<u64> {
    if !response.windows(4).any(|window| window == b"\r\n\r\n") {
        return Some(0);
    }
    let (_, headers, mut body) = parse_raw_response(response)?;
    if !headers
        .get("transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        return u64::try_from(body.len()).ok();
    }
    let mut total = 0_u64;
    loop {
        let line_end = body.windows(2).position(|window| window == b"\r\n")?;
        let size_text = std::str::from_utf8(&body[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Some(total);
        }
        let available = size.min(body.len());
        total = total.checked_add(u64::try_from(available).ok()?)?;
        if available < size {
            return Some(total);
        }
        body = &body[size..];
        if !body.starts_with(b"\r\n") {
            return Some(total);
        }
        body = &body[2..];
    }
}

struct CaseObservation {
    downstream: BodyClientObservation,
    valid_secret: bool,
    proxy_cookie_leaked: bool,
    bootstrap_header_leaked: bool,
}

struct UpstreamObservation {
    valid_secret: bool,
    proxy_cookie_leaked: bool,
    bootstrap_header_leaked: bool,
}

async fn run_case(
    nonce: u8,
    limits: TransportLimits,
    fragments: Vec<(Duration, Vec<u8>)>,
) -> io::Result<CaseObservation> {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    let upstream_address = listener.local_addr()?;
    let session = Arc::new(Secret::from_bytes([nonce; 32]));
    let upstream = Arc::new(Secret::from_bytes([nonce.wrapping_add(1); 32]));
    let bootstrap = Arc::new(Secret::from_bytes([nonce.wrapping_add(2); 32]));
    let server_secret = Arc::clone(&upstream);
    let server =
        tokio::spawn(async move { serve_response(listener, server_secret, fragments).await });
    let hostname = format!("rpackit-{}.localhost", hex::encode([nonce; 16]));
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
    let downstream = request_authenticated_body_probe(&proxy, session.as_ref(), "GET").await?;
    proxy.shutdown().await.map_err(io::Error::other)?;
    let upstream = server
        .await
        .map_err(|_| io::Error::other("response resource upstream task terminated"))??;
    Ok(CaseObservation {
        downstream,
        valid_secret: upstream.valid_secret,
        proxy_cookie_leaked: upstream.proxy_cookie_leaked,
        bootstrap_header_leaked: upstream.bootstrap_header_leaked,
    })
}

async fn serve_response(
    listener: TcpListener,
    expected_secret: Arc<Secret>,
    fragments: Vec<(Duration, Vec<u8>)>,
) -> io::Result<UpstreamObservation> {
    let (mut socket, peer) = timeout(Duration::from_secs(2), listener.accept())
        .await
        .map_err(|_| io::Error::other("response resource accept timed out"))??;
    if !peer.ip().is_loopback() {
        return Err(io::Error::other(
            "response resource probe received a non-loopback peer",
        ));
    }
    let request = crate::read_bounded_header(&mut socket).await?;
    let observation = UpstreamObservation {
        valid_secret: single_header_matches(&request, b"shiny-shared-secret", &expected_secret),
        proxy_cookie_leaked: !raw_header_values(&request, b"cookie").is_empty(),
        bootstrap_header_leaked: !raw_header_values(&request, b"x-rpackit-bootstrap").is_empty(),
    };
    for (delay, fragment) in fragments {
        tokio::time::sleep(delay).await;
        if socket.write_all(&fragment).await.is_err() {
            break;
        }
    }
    let _ = socket.shutdown().await;
    Ok(observation)
}

fn content_length_response(body: &[u8], extra_headers: &[(&str, &str)]) -> Vec<u8> {
    let length = body.len().to_string();
    let mut headers = Vec::with_capacity(extra_headers.len() + 3);
    headers.push(("Content-Type", "text/plain"));
    headers.push(("Content-Length", length.as_str()));
    headers.extend_from_slice(extra_headers);
    headers.push(("Connection", "close"));
    raw_response("200 OK", &headers, body)
}

fn response_prefix_with_body(
    content_length: usize,
    extra_headers: &[(&str, &str)],
    first_body: &[u8],
) -> Vec<u8> {
    let length = content_length.to_string();
    let mut headers = Vec::with_capacity(extra_headers.len() + 3);
    headers.push(("Content-Type", "text/plain"));
    headers.push(("Content-Length", length.as_str()));
    headers.extend_from_slice(extra_headers);
    headers.push(("Connection", "close"));
    let mut response = raw_response_prefix("200 OK", &headers);
    response.extend_from_slice(b"\r\n");
    response.extend_from_slice(first_body);
    response
}

async fn gzip(content: &[u8]) -> io::Result<Vec<u8>> {
    let capacity = content.len().saturating_mul(2).max(64 * 1024);
    let (writer, mut reader) = tokio::io::duplex(capacity);
    let mut encoder = GzipEncoder::new(writer);
    encoder.write_all(content).await?;
    encoder.shutdown().await?;
    drop(encoder);
    let mut compressed = Vec::new();
    reader.read_to_end(&mut compressed).await?;
    Ok(compressed)
}
