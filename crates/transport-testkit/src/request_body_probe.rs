//! Secret-free real-loopback evidence for authenticated request-body limits.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use rpackit_transport::{
    ProxyConfig, RunningProxy, SESSION_COOKIE_NAME, Secret, TransportLimits, TransportSecrets,
};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    time::timeout,
};

use crate::{ExternalCollector, MockUpstream, UpstreamSnapshot};

const NEGATIVE_CASES: u32 = 5;
const MINIMUM_UPSTREAM_REQUESTS: u64 = 4;
const MAXIMUM_UPSTREAM_REQUESTS: u64 = 6;

/// Secret-free evidence for request upload byte, idle, rate, duration, and
/// trailer enforcement.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct RequestBodyLimitEvidence {
    /// Whether a bounded immediate upload completed successfully.
    pub valid_baseline_passed: bool,
    /// Whether a chunked upload was cut off before crossing the byte cap.
    pub byte_limit_passed: bool,
    /// Whether an otherwise-completing upload was cut off by its idle gap.
    pub idle_limit_passed: bool,
    /// Whether an otherwise-completing upload was cut off below its rate floor.
    pub minimum_rate_limit_passed: bool,
    /// Whether an otherwise-completing upload was cut off at its total timeout.
    pub total_timeout_limit_passed: bool,
    /// Whether a parsed request trailer frame was rejected before completion.
    pub trailer_limit_passed: bool,
    /// Number of named negative cases attempted.
    pub cases_attempted: u32,
    /// Negative cases that terminated before the bounded client deadline.
    pub bounded_terminations: u32,
    /// Requests observed at the expected body-probe route.
    ///
    /// Four content-length cases must reach the route. Either chunked failure
    /// may be detected before or after its upstream request head is released,
    /// so the accepted total is four through six.
    pub upstream_body_probe_requests: u64,
    /// Requests carrying exactly one valid synthetic upstream credential.
    pub upstream_requests_with_valid_secret: u64,
    /// Requests with invalid protected-header multiplicity or content.
    pub upstream_requests_with_invalid_secret: u64,
    /// Requests in which the proxy-session cookie leaked upstream.
    pub proxy_cookie_leaks: u64,
    /// Requests in which the one-time bootstrap header leaked upstream.
    pub bootstrap_header_leaks: u64,
    /// Whether every isolated fixture and proxy shutdown completed.
    pub probe_completed: bool,
}

impl RequestBodyLimitEvidence {
    /// Return true only when the baseline, all five negative cases, bounded
    /// termination, upstream authentication, and leakage counters pass.
    #[must_use]
    pub const fn all_request_body_limits_fail_closed(&self) -> bool {
        self.probe_completed
            && self.valid_baseline_passed
            && self.byte_limit_passed
            && self.idle_limit_passed
            && self.minimum_rate_limit_passed
            && self.total_timeout_limit_passed
            && self.trailer_limit_passed
            && self.cases_attempted == NEGATIVE_CASES
            && self.bounded_terminations == self.cases_attempted
            && self.upstream_body_probe_requests >= MINIMUM_UPSTREAM_REQUESTS
            && self.upstream_body_probe_requests <= MAXIMUM_UPSTREAM_REQUESTS
            && self.upstream_requests_with_valid_secret == self.upstream_body_probe_requests
            && self.upstream_requests_with_invalid_secret == 0
            && self.proxy_cookie_leaks == 0
            && self.bootstrap_header_leaks == 0
    }
}

/// Run one valid upload and independent byte, idle, minimum-rate, total-time,
/// and trailer failures through isolated real-loopback proxies.
///
/// # Errors
///
/// Returns an I/O error if a loopback fixture cannot start or stop, or if any
/// client connection does not terminate within its bounded deadline.
pub async fn probe_request_body_limits() -> io::Result<RequestBodyLimitEvidence> {
    let baseline = run_case(
        160,
        TransportLimits {
            request_body_idle_timeout: Duration::from_millis(150),
            request_body_total_timeout: Duration::from_secs(1),
            min_request_body_bytes_per_second: 1_000,
            request_body_rate_window: Duration::from_millis(200),
            ..TransportLimits::default()
        },
        BodyRequest::ContentLength(vec![(Duration::ZERO, vec![b'x'; 512])]),
    )
    .await?;
    let idle = run_case(
        161,
        TransportLimits {
            request_body_idle_timeout: Duration::from_millis(100),
            request_body_total_timeout: Duration::from_secs(2),
            min_request_body_bytes_per_second: 0,
            request_body_rate_window: Duration::from_millis(200),
            ..TransportLimits::default()
        },
        BodyRequest::ContentLength(vec![
            (Duration::ZERO, b"safe".to_vec()),
            (Duration::from_millis(400), b"body".to_vec()),
        ]),
    )
    .await?;
    let rate = run_case(
        162,
        TransportLimits {
            request_body_idle_timeout: Duration::from_secs(1),
            request_body_total_timeout: Duration::from_secs(2),
            min_request_body_bytes_per_second: 1_000,
            request_body_rate_window: Duration::from_millis(200),
            ..TransportLimits::default()
        },
        BodyRequest::ContentLength(
            (0..10)
                .map(|_| (Duration::from_millis(60), vec![b'x']))
                .collect(),
        ),
    )
    .await?;
    let total = run_case(
        163,
        TransportLimits {
            request_body_idle_timeout: Duration::from_secs(1),
            request_body_total_timeout: Duration::from_millis(250),
            min_request_body_bytes_per_second: 0,
            request_body_rate_window: Duration::from_millis(100),
            ..TransportLimits::default()
        },
        BodyRequest::ContentLength(
            (0..6)
                .map(|_| (Duration::from_millis(80), vec![b'x']))
                .collect(),
        ),
    )
    .await?;
    let byte_limit = run_case(
        164,
        TransportLimits {
            max_request_body_bytes: 4,
            ..TransportLimits::default()
        },
        BodyRequest::ChunkedOverLimit,
    )
    .await?;
    let trailer = run_case(165, TransportLimits::default(), BodyRequest::ChunkedTrailer).await?;
    Ok(summarize_cases(
        &baseline,
        &byte_limit,
        &idle,
        &rate,
        &total,
        &trailer,
    ))
}

fn summarize_cases(
    baseline: &CaseObservation,
    byte_limit: &CaseObservation,
    idle: &CaseObservation,
    rate: &CaseObservation,
    total: &CaseObservation,
    trailer: &CaseObservation,
) -> RequestBodyLimitEvidence {
    let mut evidence = RequestBodyLimitEvidence {
        valid_baseline_passed: response_has_status(&baseline.response, 204),
        byte_limit_passed: response_has_status(&byte_limit.response, 502),
        idle_limit_passed: !response_has_status(&idle.response, 204),
        minimum_rate_limit_passed: !response_has_status(&rate.response, 204),
        total_timeout_limit_passed: !response_has_status(&total.response, 204),
        trailer_limit_passed: response_has_status(&trailer.response, 502),
        cases_attempted: NEGATIVE_CASES,
        bounded_terminations: u32::from(idle.bounded)
            + u32::from(rate.bounded)
            + u32::from(total.bounded)
            + u32::from(byte_limit.bounded)
            + u32::from(trailer.bounded),
        probe_completed: true,
        ..RequestBodyLimitEvidence::default()
    };
    for observation in [&baseline, &idle, &rate, &total, &byte_limit, &trailer] {
        evidence.upstream_body_probe_requests += observation
            .upstream
            .routes
            .get("/api/body-probe")
            .copied()
            .unwrap_or(0);
        evidence.upstream_requests_with_valid_secret += observation.upstream.protected_header_valid;
        evidence.upstream_requests_with_invalid_secret +=
            observation.upstream.protected_header_invalid_count;
        evidence.proxy_cookie_leaks += observation.upstream.proxy_cookie_leaks;
        evidence.bootstrap_header_leaks += observation.upstream.bootstrap_header_leaks;
    }
    evidence
}

struct CaseObservation {
    response: Vec<u8>,
    bounded: bool,
    upstream: UpstreamSnapshot,
}

enum BodyRequest {
    ContentLength(Vec<(Duration, Vec<u8>)>),
    ChunkedOverLimit,
    ChunkedTrailer,
}

async fn run_case(
    nonce: u8,
    limits: TransportLimits,
    request: BodyRequest,
) -> io::Result<CaseObservation> {
    let session = Arc::new(Secret::from_bytes([nonce; 32]));
    let upstream_secret = Arc::new(Secret::from_bytes([nonce.wrapping_add(1); 32]));
    let bootstrap = Arc::new(Secret::from_bytes([nonce.wrapping_add(2); 32]));
    let collector = ExternalCollector::start().await?;
    let upstream = MockUpstream::start(Arc::clone(&upstream_secret), collector.address()).await?;
    let hostname = format!("rpackit-{}.localhost", hex::encode([nonce; 16]));
    let config = ProxyConfig::explicit(
        upstream.address(),
        hostname,
        TransportSecrets::new(Arc::clone(&session), upstream_secret, bootstrap),
    )
    .map_err(io::Error::other)?
    .with_limits(limits);
    let proxy = RunningProxy::start(config)
        .await
        .map_err(io::Error::other)?;

    let response_result = match request {
        BodyRequest::ContentLength(fragments) => {
            send_fragmented_body(&proxy, session.as_ref(), fragments).await
        }
        BodyRequest::ChunkedOverLimit => send_chunked_over_limit(&proxy, session.as_ref()).await,
        BodyRequest::ChunkedTrailer => send_chunked_trailer(&proxy, session.as_ref()).await,
    };
    let upstream_snapshot = upstream.snapshot().await;
    let proxy_shutdown = proxy.shutdown().await.map_err(io::Error::other);
    let upstream_shutdown = upstream.shutdown().await;
    let collector_shutdown = collector.shutdown().await;
    let (response, bounded) = response_result?;
    proxy_shutdown?;
    upstream_shutdown?;
    collector_shutdown?;
    Ok(CaseObservation {
        response,
        bounded,
        upstream: upstream_snapshot,
    })
}

async fn send_chunked_over_limit(
    proxy: &RunningProxy,
    session: &Secret,
) -> io::Result<(Vec<u8>, bool)> {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), proxy.address().port());
    let request = session.with_exposed(|value| {
        format!(
            "POST /api/body-probe HTTP/1.1\r\nHost: {}\r\nCookie: {SESSION_COOKIE_NAME}={value}\r\nOrigin: {}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n8\r\noverload\r\n0\r\n\r\n",
            proxy.address().authority(),
            proxy.address().origin(),
        )
    });
    let mut socket = TcpStream::connect(address).await?;
    socket.write_all(request.as_bytes()).await?;
    read_bounded_response(socket).await
}

async fn send_chunked_trailer(
    proxy: &RunningProxy,
    session: &Secret,
) -> io::Result<(Vec<u8>, bool)> {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), proxy.address().port());
    let request = session.with_exposed(|value| {
        format!(
            "POST /api/body-probe HTTP/1.1\r\nHost: {}\r\nCookie: {SESSION_COOKIE_NAME}={value}\r\nOrigin: {}\r\nTransfer-Encoding: chunked\r\nTrailer: X-Untrusted\r\nConnection: close\r\n\r\n4\r\nsafe\r\n0\r\nX-Untrusted: value\r\n\r\n",
            proxy.address().authority(),
            proxy.address().origin(),
        )
    });
    let mut socket = TcpStream::connect(address).await?;
    socket.write_all(request.as_bytes()).await?;
    read_bounded_response(socket).await
}

async fn send_fragmented_body(
    proxy: &RunningProxy,
    session: &Secret,
    fragments: Vec<(Duration, Vec<u8>)>,
) -> io::Result<(Vec<u8>, bool)> {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), proxy.address().port());
    let content_length = fragments
        .iter()
        .try_fold(0_usize, |total, (_, fragment)| {
            total.checked_add(fragment.len())
        })
        .ok_or_else(|| io::Error::other("body probe length overflow"))?;
    let headers = session.with_exposed(|value| {
        format!(
            "POST /api/body-probe HTTP/1.1\r\nHost: {}\r\nCookie: {SESSION_COOKIE_NAME}={value}\r\nOrigin: {}\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n",
            proxy.address().authority(),
            proxy.address().origin(),
        )
    });
    let mut socket = TcpStream::connect(address).await?;
    socket.write_all(headers.as_bytes()).await?;
    for (delay, fragment) in fragments {
        tokio::time::sleep(delay).await;
        if socket.write_all(&fragment).await.is_err() {
            break;
        }
    }
    read_bounded_response(socket).await
}

async fn read_bounded_response(mut socket: TcpStream) -> io::Result<(Vec<u8>, bool)> {
    let mut response = Vec::new();
    match timeout(Duration::from_secs(2), socket.read_to_end(&mut response)).await {
        Ok(Ok(_)) => Ok((response, true)),
        Ok(Err(error))
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
            ) =>
        {
            Ok((response, true))
        }
        Ok(Err(error)) => Err(error),
        Err(_) => Err(io::Error::other(
            "request-body resource probe did not terminate",
        )),
    }
}

fn response_has_status(response: &[u8], status: u16) -> bool {
    response.starts_with(format!("HTTP/1.1 {status} ").as_bytes())
}
