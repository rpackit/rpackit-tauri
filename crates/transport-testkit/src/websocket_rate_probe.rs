//! Secret-free real-loopback evidence for WebSocket byte-rate shaping.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use futures_util::{SinkExt as _, StreamExt as _};
use http::{
    HeaderMap, HeaderValue, Method, Version,
    header::{
        CONNECTION, COOKIE, HOST, ORIGIN, SEC_WEBSOCKET_EXTENSIONS, SEC_WEBSOCKET_VERSION, UPGRADE,
    },
};
use rpackit_transport::{
    BOOTSTRAP_HEADER_NAME, ProxyConfig, RunningProxy, SESSION_COOKIE_NAME, Secret, TransportLimits,
    TransportSecrets,
};
use serde::Serialize;
use tokio::{net::TcpListener, time::timeout};
use tokio_tungstenite::{
    accept_hdr_async, connect_async,
    tungstenite::{
        Message,
        client::IntoClientRequest as _,
        handshake::server::{Request, Response},
    },
};

const RATE_CASES: u32 = 2;
const TOTAL_CASES: u32 = RATE_CASES + 1;
const MAX_BYTES_PER_SECOND: u64 = 100;
const BURST_WINDOW_MILLIS: u64 = 100;
const BURST_WINDOW: Duration = Duration::from_millis(BURST_WINDOW_MILLIS);
const PAYLOAD_BYTES: usize = 100;
const MINIMUM_SHAPED_MILLIS: u64 = 750;
const CASE_DEADLINE: Duration = Duration::from_secs(4);
const PAYLOAD_BYTE: u8 = 0x5a;
const PROTECTED_HEADER: &str = "shiny-shared-secret";

/// Secret-free evidence that raw WebSocket bytes are independently shaped in
/// both tunnel directions.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct WebSocketRateLimitEvidence {
    /// Whether a small authenticated WebSocket round trip completed exactly.
    pub valid_small_baseline_passed: bool,
    /// Whether client-to-upstream payload delivery respected the rate ceiling.
    pub client_to_upstream_rate_bounded: bool,
    /// Whether upstream-to-client payload delivery respected the rate ceiling.
    pub upstream_to_client_rate_bounded: bool,
    /// Application payload bytes used by each directional rate case.
    pub payload_bytes: u64,
    /// Configured maximum raw bytes per second in each direction.
    pub max_bytes_per_second: u64,
    /// Configured per-direction initial burst window in milliseconds.
    pub burst_window_millis: u64,
    /// Measured client-to-upstream delivery and acknowledgement time.
    pub client_to_upstream_elapsed_millis: u64,
    /// Measured upstream-to-client delivery time.
    pub upstream_to_client_elapsed_millis: u64,
    /// Number of independent directional rate cases attempted.
    pub rate_cases_attempted: u32,
    /// Directional rate cases that completed before the fixed deadline.
    pub bounded_completions: u32,
    /// Upstream handshakes carrying exactly one valid synthetic credential.
    pub upstream_requests_with_valid_secret: u32,
    /// Upstream handshakes with invalid credential multiplicity or content.
    pub upstream_requests_with_invalid_secret: u32,
    /// Upstream handshakes with the exact normalized WebSocket request shape.
    pub normalized_upstream_websocket_requests: u32,
    /// Upstream handshakes in which the proxy-session cookie leaked.
    pub proxy_cookie_leaks: u32,
    /// Upstream handshakes in which the one-time bootstrap header leaked.
    pub bootstrap_header_leaks: u32,
    /// Whether every isolated listener, proxy, and client completed.
    pub probe_completed: bool,
}

impl WebSocketRateLimitEvidence {
    /// Return true only when the baseline, both directional rate bounds,
    /// authentication, request normalization, and leakage counters pass.
    #[must_use]
    pub const fn all_websocket_byte_rates_are_bounded(&self) -> bool {
        self.probe_completed
            && self.valid_small_baseline_passed
            && self.client_to_upstream_rate_bounded
            && self.upstream_to_client_rate_bounded
            && self.payload_bytes == PAYLOAD_BYTES as u64
            && self.max_bytes_per_second == MAX_BYTES_PER_SECOND
            && self.burst_window_millis == BURST_WINDOW_MILLIS
            && self.client_to_upstream_elapsed_millis >= MINIMUM_SHAPED_MILLIS
            && self.upstream_to_client_elapsed_millis >= MINIMUM_SHAPED_MILLIS
            && self.rate_cases_attempted == RATE_CASES
            && self.bounded_completions == self.rate_cases_attempted
            && self.upstream_requests_with_valid_secret == TOTAL_CASES
            && self.upstream_requests_with_invalid_secret == 0
            && self.normalized_upstream_websocket_requests == TOTAL_CASES
            && self.proxy_cookie_leaks == 0
            && self.bootstrap_header_leaks == 0
    }
}

/// Run a small baseline plus independent upload and download rate cases through
/// production proxies and real loopback WebSocket peers.
///
/// # Errors
///
/// Returns an I/O error when a listener, handshake, bounded message exchange,
/// proxy shutdown, or upstream task fails.
pub async fn probe_websocket_rate_limits() -> io::Result<WebSocketRateLimitEvidence> {
    let baseline = run_case(190, CaseKind::Baseline).await?;
    let upload = run_case(191, CaseKind::Upload).await?;
    let download = run_case(192, CaseKind::Download).await?;

    let mut evidence = WebSocketRateLimitEvidence {
        valid_small_baseline_passed: baseline.payload_valid,
        client_to_upstream_rate_bounded: upload.payload_valid
            && upload.elapsed >= Duration::from_millis(MINIMUM_SHAPED_MILLIS)
            && upload.elapsed < CASE_DEADLINE,
        upstream_to_client_rate_bounded: download.payload_valid
            && download.elapsed >= Duration::from_millis(MINIMUM_SHAPED_MILLIS)
            && download.elapsed < CASE_DEADLINE,
        payload_bytes: PAYLOAD_BYTES as u64,
        max_bytes_per_second: MAX_BYTES_PER_SECOND,
        burst_window_millis: u64::try_from(BURST_WINDOW.as_millis()).unwrap_or(u64::MAX),
        client_to_upstream_elapsed_millis: duration_millis(upload.elapsed),
        upstream_to_client_elapsed_millis: duration_millis(download.elapsed),
        rate_cases_attempted: RATE_CASES,
        bounded_completions: u32::from(upload.elapsed < CASE_DEADLINE)
            + u32::from(download.elapsed < CASE_DEADLINE),
        probe_completed: true,
        ..WebSocketRateLimitEvidence::default()
    };
    for case in [&baseline, &upload, &download] {
        evidence.upstream_requests_with_valid_secret += u32::from(case.handshake.valid_secret);
        evidence.upstream_requests_with_invalid_secret += u32::from(!case.handshake.valid_secret);
        evidence.normalized_upstream_websocket_requests +=
            u32::from(case.handshake.normalized_request);
        evidence.proxy_cookie_leaks += u32::from(case.handshake.proxy_cookie_leaked);
        evidence.bootstrap_header_leaks += u32::from(case.handshake.bootstrap_header_leaked);
    }
    Ok(evidence)
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[derive(Clone, Copy)]
enum CaseKind {
    Baseline,
    Upload,
    Download,
}

struct CaseObservation {
    payload_valid: bool,
    elapsed: Duration,
    handshake: HandshakeObservation,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default)]
struct HandshakeObservation {
    valid_secret: bool,
    normalized_request: bool,
    proxy_cookie_leaked: bool,
    bootstrap_header_leaked: bool,
}

struct ServerObservation {
    payload_valid: bool,
    handshake: HandshakeObservation,
}

async fn run_case(nonce: u8, kind: CaseKind) -> io::Result<CaseObservation> {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    let upstream_address = listener.local_addr()?;
    let session = Arc::new(Secret::from_bytes([nonce; 32]));
    let upstream = Arc::new(Secret::from_bytes([nonce.wrapping_add(1); 32]));
    let bootstrap = Arc::new(Secret::from_bytes([nonce.wrapping_add(2); 32]));
    let server_secret = Arc::clone(&upstream);
    let server =
        tokio::spawn(
            async move { serve_case(listener, upstream_address, server_secret, kind).await },
        );

    let limits = TransportLimits {
        websocket_idle_timeout: Duration::from_secs(5),
        max_websocket_bytes_per_second: MAX_BYTES_PER_SECOND,
        websocket_rate_burst_window: BURST_WINDOW,
        ..TransportLimits::default()
    };
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

    let client_result = run_client_case(&proxy, session.as_ref(), kind).await;
    let shutdown_result = proxy.shutdown().await.map_err(io::Error::other);
    let server_result = timeout(Duration::from_secs(2), server)
        .await
        .map_err(|_| io::Error::other("WebSocket rate upstream task timed out"))?
        .map_err(|_| io::Error::other("WebSocket rate upstream task terminated"))?;
    shutdown_result?;
    let (client_payload_valid, elapsed) = client_result?;
    let server = server_result?;
    Ok(CaseObservation {
        payload_valid: client_payload_valid && server.payload_valid,
        elapsed,
        handshake: server.handshake,
    })
}

async fn run_client_case(
    proxy: &RunningProxy,
    session: &Secret,
    kind: CaseKind,
) -> io::Result<(bool, Duration)> {
    let physical = format!("ws://127.0.0.1:{}/ws-rate", proxy.address().port());
    let mut request = physical.into_client_request().map_err(io::Error::other)?;
    request.headers_mut().insert(
        HOST,
        HeaderValue::from_str(&proxy.address().authority()).map_err(io::Error::other)?,
    );
    request.headers_mut().insert(
        ORIGIN,
        HeaderValue::from_str(&proxy.address().origin()).map_err(io::Error::other)?,
    );
    let cookie = session.with_exposed(|value| format!("{SESSION_COOKIE_NAME}={value}"));
    request.headers_mut().insert(
        COOKIE,
        HeaderValue::from_str(&cookie).map_err(io::Error::other)?,
    );
    let (mut websocket, response) = timeout(Duration::from_secs(2), connect_async(request))
        .await
        .map_err(|_| io::Error::other("WebSocket rate client handshake timed out"))?
        .map_err(io::Error::other)?;
    if response.status() != http::StatusCode::SWITCHING_PROTOCOLS {
        return Err(io::Error::other(
            "WebSocket rate client did not switch protocols",
        ));
    }

    let started = Instant::now();
    let payload_valid = timeout(CASE_DEADLINE, async {
        match kind {
            CaseKind::Baseline => {
                websocket
                    .send(Message::Text("ok".into()))
                    .await
                    .map_err(io::Error::other)?;
                let message = next_message(&mut websocket).await?;
                Ok::<bool, io::Error>(message == Message::Text("ok".into()))
            }
            CaseKind::Upload => {
                websocket
                    .send(Message::Binary(vec![PAYLOAD_BYTE; PAYLOAD_BYTES].into()))
                    .await
                    .map_err(io::Error::other)?;
                let message = next_message(&mut websocket).await?;
                Ok::<bool, io::Error>(message == Message::Text("upload-ack".into()))
            }
            CaseKind::Download => {
                websocket
                    .send(Message::Text("go".into()))
                    .await
                    .map_err(io::Error::other)?;
                let message = next_message(&mut websocket).await?;
                Ok::<bool, io::Error>(
                    message == Message::Binary(vec![PAYLOAD_BYTE; PAYLOAD_BYTES].into()),
                )
            }
        }
    })
    .await
    .map_err(|_| io::Error::other("WebSocket rate message exchange timed out"))??;
    let elapsed = started.elapsed();
    drop(websocket);
    Ok((payload_valid, elapsed))
}

async fn next_message<S>(
    websocket: &mut tokio_tungstenite::WebSocketStream<S>,
) -> io::Result<Message>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    websocket
        .next()
        .await
        .ok_or_else(|| io::Error::other("WebSocket rate peer closed before message"))?
        .map_err(io::Error::other)
}

#[allow(clippy::result_large_err)]
async fn serve_case(
    listener: TcpListener,
    upstream_address: SocketAddr,
    expected_secret: Arc<Secret>,
    kind: CaseKind,
) -> io::Result<ServerObservation> {
    let (socket, peer) = timeout(Duration::from_secs(2), listener.accept())
        .await
        .map_err(|_| io::Error::other("WebSocket rate upstream accept timed out"))??;
    if !peer.ip().is_loopback() {
        return Err(io::Error::other(
            "WebSocket rate upstream accepted a non-loopback peer",
        ));
    }

    let observation = Arc::new(Mutex::new(HandshakeObservation::default()));
    let callback_observation = Arc::clone(&observation);
    let expected_origin = format!("http://{upstream_address}");
    let mut websocket = timeout(
        Duration::from_secs(2),
        accept_hdr_async(socket, move |request: &Request, response: Response| {
            let captured = inspect_handshake(request, expected_secret.as_ref(), &expected_origin);
            if let Ok(mut observation) = callback_observation.lock() {
                *observation = captured;
            }
            Ok(response)
        }),
    )
    .await
    .map_err(|_| io::Error::other("WebSocket rate upstream handshake timed out"))?
    .map_err(io::Error::other)?;

    let payload_valid = match kind {
        CaseKind::Baseline => {
            let message = next_message(&mut websocket).await?;
            let valid = message == Message::Text("ok".into());
            websocket.send(message).await.map_err(io::Error::other)?;
            valid
        }
        CaseKind::Upload => {
            let message = next_message(&mut websocket).await?;
            let valid = message == Message::Binary(vec![PAYLOAD_BYTE; PAYLOAD_BYTES].into());
            websocket
                .send(Message::Text("upload-ack".into()))
                .await
                .map_err(io::Error::other)?;
            valid
        }
        CaseKind::Download => {
            let message = next_message(&mut websocket).await?;
            let valid = message == Message::Text("go".into());
            websocket
                .send(Message::Binary(vec![PAYLOAD_BYTE; PAYLOAD_BYTES].into()))
                .await
                .map_err(io::Error::other)?;
            valid
        }
    };
    drop(websocket);
    let handshake = observation
        .lock()
        .map_err(|_| io::Error::other("WebSocket rate observation lock failed"))?
        .clone();
    Ok(ServerObservation {
        payload_valid,
        handshake,
    })
}

fn inspect_handshake(
    request: &Request,
    expected_secret: &Secret,
    expected_origin: &str,
) -> HandshakeObservation {
    let protected: Vec<&HeaderValue> = request.headers().get_all(PROTECTED_HEADER).iter().collect();
    let valid_secret = protected.len() == 1 && expected_secret.matches(protected[0].as_bytes());
    let normalized_request = request.method() == Method::GET
        && request.version() == Version::HTTP_11
        && request.uri().path() == "/ws-rate"
        && single_header_matches(request.headers(), CONNECTION, b"upgrade", true)
        && single_header_matches(request.headers(), UPGRADE, b"websocket", true)
        && single_header_matches(request.headers(), SEC_WEBSOCKET_VERSION, b"13", false)
        && single_header_matches(request.headers(), ORIGIN, expected_origin.as_bytes(), false)
        && !request.headers().contains_key(SEC_WEBSOCKET_EXTENSIONS);
    HandshakeObservation {
        valid_secret,
        normalized_request,
        proxy_cookie_leaked: request.headers().get_all(COOKIE).iter().any(|value| {
            value
                .as_bytes()
                .windows(SESSION_COOKIE_NAME.len())
                .any(|window| window.eq_ignore_ascii_case(SESSION_COOKIE_NAME.as_bytes()))
        }),
        bootstrap_header_leaked: request.headers().contains_key(BOOTSTRAP_HEADER_NAME),
    }
}

fn single_header_matches(
    headers: &HeaderMap,
    name: http::header::HeaderName,
    expected: &[u8],
    ignore_ascii_case: bool,
) -> bool {
    let values: Vec<&HeaderValue> = headers.get_all(name).iter().collect();
    values.len() == 1
        && if ignore_ascii_case {
            values[0].as_bytes().eq_ignore_ascii_case(expected)
        } else {
            values[0].as_bytes() == expected
        }
}
