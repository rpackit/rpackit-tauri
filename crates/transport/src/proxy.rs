//! Authenticated dual-stack loopback proxy and transparent WebSocket tunnel.

use std::{
    collections::HashSet,
    convert::Infallible,
    error::Error as StdError,
    fmt,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    str::FromStr,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use base64::{Engine as _, prelude::BASE64_STANDARD};
use bytes::{Bytes, BytesMut};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, Version,
    header::{
        CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE,
        HOST, LOCATION, ORIGIN, REFERRER_POLICY, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_EXTENSIONS,
        SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION, SET_COOKIE,
        TRANSFER_ENCODING, UPGRADE, X_CONTENT_TYPE_OPTIONS,
    },
};
use http_body_util::{BodyExt as _, Empty, Full, Limited, combinators::UnsyncBoxBody};
use hyper::{
    body::Incoming, client::conn::http1 as client_http1, server::conn::http1 as server_http1,
    service::service_fn, upgrade::OnUpgrade,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use percent_encoding::percent_decode_str;
use sha1::{Digest as _, Sha1};
use socket2::{Domain, Protocol, Socket, Type};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    task::JoinHandle,
    time::timeout,
};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    Secret, TransportLimits, TransportSecrets,
    admission::{self, RawAdmission},
    cookie,
    replay_io::ReplayIo,
    response_body::ResponseBodyGuard,
    response_guard_io::ResponseGuardIo,
};

/// Reserved native proxy-session cookie name.
pub const SESSION_COOKIE_NAME: &str = "rpackit_proxy_v1";
/// One-time native-only bootstrap request header.
pub const BOOTSTRAP_HEADER_NAME: &str = "x-rpackit-bootstrap";

const BOOTSTRAP_PATH: &str = "/__rpackit_bootstrap";
const PROTECTED_HEADER: &str = "shiny-shared-secret";
const BOOTSTRAP_BODY: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Loading</title></head><body><p>Loading application\u{2026}</p></body></html>";

type BoxError = Box<dyn StdError + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

/// Browser-visible host and port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyAddress {
    hostname: Arc<str>,
    port: u16,
}

impl ProxyAddress {
    /// Random per-launch hostname.
    #[must_use]
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// Shared IPv4/IPv6 loopback listener port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Exact `Host` header value.
    #[must_use]
    pub fn authority(&self) -> String {
        format!("{}:{}", self.hostname, self.port)
    }

    /// Exact browser-facing origin.
    #[must_use]
    pub fn origin(&self) -> String {
        format!("http://{}", self.authority())
    }

    /// Exact one-time authenticated bootstrap URL.
    #[must_use]
    pub fn bootstrap_url(&self) -> String {
        format!("{}{BOOTSTRAP_PATH}", self.origin())
    }

    /// Authenticated root URL.
    #[must_use]
    pub fn root_url(&self) -> String {
        format!("{}/", self.origin())
    }
}

/// Result of resolving the generated browser hostname.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostResolution {
    /// At least one answer was returned and every answer was loopback.
    Loopback(Vec<IpAddr>),
    /// Name resolution returned a non-loopback address.
    NonLoopback(Vec<IpAddr>),
    /// No usable address was returned.
    Unavailable,
}

/// Immutable per-launch proxy configuration.
#[derive(Clone)]
pub struct ProxyConfig {
    upstream: SocketAddr,
    hostname: String,
    secrets: TransportSecrets,
    limits: TransportLimits,
}

impl ProxyConfig {
    /// Create a production-like configuration with a fresh random hostname and
    /// independent fresh secrets.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Random`] if the operating-system random source
    /// fails, or [`ProxyError::InvalidConfiguration`] for a non-loopback
    /// upstream.
    pub fn generate(upstream: SocketAddr) -> Result<Self, ProxyError> {
        let secrets = TransportSecrets::generate().map_err(|_| ProxyError::Random)?;
        Self::generate_with_secrets(upstream, secrets)
    }

    /// Create a fresh random hostname around an explicitly owned secret pair.
    ///
    /// This lets the native acceptance shell start its fixed mock upstream
    /// before the proxy while keeping both credentials native-only.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Random`] if the random hostname cannot be
    /// generated, or [`ProxyError::InvalidConfiguration`] for a non-loopback
    /// upstream.
    pub fn generate_with_secrets(
        upstream: SocketAddr,
        secrets: TransportSecrets,
    ) -> Result<Self, ProxyError> {
        if upstream.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Err(ProxyError::InvalidConfiguration);
        }
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| ProxyError::Random)?;
        Ok(Self {
            upstream,
            hostname: format!("rpackit-{}.localhost", hex::encode(nonce)),
            secrets,
            limits: TransportLimits::default(),
        })
    }

    /// Construct an explicit deterministic configuration for the loopback
    /// acceptance testkit.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::InvalidConfiguration`] unless the upstream is
    /// IPv4 loopback and the hostname has the exact generated-name shape.
    pub fn explicit(
        upstream: SocketAddr,
        hostname: impl Into<String>,
        secrets: TransportSecrets,
    ) -> Result<Self, ProxyError> {
        let hostname = hostname.into();
        if upstream.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) || !valid_generated_hostname(&hostname)
        {
            return Err(ProxyError::InvalidConfiguration);
        }
        Ok(Self {
            upstream,
            hostname,
            secrets,
            limits: TransportLimits::default(),
        })
    }

    /// Replace resource and timing limits.
    #[must_use]
    pub fn with_limits(mut self, limits: TransportLimits) -> Self {
        self.limits = limits;
        self
    }
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyConfig")
            .field("upstream", &self.upstream)
            .field("hostname", &self.hostname)
            .field("secrets", &"[REDACTED]")
            .field("limits", &self.limits)
            .finish()
    }
}

/// Secret-free proxy startup/runtime errors.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// The configured fixed upstream or hostname violates the transport
    /// contract.
    #[error("invalid proxy configuration")]
    InvalidConfiguration,
    /// Operating-system random generation failed.
    #[error("cryptographic random generation failed")]
    Random,
    /// Compatible exclusive IPv4 and IPv6 loopback listeners could not be
    /// created on the same port.
    #[error("compatible exclusive loopback listeners are unavailable")]
    Bind(#[source] io::Error),
    /// A listener task failed.
    #[error("proxy listener failed")]
    Listener(#[source] io::Error),
    /// A tracked connection, upstream driver, or upgrade tunnel task failed.
    #[error("proxy connection task failed")]
    Task(#[source] io::Error),
}

/// A running authenticated proxy.
pub struct RunningProxy {
    address: ProxyAddress,
    secrets: TransportSecrets,
    shutdown: watch::Sender<bool>,
    listener_tasks: Vec<JoinHandle<Result<(), io::Error>>>,
    connection_tasks: Arc<TrackedTasks>,
}

impl RunningProxy {
    /// Bind exclusive IPv4/IPv6 loopback listeners and start accepting.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Bind`] if compatible exclusive dual-stack
    /// loopback listeners cannot be established.
    #[allow(clippy::unused_async)]
    pub async fn start(config: ProxyConfig) -> Result<Self, ProxyError> {
        let (ipv4, ipv6, port) = bind_dual_loopback().map_err(ProxyError::Bind)?;
        let address = ProxyAddress {
            hostname: Arc::from(config.hostname.as_str()),
            port,
        };
        let connection_tasks = Arc::new(TrackedTasks::new());
        let state = Arc::new(ProxyState {
            expected_authority: address.authority(),
            expected_origin: address.origin(),
            address: address.clone(),
            upstream: config.upstream,
            secrets: config.secrets.clone(),
            limits: config.limits.clone(),
            permits: Arc::new(Semaphore::new(config.limits.max_connections)),
            bootstrap_consumed: AtomicBool::new(false),
            tasks: Arc::clone(&connection_tasks),
        });
        let (shutdown, receiver) = watch::channel(false);
        let listener_tasks = vec![
            tokio::spawn(run_listener(
                ipv4,
                Arc::clone(&state),
                shutdown.clone(),
                receiver.clone(),
            )),
            tokio::spawn(run_listener(ipv6, state, shutdown.clone(), receiver)),
        ];
        Ok(Self {
            address,
            secrets: config.secrets,
            shutdown,
            listener_tasks,
            connection_tasks,
        })
    }

    /// Browser-facing origin details.
    #[must_use]
    pub fn address(&self) -> &ProxyAddress {
        &self.address
    }

    /// Native-only credentials for cookie installation and mock-upstream
    /// ownership. Formatting this value is always redacted.
    #[must_use]
    pub fn secrets(&self) -> &TransportSecrets {
        &self.secrets
    }

    /// Resolve the actual generated host and classify every returned address.
    pub async fn resolve_hostname(&self) -> HostResolution {
        let Ok(resolved) =
            tokio::net::lookup_host((self.address.hostname(), self.address.port())).await
        else {
            return HostResolution::Unavailable;
        };
        let mut addresses: Vec<IpAddr> = resolved.map(|address| address.ip()).collect();
        addresses.sort();
        addresses.dedup();
        if addresses.is_empty() {
            HostResolution::Unavailable
        } else if addresses.iter().all(IpAddr::is_loopback) {
            HostResolution::Loopback(addresses)
        } else {
            HostResolution::NonLoopback(addresses)
        }
    }

    /// Stop accepting traffic, cancel every active connection and upstream
    /// task, and wait until all tracked work has terminated.
    ///
    /// # Errors
    ///
    /// Returns the first listener or tracked-task failure after all other
    /// listeners and tasks have still been cleaned up.
    pub async fn shutdown(mut self) -> Result<(), ProxyError> {
        let _ = self.shutdown.send(true);
        self.connection_tasks.abort_all();

        let mut first_error = None;
        for task in self.listener_tasks.drain(..) {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    if first_error.is_none() {
                        first_error = Some(ProxyError::Listener(error));
                    }
                }
                Err(_) => {
                    if first_error.is_none() {
                        first_error = Some(ProxyError::Listener(io::Error::other(
                            "proxy listener task terminated",
                        )));
                    }
                }
            }
        }

        let tasks = self.connection_tasks.close_and_take();
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            match task.await {
                Ok(()) => {}
                Err(error) if error.is_cancelled() => {}
                Err(_) => {
                    if first_error.is_none() {
                        first_error = Some(ProxyError::Task(io::Error::other(
                            "tracked proxy task terminated",
                        )));
                    }
                }
            }
        }

        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for RunningProxy {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        for task in &self.listener_tasks {
            task.abort();
        }
        for task in self.connection_tasks.close_and_take() {
            task.abort();
        }
    }
}

struct ProxyState {
    expected_authority: String,
    expected_origin: String,
    address: ProxyAddress,
    upstream: SocketAddr,
    secrets: TransportSecrets,
    limits: TransportLimits,
    permits: Arc<Semaphore>,
    bootstrap_consumed: AtomicBool,
    tasks: Arc<TrackedTasks>,
}

#[derive(Default)]
struct TrackedTaskState {
    closed: bool,
    handles: Vec<JoinHandle<()>>,
}

struct TrackedTasks {
    state: Mutex<TrackedTaskState>,
}

impl TrackedTasks {
    fn new() -> Self {
        Self {
            state: Mutex::new(TrackedTaskState::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, TrackedTaskState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn spawn<F>(self: &Arc<Self>, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut state = self.lock();
        state.handles.retain(|task| !task.is_finished());
        if state.closed {
            return false;
        }
        state.handles.push(tokio::spawn(future));
        true
    }

    fn abort_all(&self) {
        let mut state = self.lock();
        state.closed = true;
        for task in &state.handles {
            task.abort();
        }
    }

    fn close_and_take(&self) -> Vec<JoinHandle<()>> {
        let mut state = self.lock();
        state.closed = true;
        std::mem::take(&mut state.handles)
    }
}

fn bind_dual_loopback() -> io::Result<(TcpListener, TcpListener, u16)> {
    let ipv6 = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    ipv6.set_only_v6(true)?;
    configure_listener_ownership(&ipv6)?;
    ipv6.set_nonblocking(true)?;
    ipv6.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0).into())?;
    ipv6.listen(128)?;
    let port = ipv6
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("IPv6 listener has no socket address"))?
        .port();

    let ipv4 = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    configure_listener_ownership(&ipv4)?;
    ipv4.set_nonblocking(true)?;
    ipv4.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port).into())?;
    ipv4.listen(128)?;

    let ipv4 = TcpListener::from_std(ipv4.into())?;
    let ipv6 = TcpListener::from_std(ipv6.into())?;
    Ok((ipv4, ipv6, port))
}

fn configure_listener_ownership(socket: &Socket) -> io::Result<()> {
    socket.set_reuse_address(false)?;
    #[cfg(windows)]
    crate::windows_socket::set_exclusive_address_use(socket)?;
    Ok(())
}

async fn run_listener(
    listener: TcpListener,
    state: Arc<ProxyState>,
    shutdown_sender: watch::Sender<bool>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), io::Error> {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (socket, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        let _ = shutdown_sender.send(true);
                        state.tasks.abort_all();
                        return Err(error);
                    }
                };
                if !peer.ip().is_loopback() {
                    continue;
                }
                let Ok(permit) = Arc::clone(&state.permits).try_acquire_owned() else {
                    let _ = state.tasks.spawn(async move {
                        let mut socket = socket;
                        let _ =
                            write_raw_rejection(&mut socket, StatusCode::SERVICE_UNAVAILABLE).await;
                    });
                    continue;
                };
                let request_state = Arc::clone(&state);
                let _ = state.tasks.spawn(async move {
                    let _permit = permit;
                    handle_socket(socket, request_state).await;
                });
            }
        }
    }
}

async fn handle_socket(mut socket: TcpStream, state: Arc<ProxyState>) {
    let Ok(Ok(prefix)) = timeout(
        state.limits.header_timeout,
        read_request_prefix(&mut socket, state.limits.max_header_bytes),
    )
    .await
    else {
        let _ = write_raw_rejection(&mut socket, StatusCode::BAD_REQUEST).await;
        return;
    };
    let Ok(raw) = admission::validate(&prefix, &state.expected_authority, &state.limits) else {
        let _ = write_raw_rejection(&mut socket, StatusCode::BAD_REQUEST).await;
        return;
    };
    let raw = Arc::new(raw);

    let replay = ReplayIo::new(prefix.freeze(), socket);
    let service_state = Arc::clone(&state);
    let service_raw = Arc::clone(&raw);
    let service = service_fn(move |request| {
        let state = Arc::clone(&service_state);
        let raw = Arc::clone(&service_raw);
        async move {
            let response = handle_request(request, raw, state).await;
            Ok::<_, Infallible>(response)
        }
    });

    let mut builder = server_http1::Builder::new();
    builder
        .keep_alive(true)
        .half_close(false)
        .auto_date_header(false)
        .max_headers(state.limits.max_headers)
        .max_buf_size(state.limits.max_header_bytes.max(8 * 1024))
        .timer(TokioTimer::new())
        .header_read_timeout(state.limits.header_timeout);
    let connection = builder
        .serve_connection(TokioIo::new(replay), service)
        .with_upgrades();
    let _ = connection.await;
}

async fn read_request_prefix(
    socket: &mut TcpStream,
    max_header_bytes: usize,
) -> io::Result<BytesMut> {
    let mut bytes = BytesMut::with_capacity(4 * 1024);
    let mut chunk = [0_u8; 4 * 1024];
    loop {
        if admission::header_end(&bytes).is_some() {
            return Ok(bytes);
        }
        if bytes.len() >= max_header_bytes {
            return Err(io::Error::other("request header limit exceeded"));
        }
        let remaining = max_header_bytes - bytes.len();
        let chunk_limit = remaining.min(chunk.len());
        let read = socket.read(&mut chunk[..chunk_limit]).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "request ended before headers completed",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}

async fn write_raw_rejection(socket: &mut TcpStream, status: StatusCode) -> io::Result<()> {
    let status_line = match status {
        StatusCode::SERVICE_UNAVAILABLE => "503 Service Unavailable",
        _ => "400 Bad Request",
    };
    let response = format!(
        "HTTP/1.1 {status_line}\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 16\r\n\r\nRequest rejected"
    );
    socket.write_all(response.as_bytes()).await?;
    socket.shutdown().await
}

async fn handle_request(
    mut request: Request<Incoming>,
    raw: Arc<RawAdmission>,
    state: Arc<ProxyState>,
) -> Response<ProxyBody> {
    if is_bootstrap(&request) {
        if !authenticate_bootstrap(&request, &state) {
            return fixed_response(StatusCode::UNAUTHORIZED, "Authentication failed");
        }
        return bootstrap_response(request.method() == Method::HEAD, &state.secrets.session());
    }
    if references_bootstrap_route(request.uri()) {
        return fixed_response(StatusCode::BAD_REQUEST, "Request rejected");
    }
    if request.headers().contains_key(BOOTSTRAP_HEADER_NAME) {
        return fixed_response(StatusCode::BAD_REQUEST, "Request rejected");
    }

    if validate_origin(&request, &state.expected_origin, raw.websocket_upgrade).is_err() {
        return fixed_response(StatusCode::FORBIDDEN, "Request rejected");
    }
    if cookie::authenticate_and_strip(request.headers_mut(), &state.secrets.session()).is_err() {
        return fixed_response(StatusCode::UNAUTHORIZED, "Authentication failed");
    }

    if raw.websocket_upgrade {
        return match forward_websocket(request, state).await {
            Ok(response) => response,
            Err(_) => fixed_response(StatusCode::BAD_GATEWAY, "Upstream rejected"),
        };
    }
    match forward_http(request, &raw, &state).await {
        Ok(response) => response,
        Err(_) => fixed_response(StatusCode::BAD_GATEWAY, "Upstream rejected"),
    }
}

fn is_bootstrap(request: &Request<Incoming>) -> bool {
    matches!(*request.method(), Method::GET | Method::HEAD)
        && request.uri().path() == BOOTSTRAP_PATH
        && request.uri().query().is_none()
        && !request.headers().contains_key(CONTENT_LENGTH)
        && !request.headers().contains_key(TRANSFER_ENCODING)
}

fn references_bootstrap_route(uri: &Uri) -> bool {
    percent_decode_str(uri.path())
        .decode_utf8_lossy()
        .split('/')
        .any(|segment| segment == BOOTSTRAP_PATH.trim_start_matches('/'))
}

fn authenticate_bootstrap(request: &Request<Incoming>, state: &ProxyState) -> bool {
    let values: Vec<&HeaderValue> = request
        .headers()
        .get_all(BOOTSTRAP_HEADER_NAME)
        .iter()
        .collect();
    values.len() == 1
        && state.secrets.bootstrap().matches(values[0].as_bytes())
        && state
            .bootstrap_consumed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
}

fn bootstrap_response(head_only: bool, session: &Secret) -> Response<ProxyBody> {
    let body = if head_only {
        Bytes::new()
    } else {
        Bytes::from_static(BOOTSTRAP_BODY.as_bytes())
    };
    let mut response = Response::new(full_body(body));
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
    );
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(CONNECTION, HeaderValue::from_static("close"));
    session.with_exposed(|value| {
        let text = Zeroizing::new(format!(
            "{SESSION_COOKIE_NAME}={value}; Path=/; HttpOnly; SameSite=Strict"
        ));
        if let Ok(cookie) = HeaderValue::from_str(text.as_str()) {
            headers.insert(SET_COOKIE, cookie);
        }
    });
    response
}

fn validate_origin(
    request: &Request<Incoming>,
    expected_origin: &str,
    websocket: bool,
) -> Result<(), ()> {
    let unsafe_method = !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );
    let origins: Vec<&HeaderValue> = request.headers().get_all(ORIGIN).iter().collect();
    if websocket || unsafe_method {
        if origins.len() != 1 || origins[0].as_bytes() != expected_origin.as_bytes() {
            return Err(());
        }
    } else if !origins.is_empty()
        && (origins.len() != 1 || origins[0].as_bytes() != expected_origin.as_bytes())
    {
        return Err(());
    }
    Ok(())
}

async fn forward_http(
    request: Request<Incoming>,
    raw: &RawAdmission,
    state: &ProxyState,
) -> Result<Response<ProxyBody>, BoxError> {
    let request = normalize_http_request(request, raw, state)?;
    let stream = timeout(
        state.limits.upstream_timeout,
        TcpStream::connect(state.upstream),
    )
    .await??;
    let io = TokioIo::new(ResponseGuardIo::new(
        stream,
        state.limits.max_header_bytes,
        state.limits.max_headers,
        false,
    ));
    let mut client = client_http1::Builder::new();
    client
        .allow_spaces_after_header_name_in_responses(false)
        .allow_obsolete_multiline_headers_in_responses(false)
        .ignore_invalid_headers_in_responses(false)
        .preserve_header_case(false)
        .title_case_headers(false)
        .max_headers(state.limits.max_headers)
        .max_buf_size(state.limits.max_header_bytes.max(8 * 1024));
    let (mut sender, connection) = client.handshake::<_, ProxyBody>(io).await?;
    if !state.tasks.spawn(async move {
        let _ = connection.await;
    }) {
        return Err(Box::new(io::Error::other("proxy is shutting down")));
    }
    sender.ready().await?;
    let request_method = request.method().clone();
    let response = timeout(state.limits.upstream_timeout, sender.send_request(request)).await??;
    normalize_http_response(response, &request_method, state)
}

fn normalize_http_request(
    request: Request<Incoming>,
    raw: &RawAdmission,
    state: &ProxyState,
) -> Result<Request<ProxyBody>, BoxError> {
    let (mut parts, body) = request.into_parts();
    parts.version = Version::HTTP_11;
    parts.uri = origin_form_uri(&parts.uri)?;
    strip_request_headers(&mut parts.headers, &raw.connection_tokens);
    rewrite_origin(&mut parts.headers, state);
    parts
        .headers
        .insert(HOST, HeaderValue::from_str(&state.upstream.to_string())?);
    parts.headers.insert(
        HeaderName::from_static(PROTECTED_HEADER),
        HeaderValue::from_str(state.secrets.upstream().expose())?,
    );
    if parts.headers.get_all(PROTECTED_HEADER).iter().count() != 1 {
        return Err(Box::new(io::Error::other(
            "protected upstream header invariant failed",
        )));
    }
    let body = Limited::new(body, state.limits.max_request_body_bytes).boxed_unsync();
    Ok(Request::from_parts(parts, body))
}

fn normalize_http_response(
    response: Response<Incoming>,
    request_method: &Method,
    state: &ProxyState,
) -> Result<Response<ProxyBody>, BoxError> {
    if response.status().is_informational() {
        return Err(Box::new(io::Error::other(
            "unexpected informational upstream response",
        )));
    }
    let (mut parts, body) = response.into_parts();
    let body_policy = validate_response_body_head(
        request_method,
        parts.status,
        &parts.headers,
        state.limits.max_response_body_bytes,
    )?;
    parts.version = Version::HTTP_11;
    strip_response_headers(&mut parts.headers)?;
    parts
        .headers
        .insert(CONNECTION, HeaderValue::from_static("close"));
    cookie::normalize_set_cookie_headers(&mut parts.headers, &state.upstream.ip().to_string())?;
    rewrite_location(&mut parts.headers, state)?;
    let body = match body_policy {
        ResponseBodyPolicy::Streaming { declared_length } => ResponseBodyGuard::streaming(
            body,
            declared_length,
            state.limits.max_response_body_bytes,
        ),
        ResponseBodyPolicy::Forbidden { advertised_length } => {
            ResponseBodyGuard::forbidden(body, advertised_length)
        }
    }
    .map_err(|error| -> BoxError { Box::new(error) })
    .boxed_unsync();
    Ok(Response::from_parts(parts, body))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseBodyPolicy {
    Streaming { declared_length: Option<u64> },
    Forbidden { advertised_length: Option<u64> },
}

fn validate_response_body_head(
    request_method: &Method,
    status: StatusCode,
    headers: &HeaderMap,
    max_response_body_bytes: usize,
) -> Result<ResponseBodyPolicy, BoxError> {
    if headers.contains_key("trailer") {
        return Err(Box::new(io::Error::other(
            "upstream response trailers are unsupported",
        )));
    }
    let values: Vec<&HeaderValue> = headers.get_all(CONTENT_LENGTH).iter().collect();
    if values.len() > 1 {
        return Err(Box::new(io::Error::other(
            "ambiguous upstream response length",
        )));
    }
    let declared_length = if let Some(value) = values.first() {
        Some(
            value
                .to_str()?
                .parse::<u64>()
                .map_err(|_| io::Error::other("invalid upstream response length"))?,
        )
    } else {
        None
    };

    if status == StatusCode::NO_CONTENT
        && (declared_length.is_some() || headers.contains_key(TRANSFER_ENCODING))
    {
        return Err(Box::new(io::Error::other(
            "upstream no-content response used forbidden framing",
        )));
    }
    if status == StatusCode::RESET_CONTENT
        && (declared_length.is_some_and(|declared| declared != 0)
            || headers.contains_key(TRANSFER_ENCODING))
    {
        return Err(Box::new(io::Error::other(
            "upstream reset-content response used forbidden framing",
        )));
    }

    if request_method == Method::HEAD
        || matches!(
            status,
            StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED
        )
    {
        return Ok(ResponseBodyPolicy::Forbidden {
            advertised_length: declared_length,
        });
    }

    if declared_length.is_some_and(|declared| {
        declared > u64::try_from(max_response_body_bytes).unwrap_or(u64::MAX)
    }) {
        return Err(Box::new(io::Error::other(
            "upstream response length exceeded limit",
        )));
    }
    Ok(ResponseBodyPolicy::Streaming { declared_length })
}

async fn forward_websocket(
    mut request: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<ProxyBody>, BoxError> {
    let websocket = validate_websocket_request(&request, &state.expected_origin)?;
    let downstream_upgrade = hyper::upgrade::on(&mut request);
    drop(request.into_body());
    let upstream_request = build_upstream_websocket_request(&websocket, &state)?;

    let stream = timeout(
        state.limits.upstream_timeout,
        TcpStream::connect(state.upstream),
    )
    .await??;
    let io = TokioIo::new(ResponseGuardIo::new(
        stream,
        state.limits.max_header_bytes,
        state.limits.max_headers,
        true,
    ));
    let (mut sender, connection) = client_http1::Builder::new()
        .handshake::<_, ProxyBody>(io)
        .await?;
    if !state.tasks.spawn(async move {
        let _ = connection.with_upgrades().await;
    }) {
        return Err(Box::new(io::Error::other("proxy is shutting down")));
    }
    sender.ready().await?;
    let mut upstream_response = timeout(
        state.limits.upstream_timeout,
        sender.send_request(upstream_request),
    )
    .await??;
    let selected_protocol = validate_websocket_response(&upstream_response, &websocket)?;
    let upstream_upgrade = hyper::upgrade::on(&mut upstream_response);

    let response = downstream_websocket_response(&websocket, selected_protocol.as_deref())?;
    let idle_timeout = state.limits.websocket_idle_timeout;
    if !state.tasks.spawn(async move {
        let _ = tunnel_upgrades(downstream_upgrade, upstream_upgrade, idle_timeout).await;
    }) {
        return Err(Box::new(io::Error::other("proxy is shutting down")));
    }
    Ok(response)
}

#[derive(Clone, Debug)]
struct WebSocketOffer {
    path: Uri,
    key: HeaderValue,
    expected_accept: HeaderValue,
    protocols: Vec<String>,
    application_cookie: Option<HeaderValue>,
}

fn validate_websocket_request(
    request: &Request<Incoming>,
    expected_origin: &str,
) -> Result<WebSocketOffer, BoxError> {
    if request.method() != Method::GET
        || request.version() != Version::HTTP_11
        || request.headers().contains_key(CONTENT_LENGTH)
        || request.headers().contains_key(TRANSFER_ENCODING)
        || request.headers().contains_key("trailer")
    {
        return Err(Box::new(io::Error::other(
            "invalid WebSocket request shape",
        )));
    }
    require_single_exact(request.headers(), UPGRADE, b"websocket", true)?;
    require_single_exact(request.headers(), SEC_WEBSOCKET_VERSION, b"13", false)?;
    require_single_exact(request.headers(), ORIGIN, expected_origin.as_bytes(), false)?;

    let keys: Vec<&HeaderValue> = request
        .headers()
        .get_all(SEC_WEBSOCKET_KEY)
        .iter()
        .collect();
    if keys.len() != 1 {
        return Err(Box::new(io::Error::other("invalid WebSocket key")));
    }
    let decoded = BASE64_STANDARD
        .decode(keys[0].as_bytes())
        .map_err(|_| io::Error::other("invalid WebSocket key"))?;
    if decoded.len() != 16 {
        return Err(Box::new(io::Error::other("invalid WebSocket key")));
    }

    let protocols = parse_protocols(request.headers())?;
    validate_extensions(request.headers())?;
    let expected_accept = derive_websocket_accept(keys[0])?;
    Ok(WebSocketOffer {
        path: origin_form_uri(request.uri())?,
        key: keys[0].clone(),
        expected_accept,
        protocols,
        application_cookie: request.headers().get(COOKIE).cloned(),
    })
}

fn build_upstream_websocket_request(
    offer: &WebSocketOffer,
    state: &ProxyState,
) -> Result<Request<ProxyBody>, BoxError> {
    let mut request = Request::builder()
        .method(Method::GET)
        .version(Version::HTTP_11)
        .uri(offer.path.clone())
        .body(empty_body())?;
    let headers = request.headers_mut();
    headers.insert(HOST, HeaderValue::from_str(&state.upstream.to_string())?);
    headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));
    headers.insert(SEC_WEBSOCKET_KEY, offer.key.clone());
    headers.insert(
        ORIGIN,
        HeaderValue::from_str(&format!("http://{}", state.upstream))?,
    );
    if !offer.protocols.is_empty() {
        headers.insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_str(&offer.protocols.join(", "))?,
        );
    }
    if let Some(cookie) = &offer.application_cookie {
        headers.insert(COOKIE, cookie.clone());
    }
    headers.insert(
        HeaderName::from_static(PROTECTED_HEADER),
        HeaderValue::from_str(state.secrets.upstream().expose())?,
    );
    Ok(request)
}

fn validate_websocket_response<B>(
    response: &Response<B>,
    offer: &WebSocketOffer,
) -> Result<Option<String>, BoxError> {
    if response.status() != StatusCode::SWITCHING_PROTOCOLS
        || response.version() != Version::HTTP_11
        || response.headers().contains_key(CONTENT_LENGTH)
        || response.headers().contains_key(TRANSFER_ENCODING)
        || response.headers().contains_key(SEC_WEBSOCKET_EXTENSIONS)
    {
        return Err(Box::new(io::Error::other(
            "invalid upstream WebSocket response",
        )));
    }
    require_single_exact(response.headers(), CONNECTION, b"upgrade", true)?;
    require_single_exact(response.headers(), UPGRADE, b"websocket", true)?;
    require_single_exact(
        response.headers(),
        SEC_WEBSOCKET_ACCEPT,
        offer.expected_accept.as_bytes(),
        false,
    )?;

    let protocols: Vec<&HeaderValue> = response
        .headers()
        .get_all(SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .collect();
    if protocols.len() > 1 {
        return Err(Box::new(io::Error::other(
            "invalid upstream WebSocket protocol",
        )));
    }
    let selected = protocols
        .first()
        .map(|value| value.to_str())
        .transpose()?
        .map(str::to_owned);
    if selected
        .as_ref()
        .is_some_and(|protocol| !offer.protocols.contains(protocol))
    {
        return Err(Box::new(io::Error::other(
            "unoffered upstream WebSocket protocol",
        )));
    }
    Ok(selected)
}

fn downstream_websocket_response(
    offer: &WebSocketOffer,
    selected_protocol: Option<&str>,
) -> Result<Response<ProxyBody>, BoxError> {
    let mut response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .version(Version::HTTP_11)
        .body(empty_body())?;
    let headers = response.headers_mut();
    headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(SEC_WEBSOCKET_ACCEPT, offer.expected_accept.clone());
    if let Some(protocol) = selected_protocol {
        headers.insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_str(protocol)?);
    }
    Ok(response)
}

async fn tunnel_upgrades(
    downstream: OnUpgrade,
    upstream: OnUpgrade,
    idle_timeout: Duration,
) -> Result<(), BoxError> {
    let (downstream, upstream) = futures_util::try_join!(downstream, upstream)?;
    let (activity, activity_receiver) = watch::channel(0_u64);
    let mut downstream = ActivityIo::new(TokioIo::new(downstream), activity.clone());
    let mut upstream = ActivityIo::new(TokioIo::new(upstream), activity);
    let mut transfer = Box::pin(tokio::io::copy_bidirectional(
        &mut downstream,
        &mut upstream,
    ));
    let transfer_result = tokio::select! {
        result = &mut transfer => Some(result),
        () = wait_until_idle(activity_receiver, idle_timeout) => None,
    };
    drop(transfer);
    if let Some(result) = transfer_result {
        result?;
    }
    downstream.shutdown().await?;
    upstream.shutdown().await?;
    Ok(())
}

struct ActivityIo<T> {
    inner: T,
    activity: watch::Sender<u64>,
}

impl<T> ActivityIo<T> {
    const fn new(inner: T, activity: watch::Sender<u64>) -> Self {
        Self { inner, activity }
    }

    fn record_activity(&self) {
        self.activity
            .send_modify(|sequence| *sequence = sequence.wrapping_add(1));
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ActivityIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > filled {
            this.record_activity();
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ActivityIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(context, buffer);
        if matches!(result, Poll::Ready(Ok(written)) if written > 0) {
            this.record_activity();
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(context)
    }
}

async fn wait_until_idle(mut activity: watch::Receiver<u64>, idle_timeout: Duration) {
    loop {
        match timeout(idle_timeout, activity.changed()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => return,
        }
    }
}

fn parse_protocols(headers: &HeaderMap) -> Result<Vec<String>, BoxError> {
    let values: Vec<&HeaderValue> = headers.get_all(SEC_WEBSOCKET_PROTOCOL).iter().collect();
    if values.len() > 1 {
        return Err(Box::new(io::Error::other("ambiguous WebSocket protocols")));
    }
    let Some(value) = values.first() else {
        return Ok(Vec::new());
    };
    let mut protocols = Vec::new();
    for item in value.to_str()?.split(',') {
        let protocol = item.trim();
        if protocol.is_empty()
            || !protocol.bytes().all(admission::is_token_byte)
            || protocols.iter().any(|existing| existing == protocol)
        {
            return Err(Box::new(io::Error::other("invalid WebSocket protocol")));
        }
        protocols.push(protocol.to_owned());
    }
    Ok(protocols)
}

fn validate_extensions(headers: &HeaderMap) -> Result<(), BoxError> {
    let values: Vec<&HeaderValue> = headers.get_all(SEC_WEBSOCKET_EXTENSIONS).iter().collect();
    if values.len() > 1 {
        return Err(Box::new(io::Error::other("ambiguous WebSocket extensions")));
    }
    let Some(value) = values.first() else {
        return Ok(());
    };
    let mut extension_names = HashSet::new();
    for extension in value.to_str()?.split(',') {
        let mut parts = extension.split(';');
        let name = parts.next().map(str::trim).unwrap_or_default();
        if name.is_empty()
            || !name.bytes().all(admission::is_token_byte)
            || !extension_names.insert(name.to_ascii_lowercase())
        {
            return Err(Box::new(io::Error::other("invalid WebSocket extension")));
        }
        let mut parameters = HashSet::new();
        for parameter in parts {
            let parameter = parameter.trim();
            let (parameter_name, parameter_value) = parameter
                .split_once('=')
                .map_or((parameter, None), |(name, value)| {
                    (name.trim(), Some(value.trim()))
                });
            if parameter_name.is_empty()
                || !parameter_name.bytes().all(admission::is_token_byte)
                || !parameters.insert(parameter_name.to_ascii_lowercase())
            {
                return Err(Box::new(io::Error::other(
                    "invalid WebSocket extension parameter",
                )));
            }
            if let Some(value) = parameter_value
                && !valid_extension_value(value)
            {
                return Err(Box::new(io::Error::other(
                    "invalid WebSocket extension parameter",
                )));
            }
        }
    }
    Ok(())
}

fn valid_extension_value(value: &str) -> bool {
    value.bytes().all(admission::is_token_byte)
        || (value.len() >= 2
            && value.starts_with('"')
            && value.ends_with('"')
            && value[1..value.len() - 1]
                .bytes()
                .all(|byte| byte == b'\t' || (byte >= 0x20 && byte != b'"' && byte != b'\\')))
}

fn require_single_exact(
    headers: &HeaderMap,
    name: HeaderName,
    expected: &[u8],
    case_insensitive: bool,
) -> Result<(), BoxError> {
    let values: Vec<&HeaderValue> = headers.get_all(name).iter().collect();
    if values.len() != 1 {
        return Err(Box::new(io::Error::other(
            "required WebSocket header missing",
        )));
    }
    let matches = if case_insensitive {
        values[0].as_bytes().eq_ignore_ascii_case(expected)
    } else {
        values[0].as_bytes() == expected
    };
    if !matches {
        return Err(Box::new(io::Error::other(
            "required WebSocket header invalid",
        )));
    }
    Ok(())
}

fn derive_websocket_accept(key: &HeaderValue) -> Result<HeaderValue, BoxError> {
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let value = BASE64_STANDARD.encode(digest.finalize());
    Ok(HeaderValue::from_str(&value)?)
}

fn origin_form_uri(uri: &Uri) -> Result<Uri, BoxError> {
    let path = uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    Ok(Uri::from_str(path)?)
}

fn strip_request_headers(headers: &mut HeaderMap, connection_tokens: &[String]) {
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "content-length",
        "proxy-authorization",
        "proxy-authenticate",
        PROTECTED_HEADER,
        BOOTSTRAP_HEADER_NAME,
    ] {
        headers.remove(name);
    }
    for token in connection_tokens {
        headers.remove(token);
    }
    let names: Vec<HeaderName> = headers.keys().cloned().collect();
    for name in names {
        let lower = name.as_str();
        if lower == "forwarded"
            || lower == "x-real-ip"
            || lower.starts_with("x-forwarded-")
            || lower.starts_with("x-original-")
        {
            headers.remove(name);
        }
    }
}

fn rewrite_origin(headers: &mut HeaderMap, state: &ProxyState) {
    if headers.contains_key(ORIGIN)
        && let Ok(origin) = HeaderValue::from_str(&format!("http://{}", state.upstream))
    {
        headers.insert(ORIGIN, origin);
    }
}

fn strip_response_headers(headers: &mut HeaderMap) -> Result<(), BoxError> {
    let connection_values: Vec<&HeaderValue> = headers.get_all(CONNECTION).iter().collect();
    if connection_values.len() > 1 {
        return Err(Box::new(io::Error::other(
            "ambiguous upstream connection header",
        )));
    }
    let mut nominated = Vec::new();
    if let Some(value) = connection_values.first() {
        for token in value.to_str()?.split(',') {
            let token = token.trim().to_ascii_lowercase();
            if token.is_empty()
                || !token.bytes().all(admission::is_token_byte)
                || admission::is_protected_connection_target(&token)
            {
                return Err(Box::new(io::Error::other(
                    "invalid upstream connection header",
                )));
            }
            nominated.push(token);
        }
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authenticate",
        PROTECTED_HEADER,
        BOOTSTRAP_HEADER_NAME,
    ] {
        headers.remove(name);
    }
    for name in nominated {
        headers.remove(name);
    }
    Ok(())
}

fn rewrite_location(headers: &mut HeaderMap, state: &ProxyState) -> Result<(), BoxError> {
    let values: Vec<HeaderValue> = headers.get_all(LOCATION).iter().cloned().collect();
    if values.len() > 1 {
        return Err(Box::new(io::Error::other("ambiguous upstream redirect")));
    }
    let Some(value) = values.first() else {
        return Ok(());
    };
    let text = value.to_str()?;
    let Ok(mut location) = Url::parse(text) else {
        if text.starts_with('/') && !text.starts_with("//") {
            return Ok(());
        }
        return Err(Box::new(io::Error::other("invalid upstream redirect")));
    };
    if location.scheme() == "http"
        && location.host_str() == Some(&state.upstream.ip().to_string())
        && location.port_or_known_default() == Some(state.upstream.port())
    {
        location
            .set_host(Some(state.address.hostname()))
            .map_err(|_parse_error| io::Error::other("redirect rewrite failed"))?;
        location
            .set_port(Some(state.address.port()))
            .map_err(|()| io::Error::other("redirect rewrite failed"))?;
        headers.insert(LOCATION, HeaderValue::from_str(location.as_str())?);
    }
    Ok(())
}

fn full_body(bytes: Bytes) -> ProxyBody {
    Full::new(bytes)
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}

fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}

fn fixed_response(status: StatusCode, text: &'static str) -> Response<ProxyBody> {
    let mut response = Response::new(full_body(Bytes::from_static(text.as_bytes())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    response
}

fn valid_generated_hostname(hostname: &str) -> bool {
    let Some(nonce) = hostname
        .strip_prefix("rpackit-")
        .and_then(|value| value.strip_suffix(".localhost"))
    else {
        return false;
    };
    nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn websocket_offer() -> WebSocketOffer {
        WebSocketOffer {
            path: Uri::from_static("/ws"),
            key: HeaderValue::from_static("MDEyMzQ1Njc4OWFiY2RlZg=="),
            expected_accept: HeaderValue::from_static("expected-accept"),
            protocols: vec!["chat".to_owned()],
            application_cookie: None,
        }
    }

    fn websocket_response() -> Response<()> {
        let mut response = Response::new(());
        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        *response.version_mut() = Version::HTTP_11;
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        response
            .headers_mut()
            .insert(UPGRADE, HeaderValue::from_static("websocket"));
        response.headers_mut().insert(
            SEC_WEBSOCKET_ACCEPT,
            HeaderValue::from_static("expected-accept"),
        );
        response
    }

    #[test]
    fn response_body_head_rejects_declared_trailers_and_oversized_lengths() {
        let mut declared_trailer = HeaderMap::new();
        declared_trailer.insert("trailer", HeaderValue::from_static("X-Test"));
        assert!(
            validate_response_body_head(&Method::GET, StatusCode::OK, &declared_trailer, 1024)
                .is_err()
        );

        let mut oversized = HeaderMap::new();
        oversized.insert(CONTENT_LENGTH, HeaderValue::from_static("1025"));
        assert!(
            validate_response_body_head(&Method::GET, StatusCode::OK, &oversized, 1024).is_err()
        );

        let mut exact = HeaderMap::new();
        exact.insert(CONTENT_LENGTH, HeaderValue::from_static("1024"));
        assert_eq!(
            validate_response_body_head(&Method::GET, StatusCode::OK, &exact, 1024).ok(),
            Some(ResponseBodyPolicy::Streaming {
                declared_length: Some(1024)
            })
        );
    }

    #[test]
    fn response_body_head_models_head_not_modified_and_no_content_semantics() {
        let mut hypothetical_length = HeaderMap::new();
        hypothetical_length.insert(CONTENT_LENGTH, HeaderValue::from_static("4096"));

        assert_eq!(
            validate_response_body_head(&Method::HEAD, StatusCode::OK, &hypothetical_length, 8)
                .ok(),
            Some(ResponseBodyPolicy::Forbidden {
                advertised_length: Some(4096)
            })
        );
        assert_eq!(
            validate_response_body_head(
                &Method::GET,
                StatusCode::NOT_MODIFIED,
                &hypothetical_length,
                8
            )
            .ok(),
            Some(ResponseBodyPolicy::Forbidden {
                advertised_length: Some(4096)
            })
        );
        assert_eq!(
            validate_response_body_head(&Method::GET, StatusCode::NO_CONTENT, &HeaderMap::new(), 8)
                .ok(),
            Some(ResponseBodyPolicy::Forbidden {
                advertised_length: None
            })
        );

        let mut no_content_length = HeaderMap::new();
        no_content_length.insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
        assert!(
            validate_response_body_head(
                &Method::GET,
                StatusCode::NO_CONTENT,
                &no_content_length,
                8
            )
            .is_err()
        );

        let mut no_content_transfer_encoding = HeaderMap::new();
        no_content_transfer_encoding.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        assert!(
            validate_response_body_head(
                &Method::GET,
                StatusCode::NO_CONTENT,
                &no_content_transfer_encoding,
                8
            )
            .is_err()
        );

        let mut reset_content_zero = HeaderMap::new();
        reset_content_zero.insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
        assert_eq!(
            validate_response_body_head(
                &Method::GET,
                StatusCode::RESET_CONTENT,
                &reset_content_zero,
                8
            )
            .ok(),
            Some(ResponseBodyPolicy::Forbidden {
                advertised_length: Some(0)
            })
        );

        let mut reset_content_nonzero = HeaderMap::new();
        reset_content_nonzero.insert(CONTENT_LENGTH, HeaderValue::from_static("1"));
        assert!(
            validate_response_body_head(
                &Method::GET,
                StatusCode::RESET_CONTENT,
                &reset_content_nonzero,
                8
            )
            .is_err()
        );

        let mut reset_content_chunked = HeaderMap::new();
        reset_content_chunked.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        assert!(
            validate_response_body_head(
                &Method::GET,
                StatusCode::RESET_CONTENT,
                &reset_content_chunked,
                8
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_untrusted_upstream_websocket_negotiation() {
        let offer = websocket_offer();
        assert!(validate_websocket_response(&websocket_response(), &offer).is_ok());

        let mut bad_accept = websocket_response();
        bad_accept
            .headers_mut()
            .insert(SEC_WEBSOCKET_ACCEPT, HeaderValue::from_static("wrong"));
        assert!(validate_websocket_response(&bad_accept, &offer).is_err());

        let mut unoffered_protocol = websocket_response();
        unoffered_protocol.headers_mut().insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("unoffered"),
        );
        assert!(validate_websocket_response(&unoffered_protocol, &offer).is_err());

        let mut extension = websocket_response();
        extension.headers_mut().insert(
            SEC_WEBSOCKET_EXTENSIONS,
            HeaderValue::from_static("permessage-deflate"),
        );
        assert!(validate_websocket_response(&extension, &offer).is_err());
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    fn assert_reuse_bind_rejected(domain: Domain, address: SocketAddr) -> io::Result<()> {
        let contender = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        if domain == Domain::IPV6 {
            contender.set_only_v6(true)?;
        }
        contender.set_reuse_address(true)?;
        let result = contender.bind(&address.into());
        assert!(
            result.is_err(),
            "SO_REUSEADDR contender unexpectedly rebound {address}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn windows_exclusive_listeners_reject_exact_address_takeover() -> io::Result<()> {
        let (_ipv4, _ipv6, port) = bind_dual_loopback()?;

        for (domain, address) in [
            (
                Domain::IPV4,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            ),
            (
                Domain::IPV6,
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
            ),
        ] {
            assert_reuse_bind_rejected(domain, address)?;
        }
        Ok(())
    }
}
