//! Loopback-only mock services for transport acceptance tests.
//!
//! Observations deliberately retain only booleans, counts, methods, and route
//! names. Neither native credential is ever serialized or formatted.

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
use rpackit_transport::{SESSION_COOKIE_NAME, Secret};
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpListener,
    sync::{Mutex, Notify, watch},
    task::JoinHandle,
};

type BoxError = Box<dyn StdError + Send + Sync>;
type TestBody = UnsyncBoxBody<Bytes, BoxError>;

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
}
