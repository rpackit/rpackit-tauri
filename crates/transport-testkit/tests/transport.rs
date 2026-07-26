//! Headless HTTP and WebSocket transport acceptance tests.

use std::{
    error::Error as StdError,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use futures_util::{SinkExt as _, StreamExt as _};
use http::{
    HeaderValue, StatusCode,
    header::{COOKIE, HOST, ORIGIN},
};
use rpackit_transport::{
    BOOTSTRAP_HEADER_NAME, HostResolution, ProxyConfig, RunningProxy, SESSION_COOKIE_NAME, Secret,
    TransportLimits, TransportSecrets,
};
#[cfg(windows)]
use rpackit_transport_testkit::probe_listener_overlap;
use rpackit_transport_testkit::{
    ExternalCollector, MockUpstream, probe_malformed_upstream_response_bodies,
    probe_malformed_upstream_response_heads, probe_request_body_limits,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    time::timeout,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest as _},
};

type TestError = Box<dyn StdError + Send + Sync>;

struct Fixture {
    collector: ExternalCollector,
    upstream: MockUpstream,
    proxy: RunningProxy,
}

impl Fixture {
    async fn start(nonce: u8) -> Result<Self, TestError> {
        Self::start_with_limits(nonce, TransportLimits::default()).await
    }

    async fn start_with_limits(nonce: u8, limits: TransportLimits) -> Result<Self, TestError> {
        let session = Arc::new(Secret::from_bytes([nonce; 32]));
        let upstream_secret = Arc::new(Secret::from_bytes([nonce.wrapping_add(1); 32]));
        let bootstrap = Arc::new(Secret::from_bytes([nonce.wrapping_add(2); 32]));
        let secrets = TransportSecrets::new(session, Arc::clone(&upstream_secret), bootstrap);
        let collector = ExternalCollector::start().await?;
        let upstream = MockUpstream::start(upstream_secret, collector.address()).await?;
        let hostname = format!("rpackit-{}.localhost", hex::encode([nonce; 16]));
        let config =
            ProxyConfig::explicit(upstream.address(), hostname, secrets)?.with_limits(limits);
        let proxy = RunningProxy::start(config).await?;
        Ok(Self {
            collector,
            upstream,
            proxy,
        })
    }

    fn cookie_header(&self) -> String {
        self.proxy
            .secrets()
            .session()
            .with_exposed(|value| format!("{SESSION_COOKIE_NAME}={value}"))
    }

    fn bootstrap_header(&self) -> String {
        self.proxy.secrets().bootstrap().with_exposed(str::to_owned)
    }

    async fn shutdown(self) -> Result<(), TestError> {
        self.proxy.shutdown().await?;
        self.upstream.shutdown().await?;
        self.collector.shutdown().await?;
        Ok(())
    }
}

async fn raw_request(proxy: &RunningProxy, request: &[u8]) -> io::Result<Vec<u8>> {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), proxy.address().port());
    let mut socket = TcpStream::connect(address).await?;
    socket.write_all(request).await?;
    let mut response = Vec::new();
    socket.read_to_end(&mut response).await?;
    Ok(response)
}

fn request(
    method: &str,
    path: &str,
    proxy: &RunningProxy,
    headers: &[(&str, &str)],
    body: &str,
) -> Vec<u8> {
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\n",
        proxy.address().authority()
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request.push_str(body);
    request.into_bytes()
}

fn has_status(response: &[u8], status: u16) -> bool {
    let prefix = format!("HTTP/1.1 {status} ");
    response.starts_with(prefix.as_bytes())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn bootstrap_and_cookie_authentication_precede_upstream_dial() -> Result<(), TestError> {
    let fixture = Fixture::start(1).await?;

    let unauthenticated_bootstrap = request("GET", "/__rpackit_bootstrap", &fixture.proxy, &[], "");
    assert!(has_status(
        &raw_request(&fixture.proxy, &unauthenticated_bootstrap).await?,
        401
    ));
    assert_eq!(fixture.upstream.snapshot().await.connections, 0);

    for headers in [
        vec![(BOOTSTRAP_HEADER_NAME, "wrong")],
        vec![
            (BOOTSTRAP_HEADER_NAME, "wrong"),
            (BOOTSTRAP_HEADER_NAME, "wrong"),
        ],
        vec![(BOOTSTRAP_HEADER_NAME, "malformed,credential")],
    ] {
        let rejected = request("GET", "/__rpackit_bootstrap", &fixture.proxy, &headers, "");
        assert!(!has_status(
            &raw_request(&fixture.proxy, &rejected).await?,
            200
        ));
        assert_eq!(fixture.upstream.snapshot().await.connections, 0);
    }

    let bootstrap = request(
        "GET",
        "/__rpackit_bootstrap",
        &fixture.proxy,
        &[(BOOTSTRAP_HEADER_NAME, &fixture.bootstrap_header())],
        "",
    );
    assert!(has_status(
        &raw_request(&fixture.proxy, &bootstrap).await?,
        200
    ));
    assert_eq!(fixture.upstream.snapshot().await.connections, 0);
    let replay = raw_request(&fixture.proxy, &bootstrap).await?;
    assert!(has_status(&replay, 401));
    assert_eq!(fixture.upstream.snapshot().await.connections, 0);

    let missing = request("GET", "/api/data", &fixture.proxy, &[], "");
    assert!(has_status(
        &raw_request(&fixture.proxy, &missing).await?,
        401
    ));
    assert_eq!(fixture.upstream.snapshot().await.connections, 0);

    let wrong = request(
        "GET",
        "/api/data",
        &fixture.proxy,
        &[("Cookie", &format!("{SESSION_COOKIE_NAME}=wrong"))],
        "",
    );
    assert!(has_status(&raw_request(&fixture.proxy, &wrong).await?, 401));
    assert_eq!(fixture.upstream.snapshot().await.connections, 0);

    let cookie = fixture.cookie_header();
    let misplaced_bootstrap = request(
        "GET",
        "/api/data",
        &fixture.proxy,
        &[
            ("Cookie", cookie.as_str()),
            (BOOTSTRAP_HEADER_NAME, &fixture.bootstrap_header()),
        ],
        "",
    );
    assert!(has_status(
        &raw_request(&fixture.proxy, &misplaced_bootstrap).await?,
        400
    ));
    assert_eq!(fixture.upstream.snapshot().await.connections, 0);

    for path in [
        "/__rpackit_bootstrap?query=1",
        "/%5f%5frpackit_bootstrap",
        "/__rpackit_bootstrap/",
        "/x/../__rpackit_bootstrap",
        "/%2f__rpackit_bootstrap",
    ] {
        let variant = request(
            "GET",
            path,
            &fixture.proxy,
            &[("Cookie", cookie.as_str())],
            "",
        );
        assert!(has_status(
            &raw_request(&fixture.proxy, &variant).await?,
            400
        ));
        assert_eq!(fixture.upstream.snapshot().await.connections, 0);
    }

    let duplicated = request(
        "GET",
        "/api/data",
        &fixture.proxy,
        &[("Cookie", &format!("{cookie}; RPACKIT_PROXY_V1=wrong"))],
        "",
    );
    let duplicated_response = raw_request(&fixture.proxy, &duplicated).await?;
    assert!(!has_status(&duplicated_response, 200));
    assert_eq!(fixture.upstream.snapshot().await.connections, 0);

    let valid = request(
        "GET",
        "/api/data",
        &fixture.proxy,
        &[
            ("Cookie", &format!("app_cookie=ok; {cookie}")),
            ("Shiny-Shared-Secret", "browser-controlled"),
            ("Forwarded", "for=203.0.113.9"),
            ("X-Forwarded-Host", "attacker.test"),
        ],
        "",
    );
    assert!(has_status(&raw_request(&fixture.proxy, &valid).await?, 200));
    let snapshot = fixture.upstream.snapshot().await;
    assert_eq!(snapshot.connections, 1);
    assert_eq!(snapshot.protected_header_valid, 1);
    assert_eq!(snapshot.protected_header_invalid_count, 0);
    assert_eq!(snapshot.proxy_cookie_leaks, 0);
    assert_eq!(snapshot.forwarding_header_leaks, 0);

    fixture.shutdown().await
}

#[tokio::test]
async fn malformed_and_confused_requests_never_dial_upstream() -> Result<(), TestError> {
    let fixture = Fixture::start(2).await?;
    let authority = fixture.proxy.address().authority();
    let cookie = fixture.cookie_header();
    let cases = [
        format!(
            "GET / HTTP/1.1\r\nHost: {authority}\r\nHost: {authority}\r\nCookie: {cookie}\r\n\r\n"
        ),
        format!(
            "POST / HTTP/1.1\r\nHost: {authority}\r\nCookie: {cookie}\r\nContent-Length: 0\r\nContent-Length: 0\r\nOrigin: {}\r\n\r\n",
            fixture.proxy.address().origin()
        ),
        format!(
            "POST / HTTP/1.1\r\nHost: {authority}\r\nCookie: {cookie}\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\nOrigin: {}\r\n\r\n",
            fixture.proxy.address().origin()
        ),
        format!(
            "GET http://example.test/ HTTP/1.1\r\nHost: {authority}\r\nCookie: {cookie}\r\n\r\n"
        ),
        format!(
            "CONNECT example.test:443 HTTP/1.1\r\nHost: {authority}\r\nCookie: {cookie}\r\n\r\n"
        ),
        format!("TRACE / HTTP/1.1\r\nHost: {authority}\r\nCookie: {cookie}\r\n\r\n"),
        format!(
            "GET / HTTP/1.1\r\nHost: {authority}\r\nConnection: Cookie\r\nCookie: {cookie}\r\n\r\n"
        ),
        format!(
            "GET / HTTP/1.1\r\nHost: {authority}\r\nConnection: Upgrade\r\nUpgrade: h2c\r\nHTTP2-Settings: bad\r\nCookie: {cookie}\r\n\r\n"
        ),
        format!(
            "GET / HTTP/1.1\r\nHost: localhost:{}\r\nCookie: {cookie}\r\n\r\n",
            fixture.proxy.address().port()
        ),
        format!("GET /__rpackit_bootstrap?query=1 HTTP/1.1\r\nHost: {authority}\r\n\r\n"),
        format!("GET /%5f%5frpackit_bootstrap HTTP/1.1\r\nHost: {authority}\r\n\r\n"),
    ];
    for case in cases {
        let response = raw_request(&fixture.proxy, case.as_bytes()).await?;
        assert!(!has_status(&response, 200));
    }
    assert_eq!(fixture.upstream.snapshot().await.connections, 0);
    fixture.shutdown().await
}

#[tokio::test]
async fn unsafe_methods_require_the_exact_proxy_origin() -> Result<(), TestError> {
    let fixture = Fixture::start(3).await?;
    let cookie = fixture.cookie_header();
    let body = "ok";

    for origin in [None, Some("null"), Some("http://attacker.test")] {
        let mut headers = vec![
            ("Cookie", cookie.as_str()),
            ("Content-Length", "2"),
            ("Content-Type", "text/plain"),
        ];
        if let Some(origin) = origin {
            headers.push(("Origin", origin));
        }
        let request = request("POST", "/api/submit", &fixture.proxy, &headers, body);
        assert!(has_status(
            &raw_request(&fixture.proxy, &request).await?,
            403
        ));
    }
    assert_eq!(fixture.upstream.snapshot().await.connections, 0);

    let origin = fixture.proxy.address().origin();
    let valid = request(
        "POST",
        "/api/submit",
        &fixture.proxy,
        &[
            ("Cookie", cookie.as_str()),
            ("Origin", origin.as_str()),
            ("Content-Length", "2"),
            ("Content-Type", "text/plain"),
        ],
        body,
    );
    assert!(has_status(&raw_request(&fixture.proxy, &valid).await?, 204));
    assert_eq!(fixture.upstream.snapshot().await.connections, 1);
    fixture.shutdown().await
}

#[tokio::test]
async fn redirects_and_upstream_cookies_remain_origin_bound() -> Result<(), TestError> {
    let fixture = Fixture::start(4).await?;
    let cookie = fixture.cookie_header();

    let internal = request(
        "GET",
        "/redirect/internal",
        &fixture.proxy,
        &[("Cookie", cookie.as_str())],
        "",
    );
    let internal = raw_request(&fixture.proxy, &internal).await?;
    assert!(has_status(&internal, 302));
    assert!(
        String::from_utf8_lossy(&internal)
            .contains(format!("location: {}/api/data", fixture.proxy.address().origin()).as_str())
    );

    let external = request(
        "GET",
        "/redirect/external",
        &fixture.proxy,
        &[("Cookie", cookie.as_str())],
        "",
    );
    let external = raw_request(&fixture.proxy, &external).await?;
    assert!(has_status(&external, 302));
    assert!(
        String::from_utf8_lossy(&external)
            .contains(format!("location: http://{}/collect", fixture.collector.address()).as_str())
    );
    assert_eq!(fixture.collector.snapshot().requests, 0);

    let application_cookie = request(
        "GET",
        "/cookies/app",
        &fixture.proxy,
        &[("Cookie", cookie.as_str())],
        "",
    );
    let application_cookie = raw_request(&fixture.proxy, &application_cookie).await?;
    let application_cookie_text = String::from_utf8_lossy(&application_cookie);
    assert!(has_status(&application_cookie, 204));
    assert!(application_cookie_text.contains("set-cookie: application_cookie=ok; HttpOnly"));
    assert!(
        !application_cookie_text
            .to_ascii_lowercase()
            .contains("domain=")
    );

    for path in ["/cookies/reserved", "/cookies/bad-domain"] {
        let request = request(
            "GET",
            path,
            &fixture.proxy,
            &[("Cookie", cookie.as_str())],
            "",
        );
        assert!(has_status(
            &raw_request(&fixture.proxy, &request).await?,
            502
        ));
    }

    let protected_response = request(
        "GET",
        "/headers/protected",
        &fixture.proxy,
        &[("Cookie", cookie.as_str())],
        "",
    );
    let protected_response = raw_request(&fixture.proxy, &protected_response).await?;
    let protected_response_text = String::from_utf8_lossy(&protected_response).to_ascii_lowercase();
    assert!(has_status(&protected_response, 204));
    assert!(!protected_response_text.contains("shiny-shared-secret"));
    assert!(!protected_response_text.contains("x-rpackit-bootstrap"));

    let collector = fixture.collector.snapshot();
    assert_eq!(collector.proxy_cookie_leaks, 0);
    assert_eq!(collector.protected_header_leaks, 0);
    fixture.shutdown().await
}

#[tokio::test]
async fn websocket_is_authenticated_then_tunnelled_without_extensions() -> Result<(), TestError> {
    let fixture = Fixture::start(5).await?;
    let websocket_key = "MDEyMzQ1Njc4OWFiY2RlZg==";
    let origin = fixture.proxy.address().origin();

    for cookie in [None, Some(format!("{SESSION_COOKIE_NAME}=wrong"))] {
        let mut headers = vec![
            ("Connection", "Upgrade"),
            ("Upgrade", "websocket"),
            ("Sec-WebSocket-Version", "13"),
            ("Sec-WebSocket-Key", websocket_key),
            ("Origin", origin.as_str()),
        ];
        if let Some(cookie) = cookie.as_deref() {
            headers.push(("Cookie", cookie));
        }
        let rejected = request("GET", "/ws-cookie", &fixture.proxy, &headers, "");
        assert!(has_status(
            &raw_request(&fixture.proxy, &rejected).await?,
            401
        ));
    }
    assert_eq!(fixture.upstream.snapshot().await.connections, 0);

    let cookie = fixture.cookie_header();
    for extra_headers in [
        vec![("Sec-WebSocket-Version", "12")],
        vec![("Sec-WebSocket-Key", "not-base64")],
        vec![("Sec-WebSocket-Extensions", "permessage-deflate; a=1; a=2")],
    ] {
        let mut headers = vec![
            ("Connection", "Upgrade"),
            ("Upgrade", "websocket"),
            ("Sec-WebSocket-Version", "13"),
            ("Sec-WebSocket-Key", websocket_key),
            ("Origin", origin.as_str()),
            ("Cookie", cookie.as_str()),
        ];
        for (name, value) in extra_headers {
            if name == "Sec-WebSocket-Version" {
                headers.retain(|(existing, _)| *existing != name);
            }
            if name == "Sec-WebSocket-Key" {
                headers.retain(|(existing, _)| *existing != name);
            }
            headers.push((name, value));
        }
        let rejected = request("GET", "/ws-cookie", &fixture.proxy, &headers, "");
        assert!(!has_status(
            &raw_request(&fixture.proxy, &rejected).await?,
            101
        ));
        assert_eq!(fixture.upstream.snapshot().await.connections, 0);
    }

    let physical = format!(
        "ws://127.0.0.1:{}/ws-cookie",
        fixture.proxy.address().port()
    );
    let mut request = physical.into_client_request()?;
    request.headers_mut().insert(
        HOST,
        HeaderValue::from_str(&fixture.proxy.address().authority())?,
    );
    request.headers_mut().insert(
        ORIGIN,
        HeaderValue::from_str(&fixture.proxy.address().origin())?,
    );
    request.headers_mut().insert(
        COOKIE,
        HeaderValue::from_str(&format!("app_ws=ok; {}", fixture.cookie_header()))?,
    );

    let (mut websocket, response) = connect_async(request).await?;
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    websocket.send(Message::Text("echo".into())).await?;
    let message = websocket
        .next()
        .await
        .ok_or_else(|| io::Error::other("websocket closed before echo"))??;
    assert_eq!(message, Message::Text("echo".into()));
    websocket.close(None).await?;

    let snapshot = fixture.upstream.snapshot().await;
    assert_eq!(snapshot.routes.get("/ws-cookie"), Some(&1));
    assert_eq!(snapshot.protected_header_valid, 1);
    assert_eq!(snapshot.proxy_cookie_leaks, 0);
    assert_eq!(snapshot.websocket_extension_leaks, 0);
    fixture.shutdown().await
}

#[tokio::test]
async fn concurrent_instances_cannot_reuse_proxy_credentials() -> Result<(), TestError> {
    let collector = ExternalCollector::start().await?;
    let upstream_secret = Arc::new(Secret::from_bytes([90; 32]));
    let upstream = MockUpstream::start(Arc::clone(&upstream_secret), collector.address()).await?;

    let session_a = Arc::new(Secret::from_bytes([91; 32]));
    let session_b = Arc::new(Secret::from_bytes([92; 32]));
    let bootstrap_a = Arc::new(Secret::from_bytes([93; 32]));
    let bootstrap_b = Arc::new(Secret::from_bytes([94; 32]));
    let proxy_a = RunningProxy::start(ProxyConfig::explicit(
        upstream.address(),
        "rpackit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.localhost",
        TransportSecrets::new(
            Arc::clone(&session_a),
            Arc::clone(&upstream_secret),
            bootstrap_a,
        ),
    )?)
    .await?;
    let proxy_b = RunningProxy::start(ProxyConfig::explicit(
        upstream.address(),
        "rpackit-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.localhost",
        TransportSecrets::new(Arc::clone(&session_b), upstream_secret, bootstrap_b),
    )?)
    .await?;

    let cookie_a = session_a.with_exposed(|value| format!("{SESSION_COOKIE_NAME}={value}"));
    let cross_instance = request(
        "GET",
        "/api/data",
        &proxy_b,
        &[("Cookie", cookie_a.as_str())],
        "",
    );
    assert!(has_status(
        &raw_request(&proxy_b, &cross_instance).await?,
        401
    ));
    assert_eq!(upstream.snapshot().await.connections, 0);

    let cookie_b = session_b.with_exposed(|value| format!("{SESSION_COOKIE_NAME}={value}"));
    let valid = request(
        "GET",
        "/api/data",
        &proxy_b,
        &[("Cookie", cookie_b.as_str())],
        "",
    );
    assert!(has_status(&raw_request(&proxy_b, &valid).await?, 200));
    assert_eq!(upstream.snapshot().await.connections, 1);

    proxy_a.shutdown().await?;
    proxy_b.shutdown().await?;
    upstream.shutdown().await?;
    collector.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn resolver_never_accepts_non_loopback_answers() -> Result<(), TestError> {
    let fixture = Fixture::start(6).await?;
    let resolution = fixture.proxy.resolve_hostname().await;
    assert!(!matches!(resolution, HostResolution::NonLoopback(_)));
    fixture.shutdown().await
}

#[tokio::test]
async fn websocket_idle_timeout_resets_after_each_successful_transfer() -> Result<(), TestError> {
    let limits = TransportLimits {
        websocket_idle_timeout: Duration::from_millis(250),
        ..TransportLimits::default()
    };
    let fixture = Fixture::start_with_limits(7, limits).await?;

    let physical = format!("ws://127.0.0.1:{}/ws", fixture.proxy.address().port());
    let mut request = physical.into_client_request()?;
    request.headers_mut().insert(
        HOST,
        HeaderValue::from_str(&fixture.proxy.address().authority())?,
    );
    request.headers_mut().insert(
        ORIGIN,
        HeaderValue::from_str(&fixture.proxy.address().origin())?,
    );
    request
        .headers_mut()
        .insert(COOKIE, HeaderValue::from_str(&fixture.cookie_header())?);
    let (mut websocket, response) = connect_async(request).await?;
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);

    for index in 0..4 {
        let expected = Message::Text(format!("active-{index}").into());
        websocket.send(expected.clone()).await?;
        let echoed = timeout(Duration::from_secs(1), websocket.next())
            .await
            .map_err(|_| io::Error::other("WebSocket echo timed out"))?
            .ok_or_else(|| io::Error::other("WebSocket closed while active"))??;
        assert_eq!(echoed, expected);
        if index < 3 {
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

    let closed_while_idle = timeout(Duration::from_secs(2), async {
        loop {
            match websocket.next().await {
                None | Some(Err(_) | Ok(Message::Close(_))) => return true,
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        closed_while_idle,
        "WebSocket remained open past its activity-based idle timeout"
    );

    let snapshot = fixture.upstream.snapshot().await;
    assert_eq!(snapshot.proxy_cookie_leaks, 0);
    assert_eq!(snapshot.bootstrap_header_leaks, 0);
    fixture.shutdown().await
}

#[tokio::test]
async fn request_body_resource_limits_fail_closed() -> Result<(), TestError> {
    let evidence = probe_request_body_limits().await?;

    assert!(evidence.probe_completed, "{evidence:#?}");
    assert!(evidence.valid_baseline_passed, "{evidence:#?}");
    assert!(evidence.byte_limit_passed, "{evidence:#?}");
    assert!(evidence.idle_limit_passed, "{evidence:#?}");
    assert!(evidence.minimum_rate_limit_passed, "{evidence:#?}");
    assert!(evidence.total_timeout_limit_passed, "{evidence:#?}");
    assert!(evidence.trailer_limit_passed, "{evidence:#?}");
    assert_eq!(evidence.cases_attempted, 5, "{evidence:#?}");
    assert_eq!(evidence.bounded_terminations, 5, "{evidence:#?}");
    assert!(
        (4..=6).contains(&evidence.upstream_body_probe_requests),
        "{evidence:#?}"
    );
    assert_eq!(
        evidence.upstream_requests_with_valid_secret, evidence.upstream_body_probe_requests,
        "{evidence:#?}"
    );
    assert_eq!(evidence.upstream_requests_with_invalid_secret, 0);
    assert_eq!(evidence.proxy_cookie_leaks, 0);
    assert_eq!(evidence.bootstrap_header_leaks, 0);
    assert!(
        evidence.all_request_body_limits_fail_closed(),
        "{evidence:#?}"
    );
    Ok(())
}

#[tokio::test]
async fn shutdown_drains_partial_http_and_websocket_before_returning() -> Result<(), TestError> {
    let fixture = Fixture::start(8).await?;
    let proxy_socket = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        fixture.proxy.address().port(),
    );

    let mut partial_http = TcpStream::connect(proxy_socket).await?;
    partial_http
        .write_all(
            format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nX-Incomplete",
                fixture.proxy.address().authority()
            )
            .as_bytes(),
        )
        .await?;

    let physical = format!("ws://{proxy_socket}/ws");
    let mut websocket_request = physical.into_client_request()?;
    websocket_request.headers_mut().insert(
        HOST,
        HeaderValue::from_str(&fixture.proxy.address().authority())?,
    );
    websocket_request.headers_mut().insert(
        ORIGIN,
        HeaderValue::from_str(&fixture.proxy.address().origin())?,
    );
    websocket_request
        .headers_mut()
        .insert(COOKIE, HeaderValue::from_str(&fixture.cookie_header())?);
    let (mut websocket, response) = connect_async(websocket_request).await?;
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    websocket.send(Message::Text("established".into())).await?;
    let echo = timeout(Duration::from_secs(1), websocket.next())
        .await
        .map_err(|_| io::Error::other("WebSocket establishment timed out"))?
        .ok_or_else(|| io::Error::other("WebSocket closed before shutdown"))??;
    assert_eq!(echo, Message::Text("established".into()));

    let Fixture {
        collector,
        upstream,
        proxy,
    } = fixture;
    timeout(Duration::from_secs(1), proxy.shutdown())
        .await
        .map_err(|_| io::Error::other("proxy shutdown did not drain promptly"))??;

    let mut byte = [0_u8; 1];
    let partial_result = timeout(Duration::from_secs(1), partial_http.read(&mut byte))
        .await
        .map_err(|_| io::Error::other("partial HTTP connection remained open"))?;
    assert!(
        matches!(partial_result, Ok(0) | Err(_)),
        "partial HTTP connection produced data after shutdown"
    );

    let websocket_closed = timeout(Duration::from_secs(1), async {
        loop {
            match websocket.next().await {
                None | Some(Err(_) | Ok(Message::Close(_))) => return true,
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        websocket_closed,
        "WebSocket tunnel remained open after shutdown returned"
    );

    let reconnect = timeout(Duration::from_secs(1), TcpStream::connect(proxy_socket)).await;
    match reconnect {
        Ok(Err(_)) | Err(_) => {}
        Ok(Ok(socket)) => {
            return Err(io::Error::other(format!(
                "proxy port still accepted a connection after shutdown: local={:?}, peer={:?}",
                socket.local_addr(),
                socket.peer_addr()
            ))
            .into());
        }
    }

    let upstream_snapshot = upstream.snapshot().await;
    assert_eq!(upstream_snapshot.proxy_cookie_leaks, 0);
    assert_eq!(upstream_snapshot.bootstrap_header_leaks, 0);
    assert_eq!(upstream_snapshot.forwarding_header_leaks, 0);
    assert_eq!(upstream_snapshot.websocket_extension_leaks, 0);
    let collector_snapshot = collector.snapshot();
    assert_eq!(collector_snapshot.proxy_cookie_leaks, 0);
    assert_eq!(collector_snapshot.protected_header_leaks, 0);
    assert_eq!(collector_snapshot.bootstrap_header_leaks, 0);

    upstream.shutdown().await?;
    collector.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn malformed_upstream_response_heads_fail_closed() -> Result<(), TestError> {
    let evidence = probe_malformed_upstream_response_heads().await?;

    assert!(evidence.probe_completed, "{evidence:#?}");
    assert!(evidence.valid_baseline_passed, "{evidence:#?}");
    assert!(evidence.valid_websocket_baseline_passed, "{evidence:#?}");
    assert_eq!(evidence.http_cases_attempted, 16, "{evidence:#?}");
    assert_eq!(evidence.http_fail_closed_responses, 16, "{evidence:#?}");
    assert_eq!(evidence.websocket_cases_attempted, 16, "{evidence:#?}");
    assert_eq!(
        evidence.websocket_fail_closed_responses, 16,
        "{evidence:#?}"
    );
    assert_eq!(evidence.cases_attempted, 32, "{evidence:#?}");
    assert_eq!(
        evidence.fail_closed_responses, evidence.cases_attempted,
        "{evidence:#?}"
    );
    assert_eq!(
        evidence.upstream_requests_with_valid_secret,
        evidence.cases_attempted + 2
    );
    assert_eq!(
        evidence.upstream_websocket_requests_valid,
        evidence.websocket_cases_attempted + 1
    );
    assert_eq!(evidence.unexpected_downstream_upgrades, 0, "{evidence:#?}");
    assert_eq!(evidence.attacker_markers_forwarded, 0, "{evidence:#?}");
    assert_eq!(evidence.cases.len(), evidence.cases_attempted as usize);
    assert!(
        evidence.cases.values().all(|passed| *passed),
        "{evidence:#?}"
    );
    assert!(evidence.all_response_heads_fail_closed(), "{evidence:#?}");

    Ok(())
}

#[tokio::test]
async fn malformed_upstream_response_bodies_fail_closed() -> Result<(), TestError> {
    let evidence = probe_malformed_upstream_response_bodies().await?;

    assert!(evidence.probe_completed, "{evidence:#?}");
    assert!(
        evidence.valid_content_length_baseline_passed,
        "{evidence:#?}"
    );
    assert!(evidence.valid_chunked_baseline_passed, "{evidence:#?}");
    assert!(
        evidence.valid_close_delimited_baseline_passed,
        "{evidence:#?}"
    );
    assert!(
        evidence.valid_head_nonzero_length_baseline_passed,
        "{evidence:#?}"
    );
    assert!(
        evidence.valid_not_modified_nonzero_length_baseline_passed,
        "{evidence:#?}"
    );
    assert!(evidence.valid_no_content_baseline_passed, "{evidence:#?}");
    assert!(
        evidence.valid_reset_content_zero_length_baseline_passed,
        "{evidence:#?}"
    );
    assert_eq!(evidence.cases_attempted, 23, "{evidence:#?}");
    assert_eq!(evidence.exact_bad_gateway_responses, 6, "{evidence:#?}");
    assert_eq!(
        evidence.stream_fail_closed_terminations, 12,
        "{evidence:#?}"
    );
    assert_eq!(
        evidence.close_delimited_limit_terminations, 1,
        "{evidence:#?}"
    );
    assert_eq!(evidence.bodyless_status_terminations, 2, "{evidence:#?}");
    assert_eq!(evidence.isolated_complete_responses, 2, "{evidence:#?}");
    assert_eq!(
        evidence.bounded_terminations, evidence.cases_attempted,
        "{evidence:#?}"
    );
    assert_eq!(
        evidence.upstream_requests_with_valid_secret,
        evidence.cases_attempted + 7,
        "{evidence:#?}"
    );
    assert_eq!(
        evidence.second_downstream_requests_attempted,
        evidence.cases_attempted + 7,
        "{evidence:#?}"
    );
    assert_eq!(
        evidence.downstream_connections_physically_closed,
        evidence.cases_attempted + 7,
        "{evidence:#?}"
    );
    assert_eq!(evidence.second_downstream_responses, 0, "{evidence:#?}");
    assert_eq!(evidence.attacker_markers_forwarded, 0, "{evidence:#?}");
    assert_eq!(evidence.reusable_downstream_responses, 0, "{evidence:#?}");
    assert_eq!(evidence.cases.len(), evidence.cases_attempted as usize);
    assert!(
        evidence.cases.values().all(|passed| *passed),
        "{evidence:#?}"
    );
    assert!(evidence.all_response_bodies_fail_closed(), "{evidence:#?}");

    Ok(())
}

#[cfg(windows)]
#[tokio::test]
async fn windows_wildcard_overlap_never_receives_exact_loopback_traffic() -> Result<(), TestError> {
    let fixture = Fixture::start(9).await?;
    let evidence = probe_listener_overlap(&fixture.proxy).await?;

    assert!(evidence.windows_probe_completed);
    for family in [&evidence.ipv4_wildcard, &evidence.ipv6_v6_only_wildcard] {
        assert!(family.probe_completed);
        assert_eq!(family.requests_attempted, 8);
        assert_eq!(
            family.proxy_unauthorized_responses,
            family.requests_attempted
        );
        assert_eq!(family.wildcard_accepts, 0);
        assert!(family.exact_proxy_won);
    }
    let dual_stack = &evidence.ipv6_dual_stack_wildcard;
    assert!(dual_stack.probe_completed);
    assert_eq!(dual_stack.ipv4_requests_attempted, 8);
    assert_eq!(
        dual_stack.ipv4_proxy_unauthorized_responses,
        dual_stack.ipv4_requests_attempted
    );
    assert_eq!(dual_stack.ipv6_requests_attempted, 8);
    assert_eq!(
        dual_stack.ipv6_proxy_unauthorized_responses,
        dual_stack.ipv6_requests_attempted
    );
    assert_eq!(dual_stack.wildcard_accepts, 0);
    assert!(dual_stack.exact_proxies_won);
    assert!(evidence.all_variants_prove_exact_proxy_ownership());
    assert_eq!(fixture.upstream.snapshot().await.connections, 0);

    fixture.shutdown().await
}
