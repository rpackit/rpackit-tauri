//! Real `WebView2` acceptance shell for transport contract version 2.

#[cfg(windows)]
mod native_webview;
mod report;

use std::{
    error::Error as StdError,
    io,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering},
    },
    time::Duration,
};

use report::{AcceptanceReport, CookieEvidence, DevelopmentGates, write_failure_report};
use rpackit_transport::{
    HostResolution, ProxyConfig, RunningProxy, SESSION_COOKIE_NAME, TransportSecrets,
};
use rpackit_transport_testkit::{ExternalCollector, MockUpstream, probe_listener_overlap};
use tauri::{
    AppHandle, WebviewUrl, WebviewWindow, WebviewWindowBuilder, Wry,
    webview::{
        NewWindowResponse, PageLoadEvent,
        cookie::{Cookie, Expiration, SameSite},
    },
};
use tokio::time::timeout;
use url::Url;

type HarnessError = Box<dyn StdError + Send + Sync>;

const FORBIDDEN_WEBVIEW_ENVIRONMENT_VARIABLES: &[&str] = &[
    "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
    "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER",
    "WEBVIEW2_USER_DATA_FOLDER",
    "WEBVIEW2_RELEASE_CHANNEL_PREFERENCE",
    "WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER",
    "WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER",
];

#[derive(Clone, Debug)]
struct HarnessOptions {
    report_path: PathBuf,
}

fn main() {
    let Ok(options) = parse_options() else {
        eprintln!("usage: rpackit-windows-spike [--report <path>]");
        std::process::exit(2);
    };
    let failure_path = options.report_path.clone();
    let async_failure_path = failure_path.clone();
    let process_exit_code = Arc::new(AtomicI32::new(1));
    let async_exit_code = Arc::clone(&process_exit_code);
    let result = tauri::Builder::default()
        .setup(move |app| {
            let handle = app.handle().clone();
            let exit_handle = handle.clone();
            tauri::async_runtime::spawn(async move {
                let exit_code = if let Ok(exit_code) = run_harness(handle, options).await {
                    exit_code
                } else {
                    let _ = write_failure_report(&async_failure_path);
                    1
                };
                async_exit_code.store(exit_code, Ordering::SeqCst);
                exit_handle.exit(exit_code);
            });
            Ok(())
        })
        .run(tauri::generate_context!());
    if result.is_err() {
        let _ = write_failure_report(&failure_path);
        std::process::exit(1);
    }
    std::process::exit(process_exit_code.load(Ordering::SeqCst));
}

fn parse_options() -> Result<HarnessOptions, ()> {
    let mut arguments = std::env::args_os().skip(1);
    let mut report_path = None;
    while let Some(argument) = arguments.next() {
        if argument == "--report" {
            if report_path.is_some() {
                return Err(());
            }
            report_path = arguments.next().map(PathBuf::from);
            if report_path.is_none() {
                return Err(());
            }
        } else {
            return Err(());
        }
    }
    Ok(HarnessOptions {
        report_path: report_path
            .unwrap_or_else(|| std::env::temp_dir().join("rpackit-transport-spike-report.json")),
    })
}

async fn run_harness(app: AppHandle<Wry>, options: HarnessOptions) -> Result<i32, HarnessError> {
    reject_webview_environment_overrides()?;
    let process_environment_secret_free = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let process_arguments_secret_free = Arc::new(std::sync::atomic::AtomicBool::new(true));

    let secrets = TransportSecrets::generate()?;
    let collector = ExternalCollector::start().await?;
    let upstream = MockUpstream::start(secrets.upstream(), collector.address()).await?;
    let config = ProxyConfig::generate_with_secrets(upstream.address(), secrets)?;
    let proxy = RunningProxy::start(config).await?;

    process_environment_secret_free.store(
        secrets_absent_from_environment(proxy.secrets()),
        Ordering::Relaxed,
    );
    process_arguments_secret_free.store(
        secrets_absent_from_arguments(proxy.secrets()),
        Ordering::Relaxed,
    );

    let listener_overlap = probe_listener_overlap(&proxy).await?;
    let resolution = proxy.resolve_hostname().await;
    if !resolution_allows_webview(&resolution) {
        return Err(
            io::Error::other("generated browser hostname resolved outside loopback").into(),
        );
    }
    let profile = tempfile::Builder::new()
        .prefix("rpackit-webview2-spike-")
        .tempdir()?;
    let profile_path = profile.path().to_path_buf();
    let evidence = Arc::new(Mutex::new(CookieEvidence::default()));
    let window = build_window(&app, &proxy, profile_path.clone(), Arc::clone(&evidence)).await?;

    let browser_result = timeout(Duration::from_secs(30), upstream.wait_for_browser_report()).await;
    let browser_report_received = browser_result.is_ok();
    let browser_report = browser_result.unwrap_or_default();
    update_evidence(&evidence, |item| {
        item.browser_report_received = browser_report_received;
    });
    let upstream_snapshot = upstream.snapshot().await;
    let collector_snapshot = collector.snapshot();
    let cookie_evidence = evidence
        .lock()
        .map_err(|_| io::Error::other("cookie evidence lock failed"))?
        .clone();

    // Keep Tauri's event loop alive while the secured WebView is destroyed and
    // recreated. This isolated sentinel only permits Tauri's bundled fallback.
    let sentinel_profile = tempfile::Builder::new()
        .prefix("rpackit-webview2-sentinel-")
        .tempdir()?;
    let _lifecycle_sentinel =
        build_lifecycle_sentinel(&app, sentinel_profile.path().to_path_buf()).await?;
    let cleanup_cookie_absent =
        clear_session_cookie(&window, &proxy, &cookie_evidence).unwrap_or(false);
    let cleanup_browsing_data_queued = window.clear_all_browsing_data().is_ok();
    let window_destroyed = window.destroy().is_ok();
    tokio::time::sleep(Duration::from_millis(250)).await;
    let clean_recreation_cookie_absent =
        probe_recreated_profile(&app, profile_path, Url::parse(&proxy.address().root_url())?)
            .await
            .unwrap_or(false);
    drop(profile);
    update_evidence(&evidence, |item| {
        item.clean_recreation_cookie_absent = clean_recreation_cookie_absent;
    });
    let cookie_evidence = evidence
        .lock()
        .map_err(|_| io::Error::other("cookie evidence lock failed"))?
        .clone();

    let gates = DevelopmentGates::evaluate(
        &resolution,
        &listener_overlap,
        &cookie_evidence,
        &browser_report,
        &upstream_snapshot,
        &collector_snapshot,
        process_environment_secret_free.load(Ordering::Relaxed),
        process_arguments_secret_free.load(Ordering::Relaxed),
        cleanup_cookie_absent,
        cleanup_browsing_data_queued,
        window_destroyed,
    );
    let report = AcceptanceReport::new(
        tauri::webview_version().ok(),
        resolution,
        listener_overlap,
        cookie_evidence,
        browser_report,
        upstream_snapshot,
        collector_snapshot,
        gates,
    );
    report.write(&options.report_path)?;
    let exit_code = i32::from(!report.development_gates_passed);

    proxy.shutdown().await?;
    upstream.shutdown().await?;
    collector.shutdown().await?;
    Ok(exit_code)
}

async fn build_lifecycle_sentinel(
    app: &AppHandle<Wry>,
    profile_path: PathBuf,
) -> Result<WebviewWindow<Wry>, HarnessError> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let dispatcher = app.clone();
    let builder_app = app.clone();
    dispatcher.run_on_main_thread(move || {
        let result = WebviewWindowBuilder::new(
            &builder_app,
            "lifecycle-sentinel",
            WebviewUrl::App("index.html".into()),
        )
        .visible(false)
        .focused(false)
        .resizable(false)
        .data_directory(profile_path)
        .incognito(true)
        .devtools(false)
        .browser_extensions_enabled(false)
        .general_autofill_enabled(false)
        .disable_drag_drop_handler()
        .zoom_hotkeys_enabled(false)
        .skip_taskbar(true)
        .on_navigation(is_bundled_placeholder)
        .on_new_window(|_, _| NewWindowResponse::Deny)
        .on_download(|_, _| false)
        .build()
        .map_err(|_| ());
        let _ = sender.send(result);
    })?;
    receiver
        .await
        .map_err(|_| io::Error::other("lifecycle sentinel channel closed"))?
        .map_err(|()| io::Error::other("lifecycle sentinel creation failed").into())
}

// Keeping the security controls adjacent makes this construction boundary
// auditable as one unit.
#[allow(clippy::too_many_lines)]
async fn build_window(
    app: &AppHandle<Wry>,
    proxy: &RunningProxy,
    profile_path: PathBuf,
    evidence: Arc<Mutex<CookieEvidence>>,
) -> Result<WebviewWindow<Wry>, HarnessError> {
    let bootstrap_url = Url::parse(&proxy.address().bootstrap_url())?;
    let root_url = Url::parse(&proxy.address().root_url())?;
    let expected_host = proxy.address().hostname().to_owned();
    let expected_port = proxy.address().port();
    let session = proxy.secrets().session();
    let bootstrap = proxy.secrets().bootstrap();
    let state = Arc::new(AtomicU8::new(0));
    let bootstrap_queued = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let main_thread_app = app.clone();
    let builder_app = app.clone();
    let native_bootstrap_url = bootstrap_url.clone();
    let page_bootstrap_queued = Arc::clone(&bootstrap_queued);
    main_thread_app.run_on_main_thread(move || {
        let navigation_host = expected_host.clone();
        let navigation_state = Arc::clone(&state);
        let page_bootstrap = bootstrap_url.clone();
        let page_root = root_url.clone();
        let page_state = Arc::clone(&state);
        let page_evidence = Arc::clone(&evidence);
        let page_session = Arc::clone(&session);
        let result = WebviewWindowBuilder::new(
            &builder_app,
            "transport-spike",
            WebviewUrl::App("index.html".into()),
        )
        .visible(false)
        .focused(false)
        .resizable(false)
        .data_directory(profile_path)
        .incognito(true)
        .devtools(false)
        .browser_extensions_enabled(false)
        .general_autofill_enabled(false)
        .disable_drag_drop_handler()
        .zoom_hotkeys_enabled(false)
        .on_navigation(move |url| {
            let proxy_origin = url.scheme() == "http"
                && url.host_str() == Some(navigation_host.as_str())
                && url.port() == Some(expected_port);
            let native_fallback =
                navigation_state.load(Ordering::SeqCst) == 0 && is_bundled_placeholder(url);
            (proxy_origin || native_fallback)
                && url.username().is_empty()
                && url.password().is_none()
        })
        .on_new_window(|_, _| NewWindowResponse::Deny)
        .on_download(|_, _| false)
        .on_page_load(move |window, payload| {
            if payload.event() != PageLoadEvent::Finished {
                return;
            }
            if payload.url() == &page_bootstrap
                && page_state
                    .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                let window = window.clone();
                let root_url = page_root.clone();
                let session = Arc::clone(&page_session);
                let state = Arc::clone(&page_state);
                let evidence = Arc::clone(&page_evidence);
                let bootstrap_queued = Arc::clone(&page_bootstrap_queued);
                std::thread::spawn(move || {
                    update_evidence(&evidence, |item| {
                        item.bootstrap_finished = true;
                        item.authenticated_bootstrap_queued =
                            bootstrap_queued.load(Ordering::SeqCst);
                    });
                    let observed = window.cookies_for_url(root_url.clone());
                    let cookie_ready = if let Ok(cookies) = observed {
                        record_cookie_readback(&evidence, &cookies, &session)
                    } else {
                        false
                    };
                    if !cookie_ready {
                        state.store(4, Ordering::SeqCst);
                        return;
                    }
                    state.store(2, Ordering::SeqCst);
                    if window.navigate(root_url).is_err() {
                        state.store(4, Ordering::SeqCst);
                    }
                });
            } else if payload.url() == &page_root
                && page_state
                    .compare_exchange(2, 3, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                update_evidence(&page_evidence, |item| {
                    item.authenticated_root_finished = true;
                });
                let _ = window.show();
            }
        })
        .build()
        .map_err(|_| ());
        let _ = sender.send(result);
    })?;
    let window = receiver
        .await
        .map_err(|_| io::Error::other("window creation channel closed"))?
        .map_err(|()| io::Error::other("secured WebView2 window creation failed"))?;
    native_webview::navigate_with_bootstrap_header(
        &window,
        native_bootstrap_url,
        bootstrap,
        bootstrap_queued,
    )?;
    Ok(window)
}

async fn probe_recreated_profile(
    app: &AppHandle<Wry>,
    profile_path: PathBuf,
    root_url: Url,
) -> Result<bool, HarnessError> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let dispatcher = app.clone();
    let builder_app = app.clone();
    dispatcher.run_on_main_thread(move || {
        let result = WebviewWindowBuilder::new(
            &builder_app,
            "profile-recreation",
            WebviewUrl::App("index.html".into()),
        )
        .visible(false)
        .focused(false)
        .data_directory(profile_path)
        .incognito(true)
        .devtools(false)
        .browser_extensions_enabled(false)
        .general_autofill_enabled(false)
        .disable_drag_drop_handler()
        .zoom_hotkeys_enabled(false)
        .on_navigation(is_bundled_placeholder)
        .on_new_window(|_, _| NewWindowResponse::Deny)
        .on_download(|_, _| false)
        .build()
        .map_err(|_| ());
        let _ = sender.send(result);
    })?;
    let window = receiver
        .await
        .map_err(|_| io::Error::other("profile recreation channel closed"))?
        .map_err(|()| io::Error::other("profile recreation window failed"))?;
    let cookies = window.cookies_for_url(root_url)?;
    let absent = !cookies
        .iter()
        .any(|cookie| cookie.name() == SESSION_COOKIE_NAME);
    let destroyed = window.destroy().is_ok();
    Ok(absent && destroyed)
}

fn record_cookie_readback(
    evidence: &Arc<Mutex<CookieEvidence>>,
    cookies: &[Cookie<'static>],
    session: &rpackit_transport::Secret,
) -> bool {
    let matching: Vec<&Cookie<'static>> = cookies
        .iter()
        .filter(|cookie| cookie.name() == SESSION_COOKIE_NAME)
        .collect();
    update_evidence(evidence, |item| {
        item.readback_count_exactly_one = matching.len() == 1;
        if let Some(cookie) = matching.first() {
            item.value_matches = session.matches(cookie.value().as_bytes());
            item.http_only = cookie.http_only() == Some(true);
            item.same_site_strict = cookie.same_site() == Some(SameSite::Strict);
            item.path_root = cookie.path() == Some("/");
            item.no_max_age = cookie.max_age().is_none();
            item.session_expiration = matches!(cookie.expires(), None | Some(Expiration::Session));
            item.secure_flag_false = cookie.secure() != Some(true);
            item.readback_domain = cookie.domain().map(str::to_owned);
        }
    });
    matching.len() == 1
        && matching[0].http_only() == Some(true)
        && matching[0].same_site() == Some(SameSite::Strict)
        && matching[0].path() == Some("/")
        && matching[0].max_age().is_none()
        && session.matches(matching[0].value().as_bytes())
}

fn clear_session_cookie(
    window: &WebviewWindow<Wry>,
    proxy: &RunningProxy,
    evidence: &CookieEvidence,
) -> Result<bool, HarnessError> {
    let root = Url::parse(&proxy.address().root_url())?;
    let cookies = window.cookies_for_url(root.clone())?;
    for cookie in cookies
        .into_iter()
        .filter(|cookie| cookie.name() == SESSION_COOKIE_NAME)
    {
        window.delete_cookie(cookie)?;
    }
    for _ in 0..20 {
        let remaining = window.cookies_for_url(root.clone())?;
        if !remaining
            .iter()
            .any(|cookie| cookie.name() == SESSION_COOKIE_NAME)
        {
            return Ok(evidence.readback_count_exactly_one);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(false)
}

fn update_evidence(
    evidence: &Arc<Mutex<CookieEvidence>>,
    update: impl FnOnce(&mut CookieEvidence),
) {
    if let Ok(mut evidence) = evidence.lock() {
        update(&mut evidence);
    }
}

fn reject_webview_environment_overrides() -> Result<(), HarnessError> {
    if webview_environment_override_present(|name| std::env::var_os(name).is_some()) {
        return Err(io::Error::other("WebView2 environment override is not allowed").into());
    }
    Ok(())
}

fn webview_environment_override_present(is_present: impl Fn(&str) -> bool) -> bool {
    FORBIDDEN_WEBVIEW_ENVIRONMENT_VARIABLES
        .iter()
        .copied()
        .any(is_present)
}

fn is_bundled_placeholder(url: &Url) -> bool {
    let bundled_origin =
        (url.scheme() == "tauri" && url.host_str() == Some("localhost") && url.port().is_none())
            || (url.scheme() == "http"
                && url.host_str() == Some("tauri.localhost")
                && url.port().is_none());
    bundled_origin
        && url.path() == "/index.html"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}

fn secrets_absent_from_environment(secrets: &TransportSecrets) -> bool {
    std::env::vars_os().all(|(name, value)| {
        text_is_secret_free(&name.to_string_lossy(), secrets)
            && text_is_secret_free(&value.to_string_lossy(), secrets)
    })
}

fn secrets_absent_from_arguments(secrets: &TransportSecrets) -> bool {
    std::env::args_os().all(|argument| text_is_secret_free(&argument.to_string_lossy(), secrets))
}

fn text_is_secret_free(text: &str, secrets: &TransportSecrets) -> bool {
    [secrets.session(), secrets.upstream(), secrets.bootstrap()]
        .into_iter()
        .all(|secret| secret.with_exposed(|value| !text.contains(value)))
}

fn resolution_allows_webview(resolution: &HostResolution) -> bool {
    !matches!(resolution, HostResolution::NonLoopback(_))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rpackit_transport::{Secret, TransportSecrets};

    use super::text_is_secret_free;

    #[test]
    fn embedded_secret_is_detected_without_exact_string_equality() {
        let session = Arc::new(Secret::from_bytes([1; 32]));
        let upstream = Arc::new(Secret::from_bytes([2; 32]));
        let bootstrap = Arc::new(Secret::from_bytes([3; 32]));
        let secrets = TransportSecrets::new(session, upstream, bootstrap);
        let embedded = secrets
            .session()
            .with_exposed(|value| format!("prefix={value};suffix"));

        assert!(!text_is_secret_free(&embedded, &secrets));
        assert!(text_is_secret_free("ordinary process metadata", &secrets));
    }

    #[test]
    fn debugger_environment_overrides_are_forbidden() {
        assert!(super::webview_environment_override_present(|name| {
            name == "WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER"
        }));
        assert!(super::webview_environment_override_present(|name| {
            name == "WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER"
        }));
    }

    #[test]
    fn nonloopback_resolution_blocks_webview_before_bootstrap() {
        use std::net::{IpAddr, Ipv4Addr};

        assert!(!super::resolution_allows_webview(
            &rpackit_transport::HostResolution::NonLoopback(vec![IpAddr::V4(Ipv4Addr::new(
                203, 0, 113, 9
            )),]),
        ));
        assert!(super::resolution_allows_webview(
            &rpackit_transport::HostResolution::Unavailable,
        ));
        assert!(super::resolution_allows_webview(
            &rpackit_transport::HostResolution::Loopback(vec![IpAddr::V4(Ipv4Addr::LOCALHOST),]),
        ));
    }
}
