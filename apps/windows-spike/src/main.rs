//! Real `WebView2` acceptance shell for transport contract version 2.

#[cfg(windows)]
mod native_webview;
mod report;

use std::{
    collections::VecDeque,
    error::Error as StdError,
    fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering},
    },
    time::Duration,
};

use report::{
    AcceptanceReport, BrowserEscapeProbe, CookieEvidence, DevelopmentGates, write_failure_report,
};
use rpackit_transport::{
    HostResolution, ProxyConfig, RunningProxy, SESSION_COOKIE_NAME, TransportSecrets,
};
use rpackit_transport_testkit::{
    ExternalCollector, MockUpstream, probe_listener_overlap,
    probe_malformed_upstream_response_bodies, probe_malformed_upstream_response_heads,
    probe_request_body_limits, probe_response_resource_limits, probe_websocket_rate_limits,
};
use tauri::{
    AppHandle, WebviewUrl, WebviewWindow, WebviewWindowBuilder, Wry,
    webview::{
        DownloadEvent, NewWindowResponse, PageLoadEvent,
        cookie::{Cookie, Expiration, SameSite},
    },
};
use tokio::time::timeout;
use url::Url;
use winreg::{
    RegKey,
    enums::{
        HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY,
        KEY_WOW64_64KEY,
    },
};

type HarnessError = Box<dyn StdError + Send + Sync>;

const FORBIDDEN_WEBVIEW_ENVIRONMENT_VARIABLES: &[&str] = &[
    "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
    "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER",
    "WEBVIEW2_USER_DATA_FOLDER",
    "WEBVIEW2_CHANNEL_SEARCH_KIND",
    "WEBVIEW2_RELEASE_CHANNELS",
    "WEBVIEW2_RELEASE_CHANNEL_PREFERENCE",
    "WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER",
    "WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER",
];
const WEBVIEW2_OVERRIDE_POLICY_KEYS: &[&str] = &[
    r"Software\Policies\Microsoft\Edge\WebView2\BrowserExecutableFolder",
    r"Software\Policies\Microsoft\Edge\WebView2\ChannelSearchKind",
    r"Software\Policies\Microsoft\Edge\WebView2\ReleaseChannels",
    r"Software\Policies\Microsoft\Edge\WebView2\AdditionalBrowserArguments",
    r"Software\Policies\Microsoft\Edge\WebView2\UserDataFolder",
    r"Software\Policies\Microsoft\Edge\WebView2\ReleaseChannelPreference",
];
const WEBVIEW2_APP_USER_MODEL_ID: &str = "dev.rpackit.transport-spike";
const PAGE_EXTERNAL_SCHEME_PROBE_URI: &str = "mailto:rpackit-browser-escape@example.invalid";
const EXTERNAL_SCHEME_PROBE_CANDIDATES: &[(&str, &str)] = &[
    ("ms-settings", "ms-settings:display"),
    ("search-ms", "search-ms:query=rpackit-browser-escape"),
    (
        "microsoft-edge",
        "microsoft-edge:https://example.invalid/rpackit-browser-escape",
    ),
    ("ms-windows-store", "ms-windows-store://home"),
    ("mailto", PAGE_EXTERNAL_SCHEME_PROBE_URI),
];
const EXTENSION_PROBE_MANIFEST: &str =
    r#"{"manifest_version":3,"name":"rpackit disabled-extension probe","version":"1.0.0"}"#;
const PROFILE_SCAN_ENTRY_LIMIT: usize = 100_000;

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

#[allow(clippy::too_many_lines)]
async fn run_harness(app: AppHandle<Wry>, options: HarnessOptions) -> Result<i32, HarnessError> {
    reject_webview_environment_overrides()?;
    let registry_overrides_absent_before_creation = webview_registry_overrides_absent()?;
    if !registry_overrides_absent_before_creation {
        return Err(io::Error::other("WebView2 registry override is not allowed").into());
    }
    let external_scheme_probe_uris = registered_external_scheme_probe_uris()?;

    let malformed_upstream = probe_malformed_upstream_response_heads().await?;
    let malformed_upstream_bodies = probe_malformed_upstream_response_bodies().await?;
    let request_body_limits = probe_request_body_limits().await?;
    let response_resource_limits = probe_response_resource_limits().await?;
    let websocket_rate_limits = probe_websocket_rate_limits().await?;
    let secrets = TransportSecrets::generate()?;
    let collector = ExternalCollector::start().await?;
    let upstream = MockUpstream::start(secrets.upstream(), collector.address()).await?;
    let config = ProxyConfig::generate_with_secrets(upstream.address(), secrets)?;
    let proxy = RunningProxy::start(config).await?;

    let process_environment_secret_free = secrets_absent_from_environment(proxy.secrets());
    let process_arguments_secret_free = secrets_absent_from_arguments(proxy.secrets());

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
    let extension_probe_directory = tempfile::Builder::new()
        .prefix("rpackit-disabled-extension-")
        .tempdir()?;
    fs::write(
        extension_probe_directory.path().join("manifest.json"),
        EXTENSION_PROBE_MANIFEST,
    )?;
    let download_probe_directory = tempfile::Builder::new()
        .prefix("rpackit-blocked-download-")
        .tempdir()?;
    let evidence = Arc::new(Mutex::new(CookieEvidence::default()));
    let browser_escape_probe = Arc::new(BrowserEscapeProbe::default());
    let window = build_window(
        &app,
        &proxy,
        collector.address(),
        external_scheme_probe_uris.clone(),
        profile_path.clone(),
        extension_probe_directory.path().to_path_buf(),
        download_probe_directory.path().to_path_buf(),
        Arc::clone(&evidence),
        Arc::clone(&browser_escape_probe),
    )
    .await?;

    let browser_result = timeout(Duration::from_secs(30), upstream.wait_for_browser_report()).await;
    let browser_report_received = browser_result.is_ok();
    let browser_report = browser_result.unwrap_or_default();
    update_evidence(&evidence, |item| {
        item.browser_report_received = browser_report_received;
    });
    for uri in external_scheme_probe_uris {
        let native_events_before = browser_escape_probe.external_scheme_native_event_count();
        native_webview::attempt_external_scheme(&window, Arc::clone(&browser_escape_probe), uri)?;
        if timeout(Duration::from_secs(1), async {
            loop {
                if browser_escape_probe.external_scheme_native_event_count() > native_events_before
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .is_ok()
        {
            break;
        }
    }
    let browser_escape_probe_completed = timeout(Duration::from_secs(5), async {
        loop {
            if browser_escape_probe.runtime_attempts_observed() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .is_ok();
    let registry_overrides_absent_after_creation = webview_registry_overrides_absent()?;
    let devtools_active_port_absent = file_named_absent(&profile_path, "DevToolsActivePort")?;
    let download_directory_empty = directory_is_empty(download_probe_directory.path())?;
    let browser_escape_evidence = browser_escape_probe.snapshot(
        browser_escape_probe_completed,
        true,
        registry_overrides_absent_before_creation,
        registry_overrides_absent_after_creation,
        devtools_active_port_absent,
        download_directory_empty,
    );
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
        &malformed_upstream,
        &malformed_upstream_bodies,
        &request_body_limits,
        &response_resource_limits,
        &websocket_rate_limits,
        &browser_escape_evidence,
        &cookie_evidence,
        &browser_report,
        &upstream_snapshot,
        &collector_snapshot,
        process_environment_secret_free,
        process_arguments_secret_free,
        cleanup_cookie_absent,
        cleanup_browsing_data_queued,
        window_destroyed,
    );
    let report = AcceptanceReport::new(
        tauri::webview_version().ok(),
        resolution,
        listener_overlap,
        malformed_upstream,
        malformed_upstream_bodies,
        request_body_limits,
        response_resource_limits,
        websocket_rate_limits,
        browser_escape_evidence,
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
#[allow(clippy::too_many_arguments)]
async fn build_window(
    app: &AppHandle<Wry>,
    proxy: &RunningProxy,
    collector_address: SocketAddr,
    external_scheme_probe_uris: Vec<Url>,
    profile_path: PathBuf,
    extension_probe_path: PathBuf,
    download_probe_path: PathBuf,
    evidence: Arc<Mutex<CookieEvidence>>,
    browser_escape_probe: Arc<BrowserEscapeProbe>,
) -> Result<WebviewWindow<Wry>, HarnessError> {
    let bootstrap_url = Url::parse(&proxy.address().bootstrap_url())?;
    let root_url = Url::parse(&proxy.address().root_url())?;
    let navigation_escape_url =
        Url::parse(&format!("http://{collector_address}/escape/navigation"))?;
    let popup_escape_url = Url::parse(&format!("http://{collector_address}/escape/popup"))?;
    let download_escape_url = root_url.join("download/escape")?;
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
    let native_browser_escape_probe = Arc::clone(&browser_escape_probe);
    let native_allowed_proxy_origin = root_url.clone();
    let native_navigation_escape_url = navigation_escape_url.clone();
    let native_external_scheme_probe_uris = external_scheme_probe_uris
        .iter()
        .map(|uri| uri.as_str().to_owned())
        .collect();
    let page_bootstrap_queued = Arc::clone(&bootstrap_queued);
    main_thread_app.run_on_main_thread(move || {
        let navigation_host = expected_host.clone();
        let navigation_state = Arc::clone(&state);
        let navigation_escape = navigation_escape_url.clone();
        let navigation_escape_probe = Arc::clone(&browser_escape_probe);
        let external_scheme_navigation_uris = external_scheme_probe_uris.clone();
        let popup_escape = popup_escape_url.clone();
        let popup_escape_probe = Arc::clone(&browser_escape_probe);
        let download_escape = download_escape_url.clone();
        let download_escape_probe = Arc::clone(&browser_escape_probe);
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
            if url == &navigation_escape {
                navigation_escape_probe.record_navigation_block();
                return false;
            }
            if url.as_str() == PAGE_EXTERNAL_SCHEME_PROBE_URI
                || external_scheme_navigation_uris
                    .iter()
                    .any(|candidate| candidate == url)
            {
                return true;
            }
            let proxy_origin = url.scheme() == "http"
                && url.host_str() == Some(navigation_host.as_str())
                && url.port() == Some(expected_port);
            let native_fallback =
                navigation_state.load(Ordering::SeqCst) == 0 && is_bundled_placeholder(url);
            (proxy_origin || native_fallback)
                && url.username().is_empty()
                && url.password().is_none()
        })
        .on_new_window(move |url, _| {
            if url == popup_escape {
                popup_escape_probe.record_popup_deny();
            }
            NewWindowResponse::Deny
        })
        .on_download(move |_, event| {
            if let DownloadEvent::Requested { url, .. } = event
                && url == download_escape
            {
                download_escape_probe.record_download_cancel();
            }
            false
        })
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
    native_webview::install_browser_escape_guards(
        &window,
        Arc::clone(&native_browser_escape_probe),
        native_allowed_proxy_origin,
        native_navigation_escape_url,
        native_external_scheme_probe_uris,
        extension_probe_path,
        download_probe_path,
    )?;
    timeout(Duration::from_secs(5), async {
        loop {
            if native_browser_escape_probe.native_hardening_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| io::Error::other("native browser hardening setup timed out"))?;
    if !native_browser_escape_probe.native_hardening_succeeded() {
        return Err(io::Error::other("native browser hardening setup failed").into());
    }
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

fn webview_registry_overrides_absent() -> io::Result<bool> {
    let executable = std::env::current_exe()?;
    let app_ids = webview_registry_app_ids(&executable);
    let roots = [
        RegKey::predef(HKEY_LOCAL_MACHINE),
        RegKey::predef(HKEY_CURRENT_USER),
    ];
    let views = [KEY_WOW64_64KEY, KEY_WOW64_32KEY];
    for root in roots {
        for view in views {
            if webview_registry_override_present(&app_ids, |subkey, value_name| {
                registry_value_exists(&root, view, subkey, value_name)
            })? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn registered_external_scheme_probe_uris() -> io::Result<Vec<Url>> {
    let classes = RegKey::predef(HKEY_CLASSES_ROOT);
    external_scheme_probe_uris(|scheme| registry_value_exists(&classes, 0, scheme, "URL Protocol"))
}

fn external_scheme_probe_uris(
    mut is_registered: impl FnMut(&str) -> io::Result<bool>,
) -> io::Result<Vec<Url>> {
    let mut uris = Vec::new();
    for (scheme, uri) in EXTERNAL_SCHEME_PROBE_CANDIDATES {
        if is_registered(scheme)? {
            uris.push(
                Url::parse(uri)
                    .map_err(|_| io::Error::other("invalid external-scheme probe URI"))?,
            );
        }
    }
    if uris.is_empty() {
        return Err(io::Error::other(
            "no registered external URI scheme is available for the browser escape probe",
        ));
    }
    Ok(uris)
}

fn webview_registry_app_ids(executable: &Path) -> Vec<String> {
    let mut app_ids = vec![WEBVIEW2_APP_USER_MODEL_ID.to_owned()];
    if let Some(file_name) = executable.file_name().and_then(|name| name.to_str()) {
        push_unique(&mut app_ids, file_name);
    }
    if let Some(file_stem) = executable.file_stem().and_then(|name| name.to_str()) {
        push_unique(&mut app_ids, file_stem);
    }
    push_unique(&mut app_ids, "*");
    app_ids
}

fn push_unique(items: &mut Vec<String>, value: &str) {
    if !items.iter().any(|item| item.eq_ignore_ascii_case(value)) {
        items.push(value.to_owned());
    }
}

fn webview_registry_override_present(
    app_ids: &[String],
    mut value_exists: impl FnMut(&str, &str) -> io::Result<bool>,
) -> io::Result<bool> {
    for subkey in WEBVIEW2_OVERRIDE_POLICY_KEYS {
        for app_id in app_ids {
            if value_exists(subkey, app_id)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn registry_value_exists(
    root: &RegKey,
    view: u32,
    subkey: &str,
    value_name: &str,
) -> io::Result<bool> {
    let key = match root.open_subkey_with_flags(subkey, KEY_READ | view) {
        Ok(key) => key,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    match key.get_raw_value(value_name) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn file_named_absent(root: &Path, file_name: &str) -> io::Result<bool> {
    let mut directories = VecDeque::from([root.to_path_buf()]);
    let mut entries_seen = 0_usize;
    while let Some(directory) = directories.pop_front() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = entry?;
            entries_seen = entries_seen.saturating_add(1);
            if entries_seen > PROFILE_SCAN_ENTRY_LIMIT {
                return Err(io::Error::other(
                    "WebView2 profile scan exceeded its entry limit",
                ));
            }
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.eq_ignore_ascii_case(file_name))
            {
                return Ok(false);
            }
            let file_type = entry.file_type()?;
            if file_type.is_dir() && !file_type.is_symlink() {
                directories.push_back(entry.path());
            }
        }
    }
    Ok(true)
}

fn directory_is_empty(directory: &Path) -> io::Result<bool> {
    fs::read_dir(directory)?
        .next()
        .transpose()
        .map(|entry| entry.is_none())
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
    use std::{io, path::Path, sync::Arc};

    use rpackit_transport::{Secret, TransportSecrets};
    use url::Url;

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
        assert!(super::webview_environment_override_present(|name| {
            name == "WEBVIEW2_CHANNEL_SEARCH_KIND"
        }));
        assert!(super::webview_environment_override_present(|name| {
            name == "WEBVIEW2_RELEASE_CHANNELS"
        }));
    }

    #[test]
    fn registry_override_candidates_cover_app_executable_and_wildcard() {
        let app_ids = super::webview_registry_app_ids(Path::new(
            r"C:\Program Files\rpackit\rpackit-windows-spike.exe",
        ));
        assert!(app_ids.iter().any(|id| id == "dev.rpackit.transport-spike"));
        assert!(app_ids.iter().any(|id| id == "rpackit-windows-spike.exe"));
        assert!(app_ids.iter().any(|id| id == "rpackit-windows-spike"));
        assert!(app_ids.iter().any(|id| id == "*"));

        let detected = super::webview_registry_override_present(&app_ids, |subkey, value_name| {
            Ok(subkey.ends_with("AdditionalBrowserArguments") && value_name == "*")
        });
        assert!(detected.is_ok_and(|present| present));

        let absent = super::webview_registry_override_present(&app_ids, |_, _| Ok(false));
        assert!(absent.is_ok_and(|present| !present));

        let failed = super::webview_registry_override_present(&app_ids, |_, _| {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
        });
        assert_eq!(
            failed.err().map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
    }

    #[test]
    fn external_scheme_probe_uses_only_registered_candidates() {
        let result = super::external_scheme_probe_uris(|scheme| {
            Ok(matches!(scheme, "ms-settings" | "mailto"))
        });
        assert!(result.is_ok());
        let uris = result.unwrap_or_default();
        assert_eq!(
            uris.iter().map(Url::as_str).collect::<Vec<_>>(),
            [
                "ms-settings:display",
                "mailto:rpackit-browser-escape@example.invalid",
            ]
        );

        let absent = super::external_scheme_probe_uris(|_| Ok(false));
        assert!(absent.is_err());
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
