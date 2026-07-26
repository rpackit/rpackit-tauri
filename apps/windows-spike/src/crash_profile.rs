//! Cross-process forced-termination probe for `WebView2` profile persistence.

use std::{
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::{self, Write},
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use rpackit_transport::{ProxyConfig, RunningProxy, SESSION_COOKIE_NAME, Secret};
use tauri::{
    AppHandle, WebviewUrl, WebviewWindow, WebviewWindowBuilder, Wry,
    webview::{
        NewWindowResponse, PageLoadEvent,
        cookie::{Cookie, Expiration, SameSite},
    },
};
use tokio::time::{sleep, timeout};
use url::Url;

use crate::{HarnessError, native_webview, report::CrashProfileEvidence};

pub(crate) const PRODUCER_ARGUMENT: &str = "--crash-profile-producer";

const PROFILE_ARGUMENT: &str = "--profile";
const READY_ARGUMENT: &str = "--ready";
const PROBE_DIRECTORY_PREFIX: &str = "rpackit-crash-profile-";
const PROFILE_DIRECTORY_NAME: &str = "profile";
const READY_FILE_NAME: &str = "producer-ready.txt";
const PENDING_FILE_NAME: &str = "producer-ready.pending";
const GRACEFUL_EXIT_FILE_NAME: &str = "graceful-exit.marker";
const GRACEFUL_EXIT_CONTENT: &[u8] = b"graceful cleanup reached\n";
const PRODUCER_COOKIE_SETTLE_DURATION: Duration = Duration::from_secs(2);
const PRODUCER_READY_TIMEOUT: Duration = Duration::from_secs(30);
const PROFILE_RELEASE_INITIAL_DELAY: Duration = Duration::from_millis(500);
const PROFILE_RECREATION_RETRY_DELAY: Duration = Duration::from_millis(250);
const PROFILE_RECREATION_ATTEMPTS: usize = 20;
const READY_MARKER_MAX_BYTES: u64 = 128;

#[derive(Debug)]
pub(crate) struct CrashProducerOptions {
    profile_path: PathBuf,
    ready_path: PathBuf,
}

impl CrashProducerOptions {
    pub(crate) fn parse(mut arguments: impl Iterator<Item = OsString>) -> Result<Self, ()> {
        if arguments.next().as_deref() != Some(OsStr::new(PROFILE_ARGUMENT)) {
            return Err(());
        }
        let profile_path = arguments.next().map(PathBuf::from).ok_or(())?;
        if arguments.next().as_deref() != Some(OsStr::new(READY_ARGUMENT)) {
            return Err(());
        }
        let ready_path = arguments.next().map(PathBuf::from).ok_or(())?;
        if arguments.next().is_some() {
            return Err(());
        }
        Ok(Self {
            profile_path,
            ready_path,
        })
    }
}

struct CrashExitSentinel {
    path: PathBuf,
}

impl Drop for CrashExitSentinel {
    fn drop(&mut self) {
        if let Ok(mut file) = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.path)
        {
            let _ = file.write_all(GRACEFUL_EXIT_CONTENT);
            let _ = file.sync_all();
        }
    }
}

struct ChildGuard {
    child: Child,
    reaped: bool,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    fn force_terminate(&mut self) -> TerminationOutcome {
        let requested = self.child.kill().is_ok();
        let status = self.child.wait();
        self.reaped = status.is_ok();
        TerminationOutcome {
            forced: requested && status.as_ref().is_ok_and(|value| !value.success()),
            reaped: self.reaped,
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.reaped = true;
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct TerminationOutcome {
    forced: bool,
    reaped: bool,
}

#[derive(Clone, Copy, Debug, Default)]
struct RecreationOutcome {
    completed: bool,
    cookie_absent: bool,
    webview_destroyed: bool,
}

pub(crate) async fn run_producer(
    app: AppHandle<Wry>,
    options: CrashProducerOptions,
) -> Result<i32, HarnessError> {
    if !probe_paths_are_strictly_scoped(&options.profile_path, &options.ready_path) {
        return Err(io::Error::other("crash-profile producer paths are not safely scoped").into());
    }
    crate::reject_webview_environment_overrides()?;
    if !crate::webview_registry_overrides_absent()? {
        return Err(io::Error::other("WebView2 registry override is not allowed").into());
    }

    let root = options
        .profile_path
        .parent()
        .ok_or_else(|| io::Error::other("crash-profile probe root is missing"))?;
    let exit_sentinel = CrashExitSentinel {
        path: root.join(GRACEFUL_EXIT_FILE_NAME),
    };
    let proxy = RunningProxy::start(ProxyConfig::generate(SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        9,
    )))?)
    .await?;
    let (window, cookie_verified) =
        build_producer_window(&app, &proxy, options.profile_path).await?;
    let cookie_verified = timeout(PRODUCER_READY_TIMEOUT, cookie_verified)
        .await
        .map_err(|_| io::Error::other("crash-profile producer cookie readback timed out"))?
        .map_err(|_| io::Error::other("crash-profile producer cookie channel closed"))?;
    if !cookie_verified {
        return Err(io::Error::other("crash-profile producer cookie verification failed").into());
    }

    sleep(PRODUCER_COOKIE_SETTLE_DURATION).await;
    write_ready_marker(&options.ready_path, proxy.address().hostname())?;
    std::future::pending::<()>().await;

    drop(window);
    drop(proxy);
    drop(exit_sentinel);
    Ok(0)
}

pub(crate) async fn probe(app: &AppHandle<Wry>) -> CrashProfileEvidence {
    let Ok(directory) = tempfile::Builder::new()
        .prefix(PROBE_DIRECTORY_PREFIX)
        .tempdir()
    else {
        return CrashProfileEvidence::default();
    };
    let mut evidence = probe_in_directory(app, directory.path()).await;
    sleep(PROFILE_RELEASE_INITIAL_DELAY).await;
    evidence.crash_profile_directory_removed = directory.close().is_ok();
    evidence.probe_completed = true;
    evidence
}

async fn probe_in_directory(app: &AppHandle<Wry>, root: &Path) -> CrashProfileEvidence {
    let mut evidence = CrashProfileEvidence::default();
    let profile_path = root.join(PROFILE_DIRECTORY_NAME);
    let ready_path = root.join(READY_FILE_NAME);
    let graceful_exit_path = root.join(GRACEFUL_EXIT_FILE_NAME);
    if fs::create_dir(&profile_path).is_err() {
        return evidence;
    }
    evidence.producer_paths_scoped_to_system_temp =
        probe_paths_are_strictly_scoped(&profile_path, &ready_path);
    if !evidence.producer_paths_scoped_to_system_temp {
        return evidence;
    }

    let arguments = [
        OsString::from(PRODUCER_ARGUMENT),
        OsString::from(PROFILE_ARGUMENT),
        profile_path.as_os_str().to_owned(),
        OsString::from(READY_ARGUMENT),
        ready_path.as_os_str().to_owned(),
    ];
    evidence.producer_received_no_secret_input = arguments
        .iter()
        .all(|argument| !argument.to_string_lossy().contains("rp-"));
    let Ok(executable) = std::env::current_exe() else {
        return evidence;
    };
    let Ok(child) = Command::new(executable)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return evidence;
    };
    evidence.producer_spawned = true;
    let mut child = ChildGuard::new(child);

    let marker = wait_for_ready_marker(&mut child.child, &ready_path).await;
    let hostname = marker
        .as_deref()
        .and_then(parse_ready_marker)
        .map(str::to_owned);
    evidence.control_marker_secret_free = marker
        .as_deref()
        .is_some_and(|bytes| !bytes.windows(3).any(|window| window == b"rp-"));
    evidence.producer_cookie_verified_before_crash = hostname.is_some();
    evidence.producer_profile_populated_before_crash = profile_has_entries(&profile_path);

    let termination = child.force_terminate();
    evidence.producer_forcibly_terminated = termination.forced;
    evidence.producer_reaped_after_termination = termination.reaped;
    evidence.graceful_cleanup_sentinel_absent =
        graceful_exit_path.try_exists().is_ok_and(|exists| !exists);

    if let Some(hostname) = hostname
        && termination.reaped
    {
        sleep(PROFILE_RELEASE_INITIAL_DELAY).await;
        let outcome = inspect_crashed_profile(app, profile_path, &hostname).await;
        evidence.crashed_profile_recreation_completed = outcome.completed;
        evidence.crashed_profile_cookie_absent = outcome.cookie_absent;
        evidence.recreation_webview_destroyed = outcome.webview_destroyed;
    }
    evidence
}

async fn wait_for_ready_marker(child: &mut Child, path: &Path) -> Option<Vec<u8>> {
    timeout(PRODUCER_READY_TIMEOUT, async {
        loop {
            if let Ok(metadata) = fs::metadata(path)
                && metadata.is_file()
                && metadata.len() <= READY_MARKER_MAX_BYTES
            {
                break fs::read(path).ok();
            }
            if child.try_wait().ok().flatten().is_some() {
                break None;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .ok()
    .flatten()
}

async fn inspect_crashed_profile(
    app: &AppHandle<Wry>,
    profile_path: PathBuf,
    hostname: &str,
) -> RecreationOutcome {
    let Ok(root_url) = Url::parse(&format!("http://{hostname}/")) else {
        return RecreationOutcome::default();
    };
    for attempt in 0..PROFILE_RECREATION_ATTEMPTS {
        let label = format!("crash-profile-recreation-{attempt}");
        if let Ok(window) = create_recreation_window(app, profile_path.clone(), label).await {
            let cookies = window.cookies_for_url(root_url.clone());
            let destroyed = window.destroy().is_ok();
            sleep(PROFILE_RECREATION_RETRY_DELAY).await;
            if let Ok(cookies) = cookies {
                return RecreationOutcome {
                    completed: true,
                    cookie_absent: cookies
                        .iter()
                        .all(|cookie| cookie.name() != SESSION_COOKIE_NAME),
                    webview_destroyed: destroyed,
                };
            }
        }
        sleep(PROFILE_RECREATION_RETRY_DELAY).await;
    }
    RecreationOutcome::default()
}

async fn create_recreation_window(
    app: &AppHandle<Wry>,
    profile_path: PathBuf,
    label: String,
) -> Result<WebviewWindow<Wry>, HarnessError> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let dispatcher = app.clone();
    let builder_app = app.clone();
    dispatcher.run_on_main_thread(move || {
        let result =
            WebviewWindowBuilder::new(&builder_app, label, WebviewUrl::App("index.html".into()))
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
                .on_navigation(crate::is_bundled_placeholder)
                .on_new_window(|_, _| NewWindowResponse::Deny)
                .on_download(|_, _| false)
                .build()
                .map_err(|_| ());
        let _ = sender.send(result);
    })?;
    receiver
        .await
        .map_err(|_| io::Error::other("crashed-profile recreation channel closed"))?
        .map_err(|()| io::Error::other("crashed-profile recreation WebView failed").into())
}

async fn build_producer_window(
    app: &AppHandle<Wry>,
    proxy: &RunningProxy,
    profile_path: PathBuf,
) -> Result<(WebviewWindow<Wry>, tokio::sync::oneshot::Receiver<bool>), HarnessError> {
    let bootstrap_url = Url::parse(&proxy.address().bootstrap_url())?;
    let root_url = Url::parse(&proxy.address().root_url())?;
    let expected_host = proxy.address().hostname().to_owned();
    let expected_port = proxy.address().port();
    let session = proxy.secrets().session();
    let bootstrap = proxy.secrets().bootstrap();
    let bootstrap_queued = Arc::new(AtomicBool::new(false));
    let (cookie_sender, cookie_receiver) = tokio::sync::oneshot::channel();
    let cookie_sender = Arc::new(Mutex::new(Some(cookie_sender)));
    let callback_state = Arc::new(AtomicBool::new(false));
    let (window_sender, window_receiver) = tokio::sync::oneshot::channel();
    let dispatcher = app.clone();
    let builder_app = app.clone();
    let native_bootstrap_url = bootstrap_url.clone();
    let native_bootstrap_queued = Arc::clone(&bootstrap_queued);
    dispatcher.run_on_main_thread(move || {
        let navigation_host = expected_host.clone();
        let page_bootstrap = bootstrap_url.clone();
        let page_root = root_url.clone();
        let page_session = session;
        let page_sender = Arc::clone(&cookie_sender);
        let page_state = Arc::clone(&callback_state);
        let result = WebviewWindowBuilder::new(
            &builder_app,
            "crash-profile-producer",
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
        .on_navigation(move |url| {
            let proxy_origin = url.scheme() == "http"
                && url.host_str() == Some(navigation_host.as_str())
                && url.port() == Some(expected_port);
            let bundled = crate::is_bundled_placeholder(url);
            (proxy_origin || bundled) && url.username().is_empty() && url.password().is_none()
        })
        .on_new_window(|_, _| NewWindowResponse::Deny)
        .on_download(|_, _| false)
        .on_page_load(move |window, payload| {
            if payload.event() == PageLoadEvent::Finished
                && payload.url() == &page_bootstrap
                && page_state
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                let window = window.clone();
                let root_url = page_root.clone();
                let session = Arc::clone(&page_session);
                let sender = Arc::clone(&page_sender);
                std::thread::spawn(move || {
                    let verified = window
                        .cookies_for_url(root_url)
                        .is_ok_and(|cookies| session_cookie_contract_holds(&cookies, &session));
                    if let Ok(mut sender) = sender.lock()
                        && let Some(sender) = sender.take()
                    {
                        let _ = sender.send(verified);
                    }
                });
            }
        })
        .build()
        .map_err(|_| ());
        let _ = window_sender.send(result);
    })?;
    let window = window_receiver
        .await
        .map_err(|_| io::Error::other("crash-profile producer window channel closed"))?
        .map_err(|()| io::Error::other("crash-profile producer WebView creation failed"))?;
    native_webview::navigate_with_bootstrap_header(
        &window,
        native_bootstrap_url,
        bootstrap,
        native_bootstrap_queued,
    )?;
    Ok((window, cookie_receiver))
}

fn session_cookie_contract_holds(cookies: &[Cookie<'static>], session: &Secret) -> bool {
    let mut matching = cookies
        .iter()
        .filter(|cookie| cookie.name() == SESSION_COOKIE_NAME);
    let Some(cookie) = matching.next() else {
        return false;
    };
    matching.next().is_none()
        && session.matches(cookie.value().as_bytes())
        && cookie.http_only() == Some(true)
        && cookie.same_site() == Some(SameSite::Strict)
        && cookie.path() == Some("/")
        && cookie.max_age().is_none()
        && matches!(cookie.expires(), None | Some(Expiration::Session))
        && cookie.secure() != Some(true)
}

fn write_ready_marker(path: &Path, hostname: &str) -> io::Result<()> {
    if !valid_generated_hostname(hostname) {
        return Err(io::Error::other(
            "crash-profile producer hostname is invalid",
        ));
    }
    let root = path
        .parent()
        .ok_or_else(|| io::Error::other("crash-profile probe root is missing"))?;
    let pending = root.join(PENDING_FILE_NAME);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
    file.write_all(hostname.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    fs::rename(pending, path)
}

fn parse_ready_marker(bytes: &[u8]) -> Option<&str> {
    if bytes.windows(3).any(|window| window == b"rp-") {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let hostname = text.strip_suffix('\n')?;
    if valid_generated_hostname(hostname) {
        Some(hostname)
    } else {
        None
    }
}

fn valid_generated_hostname(hostname: &str) -> bool {
    let Some(nonce) = hostname
        .strip_prefix("rpackit-")
        .and_then(|value| value.strip_suffix(".localhost"))
    else {
        return false;
    };
    nonce.len() == 32
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn probe_paths_are_strictly_scoped(profile_path: &Path, ready_path: &Path) -> bool {
    if profile_path.file_name() != Some(OsStr::new(PROFILE_DIRECTORY_NAME))
        || ready_path.file_name() != Some(OsStr::new(READY_FILE_NAME))
    {
        return false;
    }
    let Some(root) = profile_path.parent() else {
        return false;
    };
    if ready_path.parent() != Some(root)
        || !root
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.starts_with(PROBE_DIRECTORY_PREFIX))
    {
        return false;
    }
    let Ok(canonical_root) = fs::canonicalize(root) else {
        return false;
    };
    let Ok(canonical_profile) = fs::canonicalize(profile_path) else {
        return false;
    };
    let Ok(canonical_temp) = fs::canonicalize(std::env::temp_dir()) else {
        return false;
    };
    canonical_root.parent() == Some(canonical_temp.as_path())
        && canonical_profile.parent() == Some(canonical_root.as_path())
        && ready_path.try_exists().is_ok_and(|exists| !exists)
        && root
            .join(PENDING_FILE_NAME)
            .try_exists()
            .is_ok_and(|exists| !exists)
        && root
            .join(GRACEFUL_EXIT_FILE_NAME)
            .try_exists()
            .is_ok_and(|exists| !exists)
}

fn profile_has_entries(path: &Path) -> bool {
    fs::read_dir(path)
        .ok()
        .and_then(|mut entries| entries.next())
        .is_some_and(|entry| entry.is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn producer_paths_and_ready_marker_are_strictly_scoped_and_secret_free() {
        let directory = tempfile::Builder::new()
            .prefix(PROBE_DIRECTORY_PREFIX)
            .tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let profile = directory.path().join(PROFILE_DIRECTORY_NAME);
        assert!(fs::create_dir(&profile).is_ok());
        let ready = directory.path().join(READY_FILE_NAME);
        assert!(probe_paths_are_strictly_scoped(&profile, &ready));
        assert!(!probe_paths_are_strictly_scoped(directory.path(), &ready));

        let marker = b"rpackit-0123456789abcdef0123456789abcdef.localhost\n";
        assert_eq!(
            parse_ready_marker(marker),
            Some("rpackit-0123456789abcdef0123456789abcdef.localhost")
        );
        assert!(parse_ready_marker(b"rp-secret\n").is_none());
        assert!(parse_ready_marker(b"rpackit-short.localhost\n").is_none());
    }
}
