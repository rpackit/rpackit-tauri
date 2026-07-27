//! Native-only secure `WebView2` and per-launch profile ownership.
//!
//! This crate accepts browser launch material only after the authenticated
//! proxy and bundled R runtime are ready. It creates one hidden, hardened
//! `WebView`, performs the one-time native bootstrap, verifies the resulting
//! host-only session cookie, navigates to the application, and owns cookie,
//! browsing-data, window and exact profile cleanup.

#![cfg(windows)]

mod native;
mod policy;
mod profile;

use std::{
    fmt,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use rpackit_transport::{SESSION_COOKIE_NAME, Secret};
use rpackit_windows_lifecycle::BrowserLaunch;
use tauri::{
    AppHandle, WebviewUrl, WebviewWindow, WebviewWindowBuilder, Wry,
    webview::{
        NewWindowResponse, PageLoadEvent,
        cookie::{Cookie, Expiration, SameSite},
    },
};
use thiserror::Error;
use tokio::sync::oneshot;
use url::Url;

use profile::ScopedProfile;

/// Label reserved for the single application `WebView`.
pub const MAIN_WINDOW_LABEL: &str = "main";

const MAX_STARTUP_TIMEOUT: Duration = Duration::from_mins(2);
const MAX_NATIVE_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PROFILE_CLEANUP_TIMEOUT: Duration = Duration::from_mins(1);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Bounded `WebView` startup and cleanup limits.
#[derive(Clone, Copy, Debug)]
pub struct WebviewLimits {
    /// Maximum time from bootstrap navigation to an authenticated application
    /// document finishing.
    pub startup_timeout: Duration,
    /// Maximum time for one native COM dispatch.
    pub native_operation_timeout: Duration,
    /// Maximum time to wait for `WebView` profile handles to close.
    pub profile_cleanup_timeout: Duration,
    /// Poll interval for cookie and profile cleanup.
    pub poll_interval: Duration,
}

impl Default for WebviewLimits {
    fn default() -> Self {
        Self {
            startup_timeout: Duration::from_secs(30),
            native_operation_timeout: Duration::from_secs(5),
            profile_cleanup_timeout: Duration::from_secs(10),
            poll_interval: Duration::from_millis(50),
        }
    }
}

impl WebviewLimits {
    fn validate(self) -> Result<Self, WebviewError> {
        if self.startup_timeout.is_zero()
            || self.startup_timeout > MAX_STARTUP_TIMEOUT
            || self.native_operation_timeout.is_zero()
            || self.native_operation_timeout > MAX_NATIVE_OPERATION_TIMEOUT
            || self.profile_cleanup_timeout.is_zero()
            || self.profile_cleanup_timeout > MAX_PROFILE_CLEANUP_TIMEOUT
            || self.poll_interval.is_zero()
            || self.poll_interval > MAX_POLL_INTERVAL
        {
            return Err(WebviewError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Visible presentation settings with fixed security controls.
#[derive(Clone, Debug)]
pub struct SecureWindowConfig {
    /// Native window title. It is never derived from application content.
    pub title: String,
    /// Initial logical width.
    pub width: f64,
    /// Initial logical height.
    pub height: f64,
    /// Whether to show the window after authenticated root navigation.
    pub show_after_ready: bool,
}

impl Default for SecureWindowConfig {
    fn default() -> Self {
        Self {
            title: "rpackit".to_owned(),
            width: 1024.0,
            height: 768.0,
            show_after_ready: true,
        }
    }
}

impl SecureWindowConfig {
    fn validate(&self) -> Result<(), WebviewError> {
        if self.title.is_empty()
            || self.title.len() > 128
            || self.title.chars().any(char::is_control)
            || !self.width.is_finite()
            || !self.height.is_finite()
            || !(320.0..=7680.0).contains(&self.width)
            || !(240.0..=4320.0).contains(&self.height)
        {
            return Err(WebviewError::InvalidWindowConfig);
        }
        Ok(())
    }
}

/// Proof that runtime, environment and policy gates passed before R starts.
#[derive(Clone)]
pub struct WebviewPreflight {
    application_id: String,
    actual_version: String,
}

impl fmt::Debug for WebviewPreflight {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebviewPreflight")
            .field("application_id", &self.application_id)
            .field("actual_version", &self.actual_version)
            .finish()
    }
}

impl WebviewPreflight {
    /// Verifies forbidden environment and policy overrides are absent and the
    /// installed/configured `WebView2` runtime meets the reviewed minimum.
    ///
    /// Call this before launching bundled R.
    ///
    /// # Errors
    ///
    /// Returns a secret-free identity, policy, registry or runtime error.
    pub fn verify(application_id: impl Into<String>) -> Result<Self, WebviewError> {
        let application_id = application_id.into();
        let actual_version = policy::verify(&application_id)?;
        Ok(Self {
            application_id,
            actual_version,
        })
    }

    /// Returns the exact runtime version observed during preflight.
    #[must_use]
    pub fn actual_version(&self) -> &str {
        &self.actual_version
    }
}

/// Secret-free evidence returned after a complete browser cleanup.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebviewShutdownReport {
    /// Whether the reserved browser-session cookie is absent.
    pub session_cookie_absent: bool,
    /// Whether `WebView2` accepted the browsing-data clear request.
    pub browsing_data_clear_queued: bool,
    /// Whether the application `WebView` was destroyed.
    pub window_destroyed: bool,
    /// Whether the exact per-launch profile directory was removed.
    pub profile_removed: bool,
}

/// One authenticated application `WebView` and its exact per-launch profile.
#[must_use = "the secure WebView owner must be shut down explicitly"]
pub struct SecureWebviewOwner {
    window: Option<WebviewWindow<Wry>>,
    root_url: Url,
    profile: ScopedProfile,
    limits: WebviewLimits,
    runtime_version: String,
}

impl fmt::Debug for SecureWebviewOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecureWebviewOwner")
            .field("window_running", &self.window.is_some())
            .field("root_origin", &origin_text(&self.root_url))
            .field("profile", &self.profile)
            .field("limits", &self.limits)
            .field("runtime_version", &self.runtime_version)
            .finish()
    }
}

impl SecureWebviewOwner {
    /// Creates, hardens, bootstraps and shows one authenticated application
    /// `WebView` after native proxy/R readiness.
    ///
    /// # Errors
    ///
    /// Returns a secret-free preflight, profile, native hardening, bootstrap,
    /// cookie, navigation, timeout or cleanup failure. Every failure after
    /// window creation attempts bounded cookie/window/profile cleanup.
    #[allow(clippy::too_many_lines)]
    pub async fn launch(
        app: &AppHandle<Wry>,
        browser: &BrowserLaunch,
        profile_parent: impl AsRef<Path>,
        preflight: &WebviewPreflight,
        config: SecureWindowConfig,
        limits: WebviewLimits,
    ) -> Result<Self, WebviewError> {
        let limits = limits.validate()?;
        config.validate()?;
        if app.config().identifier.as_str() != preflight.application_id.as_str() {
            return Err(WebviewError::ApplicationIdentityMismatch);
        }
        let profile = ScopedProfile::create(profile_parent.as_ref())?;
        let bootstrap_url = Url::parse(&browser.address().bootstrap_url())
            .map_err(|_| WebviewError::InvalidProxyOrigin)?;
        let root_url = Url::parse(&browser.address().root_url())
            .map_err(|_| WebviewError::InvalidProxyOrigin)?;
        let native_allowed_origin = root_url.clone();
        let page_expected_root = root_url.clone();
        let expected_bootstrap = bootstrap_url.clone();
        let session = browser.session_secret();
        let bootstrap = browser.bootstrap_secret();
        let state = Arc::new(AtomicU8::new(0));
        let (ready_sender, ready_receiver) = oneshot::channel();
        let ready_sender = Arc::new(Mutex::new(Some(ready_sender)));
        let (window_sender, window_receiver) = oneshot::channel();
        let dispatcher = app.clone();
        let builder_app = app.clone();
        let profile_path = profile.path()?.to_path_buf();
        let page_state = Arc::clone(&state);
        let page_sender = Arc::clone(&ready_sender);
        let page_session = Arc::clone(&session);
        let page_root = root_url.clone();
        let page_bootstrap = bootstrap_url.clone();
        let navigation_state = Arc::clone(&state);
        let navigation_root = root_url.clone();
        let show_after_ready = config.show_after_ready;
        dispatcher
            .run_on_main_thread(move || {
                let result = WebviewWindowBuilder::new(
                    &builder_app,
                    MAIN_WINDOW_LABEL,
                    WebviewUrl::App("index.html".into()),
                )
                .title(config.title)
                .inner_size(config.width, config.height)
                .center()
                .visible(false)
                .focused(false)
                .resizable(true)
                .data_directory(profile_path)
                .incognito(true)
                .devtools(false)
                .browser_extensions_enabled(false)
                .general_autofill_enabled(false)
                .disable_drag_drop_handler()
                .zoom_hotkeys_enabled(false)
                .on_navigation(move |url| {
                    let proxy_origin = same_origin(url, &navigation_root);
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
                        let root = page_root.clone();
                        let session = Arc::clone(&page_session);
                        let state = Arc::clone(&page_state);
                        let sender = Arc::clone(&page_sender);
                        std::thread::spawn(move || {
                            let cookie_ready = window
                                .cookies_for_url(root.clone())
                                .is_ok_and(|cookies| session_cookie_is_exact(&cookies, &session));
                            if !cookie_ready {
                                state.store(4, Ordering::SeqCst);
                                signal_startup(&sender, Err(StartupFailure::Cookie));
                                return;
                            }
                            state.store(2, Ordering::SeqCst);
                            if window.navigate(root).is_err() {
                                state.store(4, Ordering::SeqCst);
                                signal_startup(&sender, Err(StartupFailure::Navigation));
                            }
                        });
                    } else if page_state.load(Ordering::SeqCst) == 2
                        && same_origin(payload.url(), &page_expected_root)
                        && payload.url() != &expected_bootstrap
                        && page_state
                            .compare_exchange(2, 3, Ordering::SeqCst, Ordering::SeqCst)
                            .is_ok()
                    {
                        if show_after_ready && window.show().is_err() {
                            page_state.store(4, Ordering::SeqCst);
                            signal_startup(&page_sender, Err(StartupFailure::Show));
                            return;
                        }
                        signal_startup(&page_sender, Ok(()));
                    }
                })
                .build()
                .map_err(|_| ());
                let _ = window_sender.send(result);
            })
            .map_err(|_| WebviewError::WindowDispatch)?;

        let window = window_receiver
            .await
            .map_err(|_| WebviewError::WindowChannel)?
            .map_err(|()| WebviewError::WindowCreation)?;
        let mut owner = Self {
            window: Some(window),
            root_url,
            profile,
            limits,
            runtime_version: preflight.actual_version.clone(),
        };

        let startup = async {
            let window = owner.window.as_ref().ok_or(WebviewError::OwnerNotRunning)?;
            native::install_guards(
                window,
                native_allowed_origin,
                owner.limits.native_operation_timeout,
            )
            .await?;
            native::navigate_with_bootstrap(
                window,
                bootstrap_url,
                bootstrap,
                owner.limits.native_operation_timeout,
            )
            .await?;
            tokio::time::timeout(owner.limits.startup_timeout, ready_receiver)
                .await
                .map_err(|_| WebviewError::StartupTimeout)?
                .map_err(|_| WebviewError::StartupChannel)?
                .map_err(WebviewError::from)
        }
        .await;
        drop(session);
        if let Err(primary) = startup {
            let cleanup = owner.shutdown().await.err();
            return Err(combine_cleanup_error(primary, cleanup));
        }
        Ok(owner)
    }

    /// Returns the preflighted `WebView2` runtime version.
    #[must_use]
    pub fn runtime_version(&self) -> &str {
        &self.runtime_version
    }

    /// Hides the window immediately while bounded native cleanup runs.
    ///
    /// # Errors
    ///
    /// Returns an error after the window was already destroyed.
    pub fn hide(&self) -> Result<(), WebviewError> {
        self.window
            .as_ref()
            .ok_or(WebviewError::OwnerNotRunning)?
            .hide()
            .map_err(|_| WebviewError::WindowHide)
    }

    /// Deletes the reserved cookie, clears browsing data, destroys the `WebView`
    /// and removes the exact per-launch profile.
    ///
    /// # Errors
    ///
    /// Returns a secret-free cleanup error after still attempting every step.
    /// A retained profile can be retried with [`Self::retry_profile_cleanup`].
    pub async fn shutdown(&mut self) -> Result<WebviewShutdownReport, WebviewError> {
        if self.window.is_none() && self.profile.is_removed() {
            return Err(WebviewError::OwnerNotRunning);
        }
        let (session_cookie_absent, browsing_data_clear_queued, window_destroyed) =
            if let Some(window) = self.window.take() {
                let session_cookie_absent =
                    delete_session_cookie(&window, &self.root_url, self.limits.poll_interval)
                        .unwrap_or(false);
                let browsing_data_clear_queued = window.clear_all_browsing_data().is_ok();
                let window_destroyed = window.destroy().is_ok();
                (
                    session_cookie_absent,
                    browsing_data_clear_queued,
                    window_destroyed,
                )
            } else {
                (false, false, false)
            };
        tokio::time::sleep(Duration::from_millis(250)).await;
        let profile_removed = self
            .profile
            .remove_bounded(
                self.limits.profile_cleanup_timeout,
                self.limits.poll_interval,
            )
            .await
            .is_ok();
        let report = WebviewShutdownReport {
            session_cookie_absent,
            browsing_data_clear_queued,
            window_destroyed,
            profile_removed,
        };
        if report.session_cookie_absent
            && report.browsing_data_clear_queued
            && report.window_destroyed
            && report.profile_removed
        {
            Ok(report)
        } else {
            Err(WebviewError::Cleanup)
        }
    }

    /// Retries removal of an exact retained profile after window destruction.
    ///
    /// # Errors
    ///
    /// Returns an error while the window is live, when cleanup already
    /// completed, or when the bounded retry still cannot remove the profile.
    pub async fn retry_profile_cleanup(&mut self) -> Result<(), WebviewError> {
        if self.window.is_some() {
            return Err(WebviewError::OwnerStillRunning);
        }
        if self.profile.is_removed() {
            return Err(WebviewError::OwnerNotRunning);
        }
        self.profile
            .remove_bounded(
                self.limits.profile_cleanup_timeout,
                self.limits.poll_interval,
            )
            .await
    }
}

impl Drop for SecureWebviewOwner {
    fn drop(&mut self) {
        if let Some(window) = self.window.take() {
            let _ = window.hide();
            let _ = window.destroy();
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum StartupFailure {
    Cookie,
    Navigation,
    Show,
}

type StartupSender = Arc<Mutex<Option<oneshot::Sender<Result<(), StartupFailure>>>>>;

impl From<StartupFailure> for WebviewError {
    fn from(value: StartupFailure) -> Self {
        match value {
            StartupFailure::Cookie => Self::CookieVerification,
            StartupFailure::Navigation => Self::RootNavigation,
            StartupFailure::Show => Self::WindowShow,
        }
    }
}

fn signal_startup(sender: &StartupSender, result: Result<(), StartupFailure>) {
    if let Ok(mut sender) = sender.lock()
        && let Some(sender) = sender.take()
    {
        let _ = sender.send(result);
    }
}

fn session_cookie_is_exact(cookies: &[Cookie<'static>], session: &Secret) -> bool {
    let matching: Vec<_> = cookies
        .iter()
        .filter(|cookie| cookie.name() == SESSION_COOKIE_NAME)
        .collect();
    matching.len() == 1
        && matching[0].http_only() == Some(true)
        && matching[0].same_site() == Some(SameSite::Strict)
        && matching[0].path() == Some("/")
        && matching[0].max_age().is_none()
        && matches!(matching[0].expires(), None | Some(Expiration::Session))
        && matching[0].secure() != Some(true)
        && session.matches(matching[0].value().as_bytes())
}

fn delete_session_cookie(
    window: &WebviewWindow<Wry>,
    root_url: &Url,
    poll_interval: Duration,
) -> tauri::Result<bool> {
    let cookies = window.cookies_for_url(root_url.clone())?;
    for cookie in cookies
        .into_iter()
        .filter(|cookie| cookie.name() == SESSION_COOKIE_NAME)
    {
        window.delete_cookie(cookie)?;
    }
    for _ in 0..20 {
        let remaining = window.cookies_for_url(root_url.clone())?;
        if !remaining
            .iter()
            .any(|cookie| cookie.name() == SESSION_COOKIE_NAME)
        {
            return Ok(true);
        }
        std::thread::sleep(poll_interval);
    }
    Ok(false)
}

fn same_origin(url: &Url, expected: &Url) -> bool {
    url.scheme() == expected.scheme()
        && url.host_str() == expected.host_str()
        && url.port() == expected.port()
        && url.username().is_empty()
        && url.password().is_none()
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

fn origin_text(url: &Url) -> String {
    format!(
        "{}://{}:{}",
        url.scheme(),
        url.host_str().unwrap_or("[INVALID]"),
        url.port().unwrap_or_default()
    )
}

fn combine_cleanup_error(primary: WebviewError, cleanup: Option<WebviewError>) -> WebviewError {
    match cleanup {
        Some(cleanup) => WebviewError::CleanupAfterFailure {
            primary: Box::new(primary),
            cleanup: Box::new(cleanup),
        },
        None => primary,
    }
}

/// Secret-free `WebView` policy, startup and cleanup failures.
#[derive(Debug, Error)]
pub enum WebviewError {
    /// A caller supplied invalid or unbounded timing limits.
    #[error("invalid secure WebView limits")]
    InvalidLimits,
    /// Visible window settings were invalid or unbounded.
    #[error("invalid secure window configuration")]
    InvalidWindowConfig,
    /// The configured application identifier was malformed.
    #[error("invalid application identity")]
    InvalidApplicationIdentity,
    /// The current executable identity could not be read.
    #[error("application executable identity was unavailable")]
    ExecutableIdentity,
    /// An untrusted `WebView2` environment override was present.
    #[error("an untrusted WebView2 environment override was present")]
    EnvironmentOverride,
    /// `WebView2` policy registry inspection failed.
    #[error("WebView2 policy inspection failed")]
    RegistryInspection,
    /// An untrusted `WebView2` policy override was present.
    #[error("an untrusted WebView2 policy override was present")]
    RegistryOverride,
    /// No usable `WebView2` runtime was available.
    #[error("WebView2 runtime was unavailable")]
    RuntimeUnavailable,
    /// The observed `WebView2` runtime was below the reviewed minimum.
    #[error("WebView2 runtime did not meet the reviewed minimum")]
    RuntimeUnsupported,
    /// Preflight and the actual Tauri application identifiers differed.
    #[error("WebView preflight did not match the Tauri application")]
    ApplicationIdentityMismatch,
    /// The profile parent did not exist or was inaccessible.
    #[error("WebView profile parent was unavailable")]
    ProfileParentUnavailable,
    /// The profile parent was a link, reparse point or non-directory.
    #[error("WebView profile parent failed its scope check")]
    UnsafeProfileParent,
    /// A random per-launch profile could not be created.
    #[error("WebView profile creation failed")]
    ProfileCreation,
    /// The exact profile path failed its scope check.
    #[error("WebView profile path failed its scope check")]
    UnsafeProfilePath,
    /// A bounded profile cleanup worker terminated unexpectedly.
    #[error("WebView profile cleanup worker terminated unexpectedly")]
    ProfileCleanupWorker,
    /// The exact profile could not be removed within its cleanup bound.
    #[error("WebView profile cleanup timed out")]
    ProfileCleanup,
    /// The proxy origin generated by the native owner was invalid.
    #[error("native proxy origin was invalid")]
    InvalidProxyOrigin,
    /// Window creation could not be dispatched to the UI thread.
    #[error("secure window dispatch failed")]
    WindowDispatch,
    /// The window creation result channel closed.
    #[error("secure window creation channel closed")]
    WindowChannel,
    /// The hidden secure window could not be created.
    #[error("secure window creation failed")]
    WindowCreation,
    /// Native hardening could not be dispatched.
    #[error("native browser hardening dispatch failed")]
    NativeGuardScheduling,
    /// Native hardening did not complete within its bound.
    #[error("native browser hardening timed out")]
    NativeGuardTimeout,
    /// The native hardening completion channel closed.
    #[error("native browser hardening channel closed")]
    NativeGuardChannel,
    /// Native settings or event guards failed closed.
    #[error("native browser hardening failed")]
    NativeGuardFailure,
    /// Native bootstrap navigation could not be dispatched.
    #[error("native bootstrap dispatch failed")]
    BootstrapScheduling,
    /// Native bootstrap did not complete within its dispatch bound.
    #[error("native bootstrap dispatch timed out")]
    BootstrapTimeout,
    /// The native bootstrap completion channel closed.
    #[error("native bootstrap channel closed")]
    BootstrapChannel,
    /// `WebView2` rejected the exact native bootstrap request.
    #[error("native bootstrap navigation failed")]
    BootstrapFailure,
    /// The authenticated application document did not become ready in time.
    #[error("authenticated WebView startup timed out")]
    StartupTimeout,
    /// The startup completion channel closed.
    #[error("authenticated WebView startup channel closed")]
    StartupChannel,
    /// The host-only session cookie did not match the native contract.
    #[error("authenticated WebView cookie verification failed")]
    CookieVerification,
    /// Navigation to the authenticated application root failed.
    #[error("authenticated application navigation failed")]
    RootNavigation,
    /// The authenticated window could not be shown.
    #[error("authenticated application window could not be shown")]
    WindowShow,
    /// The live application window could not be hidden for cleanup.
    #[error("application window could not be hidden")]
    WindowHide,
    /// Cookie, browsing-data, window or profile cleanup was incomplete.
    #[error("secure WebView cleanup was incomplete")]
    Cleanup,
    /// The combined owner no longer retained a window or profile.
    #[error("secure WebView owner was not running")]
    OwnerNotRunning,
    /// Profile retry was requested while the `WebView` remained live.
    #[error("secure WebView owner still retained a live window")]
    OwnerStillRunning,
    /// Cleanup also failed after an earlier `WebView` failure.
    #[error("secure WebView startup failed and cleanup also failed")]
    CleanupAfterFailure {
        /// Original operation failure.
        #[source]
        primary: Box<WebviewError>,
        /// Later cleanup failure.
        cleanup: Box<WebviewError>,
    },
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rpackit_transport::{SESSION_COOKIE_NAME, Secret};
    use tauri::webview::cookie::{Cookie, SameSite};
    use url::Url;

    use super::{SecureWindowConfig, session_cookie_is_exact};

    #[test]
    fn window_configuration_rejects_hidden_control_text() {
        let mut config = SecureWindowConfig::default();
        assert!(config.validate().is_ok());
        config.title = "unsafe\nwindow".to_owned();
        assert!(config.validate().is_err());
    }

    #[test]
    fn cookie_verification_requires_one_exact_value_and_flags() {
        let session = Arc::new(Secret::from_bytes([9; 32]));
        let value = session.with_exposed(str::to_owned);
        let cookie = Cookie::build((SESSION_COOKIE_NAME, value))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Strict)
            .build();
        assert!(session_cookie_is_exact(
            std::slice::from_ref(&cookie),
            &session
        ));

        let wrong_path = Cookie::build((SESSION_COOKIE_NAME, cookie.value().to_owned()))
            .path("/nested")
            .http_only(true)
            .same_site(SameSite::Strict)
            .build();
        assert!(!session_cookie_is_exact(&[wrong_path], &session));
        assert!(!session_cookie_is_exact(
            &[cookie.clone(), cookie],
            &session
        ));
    }

    #[test]
    fn origin_matching_is_exact() -> Result<(), url::ParseError> {
        let root = Url::parse("http://rpackit-abcd.localhost:48123/")?;
        assert!(super::same_origin(
            &Url::parse("http://rpackit-abcd.localhost:48123/path")?,
            &root
        ));
        assert!(!super::same_origin(
            &Url::parse("http://rpackit-abcd.localhost:48124/")?,
            &root
        ));
        Ok(())
    }
}
