//! Thin Tauri event-loop owner around the native proxy/R and `WebView` owners.

use std::{
    ffi::{OsStr, OsString},
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use rpackit_transport::TransportLimits;
use rpackit_windows_lifecycle::{
    LifecycleLimits, NativeAppOwner, NativeAppShutdownReport, ShutdownKind,
};
use rpackit_windows_webview::{
    MAIN_WINDOW_LABEL, SecureWebviewOwner, SecureWindowConfig, WebviewLimits, WebviewPreflight,
    WebviewShutdownReport,
};
use serde::Serialize;
use tauri::{RunEvent, WindowEvent, Wry};
use tokio::sync::mpsc;

const APPLICATION_ID: &str = "dev.rpackit.shell";
const HEALTH_POLL_INTERVAL: Duration = Duration::from_millis(250);
const MAX_EVIDENCE_BYTES: usize = 64 * 1024;

#[derive(Clone)]
struct ShellOptions {
    bundle: PathBuf,
    session_parent: PathBuf,
    profile_parent: PathBuf,
    evidence: Option<PathBuf>,
    close_after_ready: bool,
}

#[derive(Clone, Copy)]
enum ShellSignal {
    Graceful,
    Forced,
}

struct ShellSuccess {
    webview2_version: String,
    native: NativeAppShutdownReport,
    webview: WebviewShutdownReport,
    forced: bool,
}

#[derive(Clone, Copy)]
enum ShellFailure {
    Preflight,
    NativeStartup,
    BrowserMaterial,
    WebviewStartup,
    RuntimeHealth,
    Shutdown,
}

impl ShellFailure {
    const fn stage(self) -> &'static str {
        match self {
            Self::Preflight => "webview_preflight",
            Self::NativeStartup => "native_startup",
            Self::BrowserMaterial => "browser_material",
            Self::WebviewStartup => "webview_startup",
            Self::RuntimeHealth => "runtime_health",
            Self::Shutdown => "shutdown",
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize)]
struct ShellEvidence {
    schema_version: u32,
    success: bool,
    failure_stage: Option<&'static str>,
    webview2_version: Option<String>,
    forced_shutdown: bool,
    graceful_runtime_shutdown: bool,
    proxy_stopped: bool,
    job_empty: bool,
    private_session_removed: bool,
    session_cookie_absent: bool,
    browsing_data_clear_queued: bool,
    window_destroyed: bool,
    profile_removed: bool,
}

impl ShellEvidence {
    fn success(value: ShellSuccess) -> Self {
        Self {
            schema_version: 1,
            success: true,
            failure_stage: None,
            webview2_version: Some(value.webview2_version),
            forced_shutdown: value.forced,
            graceful_runtime_shutdown: value.native.runtime.kind == ShutdownKind::Graceful,
            proxy_stopped: value.native.proxy_stopped,
            job_empty: value.native.runtime.job_empty,
            private_session_removed: value.native.runtime.session_removed,
            session_cookie_absent: value.webview.session_cookie_absent,
            browsing_data_clear_queued: value.webview.browsing_data_clear_queued,
            window_destroyed: value.webview.window_destroyed,
            profile_removed: value.webview.profile_removed,
        }
    }

    const fn failure(failure: ShellFailure) -> Self {
        Self {
            schema_version: 1,
            success: false,
            failure_stage: Some(failure.stage()),
            webview2_version: None,
            forced_shutdown: false,
            graceful_runtime_shutdown: false,
            proxy_stopped: false,
            job_empty: false,
            private_session_removed: false,
            session_cookie_absent: false,
            browsing_data_clear_queued: false,
            window_destroyed: false,
            profile_removed: false,
        }
    }
}

pub(crate) fn main() {
    let options = match parse_options(std::env::args_os().skip(1)) {
        Ok(options) => options,
        Err(()) => {
            eprintln!(
                "usage: rpackit-windows-shell --bundle <dir> \
                 --session-parent <dir> --profile-parent <dir> \
                 [--evidence <file> --close-after-ready]"
            );
            std::process::exit(2);
        }
    };
    let evidence_path = options.evidence.clone();
    let (signal_sender, signal_receiver) = mpsc::unbounded_channel();
    let cleanup_started = Arc::new(AtomicBool::new(false));
    let allow_exit = Arc::new(AtomicBool::new(false));
    let window_signal = signal_sender.clone();
    let window_cleanup_started = Arc::clone(&cleanup_started);
    let window_allow_exit = Arc::clone(&allow_exit);
    let setup_allow_exit = Arc::clone(&allow_exit);
    let app = tauri::Builder::default()
        .on_window_event(move |window, event| {
            if window.label() != MAIN_WINDOW_LABEL || window_allow_exit.load(Ordering::SeqCst) {
                return;
            }
            match event {
                WindowEvent::CloseRequested { api, .. } => {
                    api.prevent_close();
                    request_cleanup(
                        &window_signal,
                        &window_cleanup_started,
                        ShellSignal::Graceful,
                    );
                }
                WindowEvent::Destroyed => {
                    request_cleanup(&window_signal, &window_cleanup_started, ShellSignal::Forced)
                }
                _ => {}
            }
        })
        .setup(move |app| {
            let handle = app.handle().clone();
            let exit_handle = handle.clone();
            tauri::async_runtime::spawn(async move {
                let outcome = run_shell(handle, options, signal_receiver).await;
                let (mut exit_code, evidence) = match outcome {
                    Ok(success) => (0, ShellEvidence::success(success)),
                    Err(failure) => (1, ShellEvidence::failure(failure)),
                };
                if let Some(path) = evidence_path
                    && write_evidence(&path, &evidence).is_err()
                {
                    exit_code = 1;
                }
                setup_allow_exit.store(true, Ordering::SeqCst);
                exit_handle.exit(exit_code);
            });
            Ok(())
        })
        .build(tauri::generate_context!());
    let app = match app {
        Ok(app) => app,
        Err(_) => {
            std::process::exit(1);
        }
    };
    let run_signal = signal_sender;
    let run_cleanup_started = cleanup_started;
    let run_allow_exit = allow_exit;
    let exit_code = app.run_return(move |_, event| {
        if let RunEvent::ExitRequested { api, .. } = event
            && !run_allow_exit.load(Ordering::SeqCst)
        {
            api.prevent_exit();
            request_cleanup(&run_signal, &run_cleanup_started, ShellSignal::Graceful);
        }
    });
    std::process::exit(exit_code);
}

async fn run_shell(
    app: tauri::AppHandle<Wry>,
    options: ShellOptions,
    mut signal_receiver: mpsc::UnboundedReceiver<ShellSignal>,
) -> Result<ShellSuccess, ShellFailure> {
    let preflight =
        WebviewPreflight::verify(APPLICATION_ID).map_err(|_| ShellFailure::Preflight)?;
    let mut native = NativeAppOwner::launch(
        &options.bundle,
        &options.session_parent,
        LifecycleLimits::default(),
        TransportLimits::default(),
    )
    .await
    .map_err(|_| ShellFailure::NativeStartup)?;
    let browser = native
        .browser_launch()
        .map_err(|_| ShellFailure::BrowserMaterial)?;
    let webview = SecureWebviewOwner::launch(
        &app,
        &browser,
        &options.profile_parent,
        &preflight,
        SecureWindowConfig::default(),
        WebviewLimits::default(),
    )
    .await;
    drop(browser);
    let mut webview = match webview {
        Ok(webview) => webview,
        Err(_) => {
            let _ = native.force_shutdown().await;
            return Err(ShellFailure::WebviewStartup);
        }
    };
    let webview2_version = webview.runtime_version().to_owned();
    if options.close_after_ready {
        return shutdown_owners(native, webview, webview2_version, false).await;
    }

    loop {
        tokio::select! {
            signal = signal_receiver.recv() => {
                let forced = matches!(signal, Some(ShellSignal::Forced) | None);
                return shutdown_owners(native, webview, webview2_version, forced).await;
            }
            () = tokio::time::sleep(HEALTH_POLL_INTERVAL) => {
                if native.poll_health().await.is_err() {
                    let _ = webview.hide();
                    let _ = webview.shutdown().await;
                    return Err(ShellFailure::RuntimeHealth);
                }
            }
        }
    }
}

async fn shutdown_owners(
    mut native: NativeAppOwner,
    mut webview: SecureWebviewOwner,
    webview2_version: String,
    forced: bool,
) -> Result<ShellSuccess, ShellFailure> {
    let _ = webview.hide();
    let native_report = if forced {
        native.force_shutdown().await
    } else {
        native.shutdown().await
    };
    let webview_report = webview.shutdown().await;
    match (native_report, webview_report) {
        (Ok(native), Ok(webview)) => Ok(ShellSuccess {
            webview2_version,
            native,
            webview,
            forced,
        }),
        _ => Err(ShellFailure::Shutdown),
    }
}

fn request_cleanup(
    sender: &mpsc::UnboundedSender<ShellSignal>,
    cleanup_started: &AtomicBool,
    signal: ShellSignal,
) {
    if cleanup_started
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        let _ = sender.send(signal);
    }
}

fn parse_options(mut arguments: impl Iterator<Item = OsString>) -> Result<ShellOptions, ()> {
    let mut bundle = None;
    let mut session_parent = None;
    let mut profile_parent = None;
    let mut evidence = None;
    let mut close_after_ready = false;
    while let Some(argument) = arguments.next() {
        if argument == "--bundle" {
            set_path_option(&mut bundle, arguments.next())?;
        } else if argument == "--session-parent" {
            set_path_option(&mut session_parent, arguments.next())?;
        } else if argument == "--profile-parent" {
            set_path_option(&mut profile_parent, arguments.next())?;
        } else if argument == "--evidence" {
            set_path_option(&mut evidence, arguments.next())?;
        } else if argument == "--close-after-ready" {
            if close_after_ready {
                return Err(());
            }
            close_after_ready = true;
        } else {
            return Err(());
        }
    }
    let options = ShellOptions {
        bundle: bundle.ok_or(())?,
        session_parent: session_parent.ok_or(())?,
        profile_parent: profile_parent.ok_or(())?,
        evidence,
        close_after_ready,
    };
    validate_options(&options)?;
    Ok(options)
}

fn set_path_option(slot: &mut Option<PathBuf>, value: Option<OsString>) -> Result<(), ()> {
    if slot.is_some() {
        return Err(());
    }
    *slot = value.map(PathBuf::from);
    if slot.is_none() {
        return Err(());
    }
    Ok(())
}

fn validate_options(options: &ShellOptions) -> Result<(), ()> {
    if !options.bundle.is_dir()
        || !options.session_parent.is_dir()
        || !options.profile_parent.is_dir()
        || options.close_after_ready != options.evidence.is_some()
    {
        return Err(());
    }
    if let Some(evidence) = &options.evidence {
        if evidence.try_exists().map_err(|_| ())?
            || !evidence.parent().is_some_and(Path::is_dir)
            || evidence.file_name() == Some(OsStr::new(""))
        {
            return Err(());
        }
    }
    Ok(())
}

fn write_evidence(path: &Path, evidence: &ShellEvidence) -> Result<(), ()> {
    let bytes = serde_json::to_vec_pretty(evidence).map_err(|_| ())?;
    if bytes.len() > MAX_EVIDENCE_BYTES {
        return Err(());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| ())?;
    file.write_all(&bytes).map_err(|_| ())?;
    file.write_all(b"\n").map_err(|_| ())?;
    file.sync_all().map_err(|_| ())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::parse_options;

    #[test]
    fn options_require_exact_acceptance_pairing() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let bundle = root.path().join("bundle");
        let sessions = root.path().join("sessions");
        let profiles = root.path().join("profiles");
        std::fs::create_dir(&bundle)?;
        std::fs::create_dir(&sessions)?;
        std::fs::create_dir(&profiles)?;
        let arguments = vec![
            OsString::from("--bundle"),
            bundle.into_os_string(),
            OsString::from("--session-parent"),
            sessions.into_os_string(),
            OsString::from("--profile-parent"),
            profiles.into_os_string(),
        ]
        .into_iter();
        assert!(parse_options(arguments).is_ok());
        Ok(())
    }
}
