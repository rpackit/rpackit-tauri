//! Fail-closed ownership of one bundled rpackit R lifecycle on Windows.
//!
//! This layer composes non-executing bundle validation, a private token/control
//! session, an explicit sanitized child environment, suspended Job assignment,
//! bounded protocol-2 decoding, create-time-aware runtime capture, exact
//! listener ownership, authenticated readiness, graceful control-file stop,
//! forced Job termination, and explicit cleanup.

#![cfg(windows)]
#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{
    Arc,
    mpsc::{self, Receiver, RecvTimeoutError, Sender},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rpackit_launcher_protocol::{
    ErrorPhase, EventDecoder, LauncherEvent, LifecycleState, LifecycleTracker, ProtocolError,
};
use rpackit_resource_bundle::{BundleError, ValidatedBundle};
use rpackit_transport::{Secret, TransportSecrets};
use rpackit_windows_launcher::{
    JobMemberProcess, JobProcess, LaunchCommand, LaunchEnvironment, LaunchError, PrivateSession,
    ProcessIdentity, launch,
};
use thiserror::Error;
use zeroize::Zeroizing;

const FORCED_EXIT_CODE: u32 = 0x5250_4B46;
const STATUS_LINE_MAX_BYTES: usize = 512;
const MAX_LIFECYCLE_DURATION: Duration = Duration::from_mins(10);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(1);

const AMBIENT_R_VARIABLES: [&str; 14] = [
    "R_ARCH",
    "R_DOC_DIR",
    "R_ENVIRON",
    "R_ENVIRON_USER",
    "R_HOME",
    "R_INCLUDE_DIR",
    "R_LIBS",
    "R_LIBS_SITE",
    "R_LIBS_USER",
    "R_PROFILE",
    "R_PROFILE_USER",
    "R_SHARE_DIR",
    "RPACKIT_LAUNCH_PROTOCOL",
    "RPACKIT_SESSION_TOKEN",
];

/// Bounded timing policy for one runtime lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleLimits {
    /// Maximum time from process creation through authenticated readiness.
    pub startup_timeout: Duration,
    /// Maximum subset of startup time spent waiting for listener ownership.
    pub listener_timeout: Duration,
    /// Read/write timeout for one direct authenticated readiness attempt.
    pub readiness_io_timeout: Duration,
    /// Maximum graceful period after creating the control file.
    pub graceful_timeout: Duration,
    /// Maximum time to verify an intentionally terminated Job becomes empty.
    pub termination_timeout: Duration,
    /// Poll interval for process, protocol, listener, and readiness state.
    pub poll_interval: Duration,
}

impl Default for LifecycleLimits {
    fn default() -> Self {
        Self {
            startup_timeout: Duration::from_secs(30),
            listener_timeout: Duration::from_secs(3),
            readiness_io_timeout: Duration::from_secs(1),
            graceful_timeout: Duration::from_secs(5),
            termination_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(25),
        }
    }
}

impl LifecycleLimits {
    fn validate(&self) -> Result<(), LifecycleError> {
        let bounded = [
            self.startup_timeout,
            self.listener_timeout,
            self.readiness_io_timeout,
            self.graceful_timeout,
            self.termination_timeout,
        ]
        .into_iter()
        .all(|duration| !duration.is_zero() && duration <= MAX_LIFECYCLE_DURATION);
        if !bounded
            || self.poll_interval.is_zero()
            || self.poll_interval > MAX_POLL_INTERVAL
            || self.listener_timeout > self.startup_timeout
        {
            return Err(LifecycleError::InvalidLimits);
        }
        Ok(())
    }
}

/// How a completed lifecycle stopped its process tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownKind {
    /// The launcher observed the control file and completed protocol 2.
    Graceful,
    /// The owner intentionally terminated the complete Job.
    Forced,
}

/// Secret-free evidence returned after successful cleanup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShutdownReport {
    /// Graceful protocol completion or forced Job fallback.
    pub kind: ShutdownKind,
    /// Wrapper exit status when Windows returned it.
    pub wrapper_exit_code: Option<u32>,
    /// Captured runtime exit status when Windows returned it.
    pub runtime_exit_code: Option<u32>,
    /// Number of non-protocol stdout lines discarded without retaining text.
    pub ignored_stdout_lines: u64,
    /// Number of stderr bytes discarded without retaining text.
    pub discarded_stderr_bytes: u64,
    /// Whether Job accounting reached zero active processes.
    pub job_empty: bool,
    /// Whether the exact private launch directory was removed.
    pub session_removed: bool,
}

/// A real bundled R process that passed every startup gate.
#[must_use = "the runtime owner must be polled and shut down explicitly"]
pub struct RuntimeOwner {
    bundle: ValidatedBundle,
    upstream_port: u16,
    upstream_secret: Option<Arc<Secret>>,
    limits: LifecycleLimits,
    session: Option<PrivateSession>,
    process: Option<JobProcess>,
    runtime: Option<JobMemberProcess>,
    monitor: Receiver<MonitorMessage>,
    stdout_thread: Option<JoinHandle<()>>,
    stderr_thread: Option<JoinHandle<u64>>,
    monitor_state: LifecycleState,
    ignored_stdout_lines: u64,
    discarded_stderr_bytes: u64,
    stdout_ended: bool,
    owner_state: OwnerState,
}

impl fmt::Debug for RuntimeOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeOwner")
            .field("bundle", &self.bundle.bundle())
            .field("upstream_port", &self.upstream_port)
            .field("upstream_secret", &"[REDACTED]")
            .field("monitor_state", &self.monitor_state)
            .field("owner_state", &self.owner_state)
            .finish_non_exhaustive()
    }
}

impl RuntimeOwner {
    /// Validates and starts one bundled R lifecycle.
    ///
    /// The caller must already own the matching transport secrets and must
    /// select a currently unused IPv4-loopback upstream port. Only the upstream
    /// secret is copied to the protected one-time token file; it never enters
    /// arguments, environment variables, monitor messages, or errors.
    ///
    /// This function returns only after a matching `listening` event, token
    /// consumption, exact Job-member/listener ownership, and an authenticated
    /// direct HTTP readiness response have all succeeded.
    ///
    /// # Errors
    ///
    /// Returns a secret-free error for invalid configuration, bundle or launch
    /// failure, protocol failure, ownership mismatch, readiness timeout, or
    /// cleanup failure. Every post-spawn failure attempts bounded Job
    /// termination before returning.
    #[allow(clippy::too_many_lines)]
    pub fn launch(
        bundle: impl AsRef<Path>,
        session_parent: impl AsRef<Path>,
        upstream_port: u16,
        secrets: &TransportSecrets,
        limits: LifecycleLimits,
    ) -> Result<Self, LifecycleError> {
        limits.validate()?;
        if upstream_port == 0 {
            return Err(LifecycleError::InvalidUpstreamPort);
        }

        // This must remain the first filesystem/content operation: no session
        // or process exists until the complete resource contract passes.
        let bundle = ValidatedBundle::load(bundle)?;
        let session = PrivateSession::create(session_parent)?;
        let upstream_secret = secrets.upstream();

        if let Err(error) = upstream_secret.with_exposed(|value| session.write_token_file(value)) {
            return Err(cleanup_prelaunch_error(error.into(), &session));
        }

        let environment = match bundled_r_environment(&bundle) {
            Ok(environment) => environment,
            Err(error) => return Err(cleanup_prelaunch_error(error, &session)),
        };
        let command = bundled_r_command(
            &bundle,
            upstream_port,
            session.token_path(),
            session.control_path(),
            environment,
        );
        let mut process = match launch(&command) {
            Ok(process) => process,
            Err(error) => return Err(cleanup_prelaunch_error(error.into(), &session)),
        };
        let Some(stdout) = process.take_stdout() else {
            let primary = LifecycleError::MissingLifecyclePipe("stdout");
            return Err(cleanup_spawned_error(
                primary,
                process,
                &session,
                None,
                None,
                limits.termination_timeout,
            ));
        };
        let Some(stderr) = process.take_stderr() else {
            let primary = LifecycleError::MissingLifecyclePipe("stderr");
            return Err(cleanup_spawned_error(
                primary,
                process,
                &session,
                None,
                None,
                limits.termination_timeout,
            ));
        };

        let (sender, monitor) = mpsc::channel();
        let stderr_sender = sender.clone();
        let stderr_thread = match thread::Builder::new()
            .name("rpackit-stderr-drain".to_owned())
            .spawn(move || drain_stderr(stderr, &stderr_sender))
        {
            Ok(handle) => handle,
            Err(source) => {
                let primary = LifecycleError::ThreadSpawn {
                    thread: "stderr",
                    source,
                };
                return Err(cleanup_spawned_error(
                    primary,
                    process,
                    &session,
                    None,
                    None,
                    limits.termination_timeout,
                ));
            }
        };
        let stdout_thread = match thread::Builder::new()
            .name("rpackit-protocol-monitor".to_owned())
            .spawn(move || monitor_stdout(stdout, upstream_port, &sender))
        {
            Ok(handle) => handle,
            Err(source) => {
                let primary = LifecycleError::ThreadSpawn {
                    thread: "stdout",
                    source,
                };
                return Err(cleanup_spawned_error(
                    primary,
                    process,
                    &session,
                    None,
                    Some(stderr_thread),
                    limits.termination_timeout,
                ));
            }
        };

        let mut owner = Self {
            bundle,
            upstream_port,
            upstream_secret: Some(upstream_secret),
            limits,
            session: Some(session),
            process: Some(process),
            runtime: None,
            monitor,
            stdout_thread: Some(stdout_thread),
            stderr_thread: Some(stderr_thread),
            monitor_state: LifecycleState::AwaitingStart,
            ignored_stdout_lines: 0,
            discarded_stderr_bytes: 0,
            stdout_ended: false,
            owner_state: OwnerState::Starting,
        };

        if let Err(primary) = owner.wait_until_ready() {
            let cleanup = owner.abort_and_cleanup();
            return Err(combine_cleanup_error(primary, cleanup.err()));
        }
        Ok(owner)
    }

    /// Returns the validated bundle used by this owner.
    #[must_use]
    pub const fn bundle(&self) -> &ValidatedBundle {
        &self.bundle
    }

    /// Returns the selected fixed IPv4-loopback upstream port.
    #[must_use]
    pub const fn upstream_port(&self) -> u16 {
        self.upstream_port
    }

    /// Returns the exact create-time-aware runtime identity.
    #[must_use]
    pub fn runtime_identity(&self) -> Option<ProcessIdentity> {
        self.runtime.as_ref().map(JobMemberProcess::identity)
    }

    /// Returns the private session directory retained for retryable cleanup.
    #[must_use]
    pub fn session_directory(&self) -> Option<&Path> {
        self.session.as_ref().map(PrivateSession::directory)
    }

    /// Polls protocol, wrapper, and runtime health without blocking.
    ///
    /// # Errors
    ///
    /// Returns an error if either exact process exits, a terminal or malformed
    /// launcher event arrives, or the lifecycle stdout pipe closes before an
    /// explicit shutdown begins.
    pub fn poll_health(&mut self) -> Result<(), LifecycleError> {
        if self.owner_state != OwnerState::Ready {
            return Err(LifecycleError::OwnerNotRunning);
        }
        self.drain_monitor(true)?;
        if self.stdout_ended {
            return Err(LifecycleError::ProtocolStreamEnded);
        }
        if self.process_ref()?.wait(Duration::ZERO)?.is_some() {
            return Err(LifecycleError::WrapperExitedUnexpectedly);
        }
        if self.runtime_ref()?.wait(Duration::ZERO)?.is_some() {
            return Err(LifecycleError::RuntimeExitedUnexpectedly);
        }
        if self.monitor_state != LifecycleState::Listening {
            return Err(LifecycleError::UnexpectedLifecycleState(self.monitor_state));
        }
        Ok(())
    }

    /// Requests graceful control-file shutdown and uses bounded Job
    /// termination as fallback.
    ///
    /// A cleanup error leaves the private session path retained by this value
    /// so the caller can inspect it and call [`Self::retry_private_cleanup`].
    ///
    /// # Errors
    ///
    /// Returns an error when signaling, Job termination/accounting, monitor
    /// joining, or exact non-recursive session cleanup fails.
    pub fn shutdown(&mut self) -> Result<ShutdownReport, LifecycleError> {
        if self.owner_state == OwnerState::Cleaned {
            return Err(LifecycleError::OwnerAlreadyCleaned);
        }
        if self.owner_state != OwnerState::Stopping {
            self.owner_state = OwnerState::Stopping;
            if let Err(primary) = self.session_ref()?.create_control_file() {
                let cleanup = self.force_and_cleanup();
                return Err(combine_cleanup_error(primary.into(), cleanup.err()));
            }
        }

        let deadline = checked_deadline(self.limits.graceful_timeout)?;
        loop {
            if let Err(primary) = self.drain_monitor(true) {
                let cleanup = self.force_and_cleanup();
                return Err(combine_cleanup_error(primary, cleanup.err()));
            }
            if self.graceful_completion_observed()? {
                return self.finish_cleanup(ShutdownKind::Graceful, true);
            }
            if Instant::now() >= deadline {
                return self.force_and_cleanup();
            }
            thread::sleep(self.remaining_poll(deadline));
        }
    }

    /// Immediately terminates the owned Job and performs bounded cleanup.
    ///
    /// # Errors
    ///
    /// Returns an error if Job termination/accounting, monitor joining, or
    /// exact non-recursive session cleanup fails.
    pub fn force_shutdown(&mut self) -> Result<ShutdownReport, LifecycleError> {
        if self.owner_state == OwnerState::Cleaned {
            return Err(LifecycleError::OwnerAlreadyCleaned);
        }
        self.owner_state = OwnerState::Stopping;
        self.force_and_cleanup()
    }

    /// Retries only the exact private-session cleanup after the process tree
    /// and monitor threads have already stopped.
    ///
    /// This is intended for a prior non-recursive cleanup failure caused by an
    /// unexpected audit entry or a transient filesystem error.
    ///
    /// # Errors
    ///
    /// Returns an error while a process is still owned, after cleanup already
    /// completed, or when DACL verification/removal still fails.
    pub fn retry_private_cleanup(&mut self) -> Result<(), LifecycleError> {
        if self.owner_state == OwnerState::Cleaned {
            return Err(LifecycleError::OwnerAlreadyCleaned);
        }
        if self.process.is_some() || self.stdout_thread.is_some() || self.stderr_thread.is_some() {
            return Err(LifecycleError::OwnerStillHasLiveResources);
        }
        let mut first_error = None;
        let mut removed = false;
        if let Some(session) = self.session.as_ref() {
            if let Err(error) = session.verify_security() {
                store_first_error(&mut first_error, error.into());
            }
            match session.cleanup() {
                Ok(()) => removed = true,
                Err(error) => store_first_error(&mut first_error, error.into()),
            }
        } else {
            removed = true;
        }
        if removed {
            self.session.take();
            self.runtime.take();
            self.upstream_secret.take();
            self.owner_state = OwnerState::Cleaned;
        }
        first_error.map_or(Ok(()), Err)
    }

    fn wait_until_ready(&mut self) -> Result<(), LifecycleError> {
        let startup_deadline = checked_deadline(self.limits.startup_timeout)?;
        loop {
            self.ensure_wrapper_alive_before_ready()?;
            let now = Instant::now();
            if now >= startup_deadline {
                return Err(LifecycleError::ReadinessTimeout);
            }
            let timeout = self.remaining_poll(startup_deadline);
            match self.monitor.recv_timeout(timeout) {
                Ok(message) => {
                    let event = self.apply_monitor(message, true)?;
                    match event {
                        Some(MonitorEvent::Starting(_)) => {
                            self.verify_token_consumed()?;
                        }
                        Some(MonitorEvent::Listening(pid)) => {
                            self.verify_token_consumed()?;
                            let runtime = self.process_ref()?.capture_job_member(pid)?;
                            self.runtime = Some(runtime);
                            self.wait_for_listener(startup_deadline)?;
                            self.wait_for_authenticated_readiness(startup_deadline)?;
                            self.owner_state = OwnerState::Ready;
                            return Ok(());
                        }
                        Some(MonitorEvent::Stopping | MonitorEvent::Stopped(_)) => {
                            return Err(LifecycleError::StoppedBeforeReadiness);
                        }
                        Some(MonitorEvent::LauncherFailed(phase)) => {
                            return Err(LifecycleError::LauncherReportedFailure(phase));
                        }
                        None => {}
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(LifecycleError::MonitorDisconnected);
                }
            }
        }
    }

    fn wait_for_listener(&mut self, startup_deadline: Instant) -> Result<(), LifecycleError> {
        let listener_deadline =
            checked_deadline(self.limits.listener_timeout)?.min(startup_deadline);
        loop {
            self.ensure_processes_alive_before_ready()?;
            self.drain_monitor(true)?;
            match self
                .process_ref()?
                .verify_ipv4_listener(self.runtime_ref()?, self.upstream_port)
            {
                Ok(_) => return Ok(()),
                Err(LaunchError::ExpectedListenerNotFound)
                    if Instant::now() < listener_deadline =>
                {
                    thread::sleep(self.remaining_poll(listener_deadline));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn wait_for_authenticated_readiness(
        &mut self,
        startup_deadline: Instant,
    ) -> Result<(), LifecycleError> {
        loop {
            self.ensure_processes_alive_before_ready()?;
            self.drain_monitor(true)?;
            let remaining = startup_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(LifecycleError::ReadinessTimeout);
            }
            if authenticated_http_ready(
                self.upstream_port,
                self.upstream_secret
                    .as_deref()
                    .ok_or(LifecycleError::OwnerNotRunning)?,
                self.limits.readiness_io_timeout.min(remaining),
            )? {
                return Ok(());
            }
            if Instant::now() >= startup_deadline {
                return Err(LifecycleError::ReadinessTimeout);
            }
            thread::sleep(self.remaining_poll(startup_deadline));
        }
    }

    fn verify_token_consumed(&self) -> Result<(), LifecycleError> {
        match self.session_ref()?.token_path().try_exists() {
            Ok(false) => Ok(()),
            Ok(true) => Err(LifecycleError::TokenNotConsumed),
            Err(source) => Err(LifecycleError::Io {
                operation: "inspect one-time token path",
                source,
            }),
        }
    }

    fn ensure_wrapper_alive_before_ready(&self) -> Result<(), LifecycleError> {
        if self.process_ref()?.wait(Duration::ZERO)?.is_some() {
            return Err(LifecycleError::WrapperExitedBeforeReadiness);
        }
        Ok(())
    }

    fn ensure_processes_alive_before_ready(&self) -> Result<(), LifecycleError> {
        self.ensure_wrapper_alive_before_ready()?;
        if self.runtime_ref()?.wait(Duration::ZERO)?.is_some() {
            return Err(LifecycleError::RuntimeExitedBeforeReadiness);
        }
        Ok(())
    }

    fn graceful_completion_observed(&self) -> Result<bool, LifecycleError> {
        if self.monitor_state != LifecycleState::Stopped {
            return Ok(false);
        }
        let process = self.process_ref()?;
        let wrapper_stopped = process.wait(Duration::ZERO)?.is_some();
        let runtime_stopped = self.runtime_ref()?.wait(Duration::ZERO)?.is_some();
        Ok(wrapper_stopped && runtime_stopped && process.active_process_count()? == 0)
    }

    fn force_and_cleanup(&mut self) -> Result<ShutdownReport, LifecycleError> {
        let mut first_error = None;
        match self.process.as_ref() {
            Some(process) => {
                if let Err(error) = process.terminate(FORCED_EXIT_CODE) {
                    store_first_error(&mut first_error, error.into());
                }
                match process.wait_for_empty(self.limits.termination_timeout) {
                    Ok(true) => {}
                    Ok(false) => {
                        store_first_error(&mut first_error, LifecycleError::JobDidNotBecomeEmpty);
                    }
                    Err(error) => store_first_error(&mut first_error, error.into()),
                }
            }
            None => store_first_error(&mut first_error, LifecycleError::OwnerNotRunning),
        }
        let cleanup = self.finish_cleanup(ShutdownKind::Forced, false);
        match (first_error, cleanup) {
            (None, result) => result,
            (Some(primary), Ok(_)) => Err(primary),
            (Some(primary), Err(cleanup)) => Err(combine_cleanup_error(primary, Some(cleanup))),
        }
    }

    fn finish_cleanup(
        &mut self,
        kind: ShutdownKind,
        strict_protocol: bool,
    ) -> Result<ShutdownReport, LifecycleError> {
        let mut first_error = None;
        let mut wrapper_exit_code = None;
        let mut runtime_exit_code = None;
        let mut job_empty = false;
        if let Some(process) = self.process.as_ref() {
            match process.wait_for_empty(self.limits.termination_timeout) {
                Ok(empty) => {
                    job_empty = empty;
                    if !empty {
                        store_first_error(&mut first_error, LifecycleError::JobDidNotBecomeEmpty);
                    }
                }
                Err(error) => store_first_error(&mut first_error, error.into()),
            }
            match process.wait(self.limits.termination_timeout) {
                Ok(code) => wrapper_exit_code = code,
                Err(error) => store_first_error(&mut first_error, error.into()),
            }
        } else {
            store_first_error(&mut first_error, LifecycleError::OwnerNotRunning);
        }
        match self.runtime.as_ref() {
            Some(runtime) => match runtime.wait(self.limits.termination_timeout) {
                Ok(code) => runtime_exit_code = code,
                Err(error) => store_first_error(&mut first_error, error.into()),
            },
            None => store_first_error(&mut first_error, LifecycleError::RuntimeIdentityUnavailable),
        }
        if wrapper_exit_code.is_none() || runtime_exit_code.is_none() {
            store_first_error(&mut first_error, LifecycleError::ProcessDidNotExit);
        }
        if !job_empty || wrapper_exit_code.is_none() || runtime_exit_code.is_none() {
            return Err(first_error.unwrap_or(LifecycleError::ProcessDidNotExit));
        }

        // Dropping the last process-owner value closes the Job handle. This is
        // still performed after a query error so kill-on-close remains the
        // final fail-safe and the pipe threads can observe EOF.
        self.process.take();
        if let Err(error) = self.join_monitors(strict_protocol) {
            store_first_error(&mut first_error, error);
        }
        let mut session_removed = false;
        if let Some(session) = self.session.as_ref() {
            if let Err(error) = session.verify_security() {
                store_first_error(&mut first_error, error.into());
            }
            match session.cleanup() {
                Ok(()) => session_removed = true,
                Err(error) => store_first_error(&mut first_error, error.into()),
            }
        } else {
            session_removed = true;
        }
        if session_removed {
            self.session.take();
        }
        self.runtime.take();
        self.upstream_secret.take();
        if session_removed {
            self.owner_state = OwnerState::Cleaned;
        }

        if let Some(error) = first_error {
            return Err(error);
        }

        Ok(ShutdownReport {
            kind,
            wrapper_exit_code,
            runtime_exit_code,
            ignored_stdout_lines: self.ignored_stdout_lines,
            discarded_stderr_bytes: self.discarded_stderr_bytes,
            job_empty,
            session_removed,
        })
    }

    fn abort_and_cleanup(&mut self) -> Result<(), LifecycleError> {
        self.owner_state = OwnerState::Stopping;
        let mut first_error = None;
        let mut job_empty = self.process.is_none();
        if let Some(process) = self.process.as_ref() {
            if let Err(error) = process.terminate(FORCED_EXIT_CODE) {
                store_first_error(&mut first_error, error.into());
            }
            match process.wait_for_empty(self.limits.termination_timeout) {
                Ok(true) => job_empty = true,
                Ok(false) => {
                    store_first_error(&mut first_error, LifecycleError::JobDidNotBecomeEmpty);
                }
                Err(error) => store_first_error(&mut first_error, error.into()),
            }
        }
        if !job_empty {
            return Err(first_error.unwrap_or(LifecycleError::JobDidNotBecomeEmpty));
        }
        self.process.take();
        if let Err(error) = self.join_monitors(false) {
            store_first_error(&mut first_error, error);
        }
        let mut session_removed = false;
        if let Some(session) = self.session.as_ref() {
            if let Err(error) = session.verify_security() {
                store_first_error(&mut first_error, error.into());
            }
            match session.cleanup() {
                Ok(()) => session_removed = true,
                Err(error) => store_first_error(&mut first_error, error.into()),
            }
        } else {
            session_removed = true;
        }
        if session_removed {
            self.session.take();
        }
        self.runtime.take();
        self.upstream_secret.take();
        if session_removed {
            self.owner_state = OwnerState::Cleaned;
        }
        first_error.map_or(Ok(()), Err)
    }

    fn join_monitors(&mut self, strict_protocol: bool) -> Result<(), LifecycleError> {
        let mut first_error = None;
        if let Some(handle) = self.stdout_thread.take()
            && handle.join().is_err()
        {
            store_first_error(
                &mut first_error,
                LifecycleError::MonitorThreadPanicked("stdout"),
            );
        }
        if let Some(handle) = self.stderr_thread.take() {
            match handle.join() {
                Ok(bytes) => self.discarded_stderr_bytes = bytes,
                Err(_) => store_first_error(
                    &mut first_error,
                    LifecycleError::MonitorThreadPanicked("stderr"),
                ),
            }
        }
        if let Err(error) = self.drain_monitor(strict_protocol) {
            store_first_error(&mut first_error, error);
        }
        first_error.map_or(Ok(()), Err)
    }

    fn drain_monitor(&mut self, strict: bool) -> Result<(), LifecycleError> {
        loop {
            match self.monitor.try_recv() {
                Ok(message) => {
                    let event = self.apply_monitor(message, strict)?;
                    if strict {
                        match event {
                            Some(MonitorEvent::LauncherFailed(phase)) => {
                                return Err(LifecycleError::LauncherReportedFailure(phase));
                            }
                            Some(MonitorEvent::Stopping | MonitorEvent::Stopped(_))
                                if self.owner_state != OwnerState::Stopping =>
                            {
                                return Err(LifecycleError::StoppedUnexpectedly);
                            }
                            _ => {}
                        }
                    }
                }
                Err(mpsc::TryRecvError::Disconnected)
                    if strict && self.owner_state != OwnerState::Stopping =>
                {
                    return Err(LifecycleError::MonitorDisconnected);
                }
                Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => return Ok(()),
            }
        }
    }

    fn apply_monitor(
        &mut self,
        message: MonitorMessage,
        strict: bool,
    ) -> Result<Option<MonitorEvent>, LifecycleError> {
        match message {
            MonitorMessage::Event { state, event } => {
                self.monitor_state = state;
                Ok(Some(event))
            }
            MonitorMessage::ProtocolFailure(error) if strict => Err(error.into()),
            MonitorMessage::StdoutReadFailure if strict => {
                Err(LifecycleError::ProtocolStreamReadFailed)
            }
            MonitorMessage::StdoutEnded {
                state,
                ignored_lines,
            } => {
                self.monitor_state = state;
                self.ignored_stdout_lines = ignored_lines;
                self.stdout_ended = true;
                if strict && self.owner_state != OwnerState::Stopping {
                    Err(LifecycleError::ProtocolStreamEnded)
                } else {
                    Ok(None)
                }
            }
            MonitorMessage::StderrReadFailure if strict => {
                Err(LifecycleError::StderrStreamReadFailed)
            }
            MonitorMessage::ProtocolFailure(_)
            | MonitorMessage::StdoutReadFailure
            | MonitorMessage::StderrReadFailure => Ok(None),
        }
    }

    fn process_ref(&self) -> Result<&JobProcess, LifecycleError> {
        self.process.as_ref().ok_or(LifecycleError::OwnerNotRunning)
    }

    fn runtime_ref(&self) -> Result<&JobMemberProcess, LifecycleError> {
        self.runtime
            .as_ref()
            .ok_or(LifecycleError::RuntimeIdentityUnavailable)
    }

    fn session_ref(&self) -> Result<&PrivateSession, LifecycleError> {
        self.session
            .as_ref()
            .ok_or(LifecycleError::PrivateSessionUnavailable)
    }

    fn remaining_poll(&self, deadline: Instant) -> Duration {
        deadline
            .saturating_duration_since(Instant::now())
            .min(self.limits.poll_interval)
    }
}

impl Drop for RuntimeOwner {
    fn drop(&mut self) {
        if self.owner_state != OwnerState::Cleaned {
            let _ = self.abort_and_cleanup();
        }
    }
}

/// Reserves and releases one ephemeral IPv4-loopback port for the R launcher.
///
/// The reservation is released before R binds. Exact owner-PID listener
/// verification detects any takeover before authenticated readiness.
///
/// # Errors
///
/// Returns an error if Windows cannot bind or inspect the temporary listener.
pub fn select_upstream_port() -> Result<u16, LifecycleError> {
    let listener =
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).map_err(|source| {
            LifecycleError::Io {
                operation: "reserve upstream loopback port",
                source,
            }
        })?;
    let address = listener.local_addr().map_err(|source| LifecycleError::Io {
        operation: "inspect reserved upstream port",
        source,
    })?;
    let port = address.port();
    drop(listener);
    if port == 0 {
        return Err(LifecycleError::InvalidUpstreamPort);
    }
    Ok(port)
}

fn bundled_r_environment(bundle: &ValidatedBundle) -> Result<LaunchEnvironment, LifecycleError> {
    let mut environment = LaunchEnvironment::from_current()?;
    for name in AMBIENT_R_VARIABLES {
        let _ = environment.remove(name)?;
    }

    let rscript_directory = bundle
        .rscript()
        .parent()
        .ok_or(LifecycleError::InvalidRuntimeTopology)?;
    let runtime_home = rscript_directory
        .parent()
        .ok_or(LifecycleError::InvalidRuntimeTopology)?;
    environment.set("R_HOME", runtime_home.as_os_str())?;
    environment.set("R_LIBS", bundle.library().as_os_str())?;
    environment.set("R_LIBS_SITE", bundle.library().as_os_str())?;
    environment.set("R_LIBS_USER", bundle.library().as_os_str())?;
    environment.set("RPACKIT_LAUNCH_PROTOCOL", "2")?;

    let mut path = OsString::from(rscript_directory.as_os_str());
    if let Some(ambient_path) = std::env::var_os("PATH")
        && !ambient_path.is_empty()
    {
        path.push(OsStr::new(";"));
        path.push(ambient_path);
    }
    environment.set("PATH", path)?;
    Ok(environment)
}

fn bundled_r_command(
    bundle: &ValidatedBundle,
    port: u16,
    token_path: &Path,
    control_path: &Path,
    environment: LaunchEnvironment,
) -> LaunchCommand {
    LaunchCommand::new(bundle.rscript(), bundle.resources())
        .args([
            OsString::from("--vanilla"),
            bundle.launcher().as_os_str().to_owned(),
            OsString::from("--app"),
            bundle.app().as_os_str().to_owned(),
            OsString::from("--port"),
            OsString::from(port.to_string()),
            OsString::from("--token-file"),
            token_path.as_os_str().to_owned(),
            OsString::from("--control"),
            control_path.as_os_str().to_owned(),
        ])
        .environment(environment)
}

fn authenticated_http_ready(
    port: u16,
    secret: &Secret,
    timeout: Duration,
) -> Result<bool, LifecycleError> {
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let Ok(mut stream) = TcpStream::connect_timeout(&address, timeout) else {
        return Ok(false);
    };
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|source| LifecycleError::Io {
            operation: "set readiness read timeout",
            source,
        })?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|source| LifecycleError::Io {
            operation: "set readiness write timeout",
            source,
        })?;

    let mut request = Zeroizing::new(Vec::with_capacity(256));
    request.extend_from_slice(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:");
    request.extend_from_slice(port.to_string().as_bytes());
    request.extend_from_slice(b"\r\nShiny-Shared-Secret: ");
    secret.with_exposed(|value| request.extend_from_slice(value.as_bytes()));
    request.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
    if stream.write_all(&request).is_err() || stream.flush().is_err() {
        return Ok(false);
    }

    let mut status_line = Vec::with_capacity(64);
    let mut byte = [0_u8; 1];
    while status_line.len() < STATUS_LINE_MAX_BYTES {
        match stream.read(&mut byte) {
            Ok(0) | Err(_) => return Ok(false),
            Ok(_) => {
                status_line.push(byte[0]);
                if status_line.ends_with(b"\r\n") {
                    return Ok(success_status_line(&status_line[..status_line.len() - 2]));
                }
            }
        }
    }
    Ok(false)
}

fn success_status_line(line: &[u8]) -> bool {
    let Some(rest) = line
        .strip_prefix(b"HTTP/1.0 ")
        .or_else(|| line.strip_prefix(b"HTTP/1.1 "))
    else {
        return false;
    };
    if rest.len() < 3 || !rest[..3].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let status = u16::from(rest[0] - b'0') * 100
        + u16::from(rest[1] - b'0') * 10
        + u16::from(rest[2] - b'0');
    (200..400).contains(&status) && rest.get(3).is_none_or(u8::is_ascii_whitespace)
}

fn monitor_stdout(mut stdout: impl Read, expected_port: u16, sender: &Sender<MonitorMessage>) {
    let mut decoder = EventDecoder::with_default_limit();
    let mut tracker = match LifecycleTracker::new(expected_port, true) {
        Ok(tracker) => tracker,
        Err(error) => {
            let _ = sender.send(MonitorMessage::ProtocolFailure(error));
            return;
        }
    };
    let mut buffer = [0_u8; 4096];
    loop {
        let count = match stdout.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(_) => {
                let _ = sender.send(MonitorMessage::StdoutReadFailure);
                return;
            }
        };
        let events = match decoder.push(&buffer[..count]) {
            Ok(events) => events,
            Err(error) => {
                let _ = sender.send(MonitorMessage::ProtocolFailure(error));
                return;
            }
        };
        for event in events {
            let state = match tracker.observe(&event) {
                Ok(state) => state,
                Err(error) => {
                    let _ = sender.send(MonitorMessage::ProtocolFailure(error));
                    return;
                }
            };
            let event = match event {
                LauncherEvent::Starting(event) => MonitorEvent::Starting(event.pid),
                LauncherEvent::Listening(event) => MonitorEvent::Listening(event.pid),
                LauncherEvent::Stopping(_) => MonitorEvent::Stopping,
                LauncherEvent::Stopped(event) => MonitorEvent::Stopped(event.pid),
                LauncherEvent::Error(event) => MonitorEvent::LauncherFailed(event.phase),
            };
            if sender.send(MonitorMessage::Event { state, event }).is_err() {
                return;
            }
        }
    }
    if let Err(error) = decoder.finish() {
        let _ = sender.send(MonitorMessage::ProtocolFailure(error));
        return;
    }
    let _ = sender.send(MonitorMessage::StdoutEnded {
        state: tracker.state(),
        ignored_lines: decoder.ignored_lines(),
    });
}

fn drain_stderr(mut stderr: impl Read, sender: &Sender<MonitorMessage>) -> u64 {
    let mut total = 0_u64;
    let mut buffer = [0_u8; 4096];
    loop {
        match stderr.read(&mut buffer) {
            Ok(0) => return total,
            Ok(count) => {
                total = total.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
            }
            Err(_) => {
                let _ = sender.send(MonitorMessage::StderrReadFailure);
                return total;
            }
        }
    }
}

fn cleanup_prelaunch_error(primary: LifecycleError, session: &PrivateSession) -> LifecycleError {
    match session.cleanup() {
        Ok(()) => primary,
        Err(cleanup) => combine_cleanup_error(primary, Some(cleanup.into())),
    }
}

fn cleanup_spawned_error(
    primary: LifecycleError,
    process: JobProcess,
    session: &PrivateSession,
    stdout_thread: Option<JoinHandle<()>>,
    stderr_thread: Option<JoinHandle<u64>>,
    timeout: Duration,
) -> LifecycleError {
    let mut cleanup_error = None;
    let mut job_empty = false;
    if let Err(error) = process.terminate(FORCED_EXIT_CODE) {
        store_first_error(&mut cleanup_error, error.into());
    }
    match process.wait_for_empty(timeout) {
        Ok(true) => job_empty = true,
        Ok(false) => store_first_error(&mut cleanup_error, LifecycleError::JobDidNotBecomeEmpty),
        Err(error) => store_first_error(&mut cleanup_error, error.into()),
    }
    drop(process);
    if !job_empty {
        return combine_cleanup_error(
            primary,
            Some(cleanup_error.unwrap_or(LifecycleError::JobDidNotBecomeEmpty)),
        );
    }
    if let Some(handle) = stdout_thread
        && handle.join().is_err()
    {
        store_first_error(
            &mut cleanup_error,
            LifecycleError::MonitorThreadPanicked("stdout"),
        );
    }
    if let Some(handle) = stderr_thread
        && handle.join().is_err()
    {
        store_first_error(
            &mut cleanup_error,
            LifecycleError::MonitorThreadPanicked("stderr"),
        );
    }
    if let Err(error) = session.verify_security() {
        store_first_error(&mut cleanup_error, error.into());
    }
    if let Err(error) = session.cleanup() {
        store_first_error(&mut cleanup_error, error.into());
    }
    combine_cleanup_error(primary, cleanup_error)
}

fn combine_cleanup_error(
    primary: LifecycleError,
    cleanup: Option<LifecycleError>,
) -> LifecycleError {
    match cleanup {
        Some(cleanup) => LifecycleError::CleanupAfterFailure {
            primary: Box::new(primary),
            cleanup: Box::new(cleanup),
        },
        None => primary,
    }
}

fn store_first_error(slot: &mut Option<LifecycleError>, error: LifecycleError) {
    if slot.is_none() {
        *slot = Some(error);
    }
}

fn checked_deadline(duration: Duration) -> Result<Instant, LifecycleError> {
    Instant::now()
        .checked_add(duration)
        .ok_or(LifecycleError::InvalidLimits)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnerState {
    Starting,
    Ready,
    Stopping,
    Cleaned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MonitorEvent {
    Starting(u32),
    Listening(u32),
    Stopping,
    Stopped(u32),
    LauncherFailed(ErrorPhase),
}

#[derive(Clone, Copy, Debug)]
enum MonitorMessage {
    Event {
        state: LifecycleState,
        event: MonitorEvent,
    },
    ProtocolFailure(ProtocolError),
    StdoutReadFailure,
    StdoutEnded {
        state: LifecycleState,
        ignored_lines: u64,
    },
    StderrReadFailure,
}

/// Secret-free lifecycle failure.
#[derive(Debug, Error)]
pub enum LifecycleError {
    /// The timing policy was zero, inconsistent, or unreasonably large.
    #[error("the lifecycle timing policy was invalid")]
    InvalidLimits,
    /// The fixed R upstream port cannot be zero.
    #[error("the selected upstream port was zero")]
    InvalidUpstreamPort,
    /// The validated Rscript path did not have the required `R/bin` topology.
    #[error("the validated bundled runtime topology was invalid")]
    InvalidRuntimeTopology,
    /// A validated bundle operation failed before process creation.
    #[error(transparent)]
    Bundle(#[from] BundleError),
    /// A native process/session operation failed.
    #[error(transparent)]
    Launch(#[from] LaunchError),
    /// The bounded protocol-2 decoder or state tracker rejected the stream.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// A bounded filesystem or socket operation failed.
    #[error("{operation} failed")]
    Io {
        /// Secret-free operation label.
        operation: &'static str,
        /// Underlying operating-system error.
        #[source]
        source: io::Error,
    },
    /// A lifecycle drain thread could not be created.
    #[error("the {thread} lifecycle thread could not be created")]
    ThreadSpawn {
        /// Static thread role.
        thread: &'static str,
        /// Underlying thread creation error.
        #[source]
        source: io::Error,
    },
    /// A successful launch unexpectedly lacked a required pipe.
    #[error("the {0} lifecycle pipe was unavailable")]
    MissingLifecyclePipe(&'static str),
    /// The launcher did not delete the protected one-time token before start.
    #[error("the one-time token file remained after launcher start")]
    TokenNotConsumed,
    /// The launcher reported a stable failure phase; its message was discarded.
    #[error("the launcher reported a {0:?} failure")]
    LauncherReportedFailure(ErrorPhase),
    /// The wrapper exited before authenticated readiness.
    #[error("the R wrapper exited before authenticated readiness")]
    WrapperExitedBeforeReadiness,
    /// The captured runtime exited before authenticated readiness.
    #[error("the R runtime exited before authenticated readiness")]
    RuntimeExitedBeforeReadiness,
    /// The lifecycle stopped before authenticated readiness.
    #[error("the launcher stopped before authenticated readiness")]
    StoppedBeforeReadiness,
    /// Authenticated readiness did not complete within the startup bound.
    #[error("authenticated R readiness timed out")]
    ReadinessTimeout,
    /// The protocol monitor channel closed unexpectedly.
    #[error("the lifecycle protocol monitor disconnected")]
    MonitorDisconnected,
    /// The protocol stdout pipe could not be read.
    #[error("the lifecycle protocol stream could not be read")]
    ProtocolStreamReadFailed,
    /// The protocol stdout pipe closed outside intentional shutdown.
    #[error("the lifecycle protocol stream ended unexpectedly")]
    ProtocolStreamEnded,
    /// The stderr drain pipe could not be read.
    #[error("the lifecycle stderr stream could not be drained")]
    StderrStreamReadFailed,
    /// The exact wrapper exited after readiness without a shutdown request.
    #[error("the R wrapper exited unexpectedly")]
    WrapperExitedUnexpectedly,
    /// The exact runtime exited after readiness without a shutdown request.
    #[error("the R runtime exited unexpectedly")]
    RuntimeExitedUnexpectedly,
    /// A stop event arrived before the owner requested shutdown.
    #[error("the launcher began stopping without an owner shutdown request")]
    StoppedUnexpectedly,
    /// Monitor state disagreed with the required ready state.
    #[error("the launcher was in unexpected state {0:?}")]
    UnexpectedLifecycleState(LifecycleState),
    /// The owner no longer retained a live process.
    #[error("the runtime owner was not running")]
    OwnerNotRunning,
    /// Private cleanup cannot run while a process or monitor is still owned.
    #[error("the runtime owner still retained live process or monitor resources")]
    OwnerStillHasLiveResources,
    /// The reported runtime identity had not been captured.
    #[error("the runtime identity was unavailable")]
    RuntimeIdentityUnavailable,
    /// The private launch session was unavailable.
    #[error("the private launch session was unavailable")]
    PrivateSessionUnavailable,
    /// Shutdown was requested again after successful cleanup.
    #[error("the runtime owner was already cleaned")]
    OwnerAlreadyCleaned,
    /// Job accounting did not reach zero after bounded termination.
    #[error("the owned Job did not become empty after termination")]
    JobDidNotBecomeEmpty,
    /// Exact wrapper or runtime handles did not signal within the bound.
    #[error("an owned runtime process did not exit within the cleanup bound")]
    ProcessDidNotExit,
    /// A lifecycle monitor thread panicked.
    #[error("the {0} lifecycle monitor thread panicked")]
    MonitorThreadPanicked(&'static str),
    /// Cleanup also failed after an earlier lifecycle failure.
    #[error("lifecycle failed and bounded cleanup also failed")]
    CleanupAfterFailure {
        /// Original lifecycle failure.
        #[source]
        primary: Box<LifecycleError>,
        /// Later cleanup failure.
        cleanup: Box<LifecycleError>,
    },
}

#[cfg(test)]
mod tests {
    use super::{LifecycleLimits, success_status_line};

    #[test]
    fn status_line_accepts_only_http_one_success_or_redirect() {
        assert!(success_status_line(b"HTTP/1.1 200 OK"));
        assert!(success_status_line(b"HTTP/1.0 302 Found"));
        assert!(!success_status_line(b"HTTP/2 200"));
        assert!(!success_status_line(b"HTTP/1.1 199 Early"));
        assert!(!success_status_line(b"HTTP/1.1 400 Bad"));
        assert!(!success_status_line(b"HTTP/1.1 2000"));
        assert!(!success_status_line(b"garbage"));
    }

    #[test]
    fn default_limits_are_valid() -> Result<(), super::LifecycleError> {
        LifecycleLimits::default().validate()
    }
}
