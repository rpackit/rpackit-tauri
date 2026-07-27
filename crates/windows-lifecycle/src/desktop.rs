//! Composition of the authenticated proxy and one owned R lifecycle.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::sync::Arc;

use rpackit_resource_bundle::{BundleError, ValidatedBundle};
use rpackit_transport::{
    HostResolution, ProxyAddress, ProxyConfig, ProxyError, RunningProxy, Secret, TransportLimits,
    TransportSecrets,
};
use thiserror::Error;

use super::{LifecycleError, LifecycleLimits, RuntimeOwner, ShutdownReport, select_upstream_port};

/// Native-only browser launch material for one authenticated proxy.
///
/// This value intentionally omits the upstream secret. The session and
/// bootstrap credentials may be exposed only to trusted native `WebView` setup
/// code and must be released when that browser session is destroyed.
#[must_use = "browser launch material must remain native-only"]
pub struct BrowserLaunch {
    address: ProxyAddress,
    session: Arc<Secret>,
    bootstrap: Arc<Secret>,
}

impl BrowserLaunch {
    /// Returns the exact random browser origin and proxy listener port.
    #[must_use]
    pub const fn address(&self) -> &ProxyAddress {
        &self.address
    }

    /// Returns the native-only host cookie credential.
    #[must_use]
    pub fn session_secret(&self) -> Arc<Secret> {
        Arc::clone(&self.session)
    }

    /// Returns the native-only one-time bootstrap credential.
    #[must_use]
    pub fn bootstrap_secret(&self) -> Arc<Secret> {
        Arc::clone(&self.bootstrap)
    }
}

impl fmt::Debug for BrowserLaunch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserLaunch")
            .field("address", &self.address)
            .field("session", &"[REDACTED]")
            .field("bootstrap", &"[REDACTED]")
            .finish()
    }
}

/// Secret-free evidence returned after both native owners stop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeAppShutdownReport {
    /// Verified R process-tree and private-session cleanup evidence.
    pub runtime: ShutdownReport,
    /// Whether proxy listeners and every tracked connection were stopped.
    pub proxy_stopped: bool,
}

/// One authenticated proxy and its exact bundled R process tree.
///
/// Startup validates resources before binding the proxy, binds the proxy
/// before R can execute, and returns only after the runtime has passed
/// authenticated readiness. Dropping an unclean owner first stops accepting
/// proxy traffic best-effort and then invokes the runtime Job cleanup.
#[must_use = "the native application owner must be polled and shut down explicitly"]
pub struct NativeAppOwner {
    // Field and explicit Drop order keep the browser-facing listener ahead of
    // process cleanup on an unexpected owner drop.
    proxy: Option<RunningProxy>,
    runtime: Option<RuntimeOwner>,
    host_resolution: HostResolution,
}

impl fmt::Debug for NativeAppOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeAppOwner")
            .field(
                "proxy_address",
                &self.proxy.as_ref().map(RunningProxy::address),
            )
            .field("host_resolution", &self.host_resolution)
            .field("runtime", &self.runtime.as_ref().map(|_| "[OWNED]"))
            .finish_non_exhaustive()
    }
}

impl NativeAppOwner {
    /// Validates resources, binds the authenticated proxy, and starts bundled
    /// R with the same independently generated transport credentials.
    ///
    /// No `WebView` should be created until this method succeeds. The proxy is
    /// stopped if runtime startup or hostname classification fails.
    ///
    /// # Errors
    ///
    /// Returns a secret-free validation, proxy, runtime, worker, or cleanup
    /// error. Every failure after proxy binding attempts bounded proxy
    /// shutdown before returning.
    pub async fn launch(
        bundle: impl AsRef<Path>,
        session_parent: impl AsRef<Path>,
        lifecycle_limits: LifecycleLimits,
        transport_limits: TransportLimits,
    ) -> Result<Self, NativeAppError> {
        lifecycle_limits.validate()?;
        let bundle = ValidatedBundle::load(bundle)?;
        let session_parent = session_parent.as_ref().to_path_buf();
        let upstream_port = select_upstream_port()?;
        let secrets = TransportSecrets::generate().map_err(|_| NativeAppError::SecretGeneration)?;
        let upstream = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, upstream_port));
        let proxy_config = ProxyConfig::generate_with_secrets(upstream, secrets.clone())?
            .with_limits(transport_limits);
        let proxy = RunningProxy::start(proxy_config).await?;
        let host_resolution = proxy.resolve_hostname().await;
        if matches!(host_resolution, HostResolution::NonLoopback(_)) {
            return Err(
                cleanup_proxy_after_failure(NativeAppError::NonLoopbackBrowserHost, proxy).await,
            );
        }

        let runtime_result = tokio::task::spawn_blocking(move || {
            RuntimeOwner::launch_validated(
                bundle,
                session_parent,
                upstream_port,
                &secrets,
                lifecycle_limits,
            )
        })
        .await;
        match runtime_result {
            Ok(Ok(runtime)) => Ok(Self {
                proxy: Some(proxy),
                runtime: Some(runtime),
                host_resolution,
            }),
            Ok(Err(error)) => {
                Err(cleanup_proxy_after_failure(NativeAppError::Runtime(error), proxy).await)
            }
            Err(_) => Err(cleanup_proxy_after_failure(
                NativeAppError::LifecycleWorkerTerminated,
                proxy,
            )
            .await),
        }
    }

    /// Returns native-only material needed to install the initial `WebView`
    /// cookie and navigate to the authenticated origin.
    ///
    /// # Errors
    ///
    /// Returns [`NativeAppError::OwnerNotRunning`] after proxy cleanup.
    pub fn browser_launch(&self) -> Result<BrowserLaunch, NativeAppError> {
        let proxy = self.proxy.as_ref().ok_or(NativeAppError::OwnerNotRunning)?;
        Ok(BrowserLaunch {
            address: proxy.address().clone(),
            session: proxy.secrets().session(),
            bootstrap: proxy.secrets().bootstrap(),
        })
    }

    /// Returns how native name resolution classified the random `.localhost`
    /// hostname before R was started.
    #[must_use]
    pub const fn host_resolution(&self) -> &HostResolution {
        &self.host_resolution
    }

    /// Polls exact R process and protocol health.
    ///
    /// If health fails, this method immediately stops the proxy and forces
    /// bounded runtime cleanup before returning the original failure.
    ///
    /// # Errors
    ///
    /// Returns the secret-free runtime failure, combined with any later
    /// cleanup failure.
    pub async fn poll_health(&mut self) -> Result<(), NativeAppError> {
        let health = self
            .runtime
            .as_mut()
            .ok_or(NativeAppError::OwnerNotRunning)?
            .poll_health();
        if let Err(error) = health {
            let primary = NativeAppError::Runtime(error);
            let cleanup = self.force_shutdown().await.err();
            return Err(combine_cleanup_error(primary, cleanup));
        }
        Ok(())
    }

    /// Requests graceful R shutdown, verifies its Job becomes empty, and then
    /// drains and closes the proxy.
    ///
    /// A Tauri caller must prevent immediate application exit while awaiting
    /// this method, then destroy the `WebView` and remove its per-launch profile
    /// before releasing any [`BrowserLaunch`] credential clones.
    ///
    /// # Errors
    ///
    /// Returns the first secret-free runtime or proxy failure, retaining a
    /// runtime value when private-session cleanup remains retryable.
    pub async fn shutdown(&mut self) -> Result<NativeAppShutdownReport, NativeAppError> {
        if self.runtime.is_none() && self.proxy.is_none() {
            return Err(NativeAppError::OwnerNotRunning);
        }
        let runtime = self.stop_runtime(RuntimeStop::Graceful).await;
        let proxy = self.stop_proxy().await;
        finish_shutdown(runtime, proxy)
    }

    /// Stops accepting browser traffic and immediately terminates the R Job.
    ///
    /// This ordering is used for unexpected process/browser failures so new
    /// requests cannot race forced process cleanup.
    ///
    /// # Errors
    ///
    /// Returns the first secret-free proxy or runtime failure and still
    /// attempts both cleanup paths.
    pub async fn force_shutdown(&mut self) -> Result<NativeAppShutdownReport, NativeAppError> {
        if self.runtime.is_none() && self.proxy.is_none() {
            return Err(NativeAppError::OwnerNotRunning);
        }
        let proxy = self.stop_proxy().await;
        let runtime = self.stop_runtime(RuntimeStop::Forced).await;
        finish_shutdown(runtime, proxy)
    }

    /// Retries exact private-session removal after process and proxy cleanup.
    ///
    /// # Errors
    ///
    /// Returns an error while the proxy is still running, when no retained
    /// runtime exists, or when the runtime's non-recursive cleanup still
    /// fails.
    pub fn retry_private_cleanup(&mut self) -> Result<(), NativeAppError> {
        if self.proxy.is_some() {
            return Err(NativeAppError::OwnerStillRunning);
        }
        let runtime = self
            .runtime
            .as_mut()
            .ok_or(NativeAppError::OwnerNotRunning)?;
        runtime.retry_private_cleanup()?;
        self.runtime.take();
        Ok(())
    }

    async fn stop_proxy(&mut self) -> Result<(), NativeAppError> {
        let Some(proxy) = self.proxy.take() else {
            return Ok(());
        };
        proxy.shutdown().await?;
        Ok(())
    }

    async fn stop_runtime(&mut self, stop: RuntimeStop) -> Result<ShutdownReport, NativeAppError> {
        let runtime = self.runtime.take().ok_or(NativeAppError::OwnerNotRunning)?;
        let result = tokio::task::spawn_blocking(move || {
            let mut runtime = runtime;
            let result = match stop {
                RuntimeStop::Graceful => runtime.shutdown(),
                RuntimeStop::Forced => runtime.force_shutdown(),
            };
            (runtime, result)
        })
        .await;
        match result {
            Ok((_, Ok(report))) => Ok(report),
            Ok((runtime, Err(error))) => {
                self.runtime = Some(runtime);
                Err(NativeAppError::Runtime(error))
            }
            Err(_) => Err(NativeAppError::LifecycleWorkerTerminated),
        }
    }
}

impl Drop for NativeAppOwner {
    fn drop(&mut self) {
        drop(self.proxy.take());
        drop(self.runtime.take());
    }
}

#[derive(Clone, Copy)]
enum RuntimeStop {
    Graceful,
    Forced,
}

fn finish_shutdown(
    runtime: Result<ShutdownReport, NativeAppError>,
    proxy: Result<(), NativeAppError>,
) -> Result<NativeAppShutdownReport, NativeAppError> {
    match (runtime, proxy) {
        (Ok(runtime), Ok(())) => Ok(NativeAppShutdownReport {
            runtime,
            proxy_stopped: true,
        }),
        (Err(primary), Ok(())) | (Ok(_), Err(primary)) => Err(primary),
        (Err(primary), Err(cleanup)) => Err(combine_cleanup_error(primary, Some(cleanup))),
    }
}

async fn cleanup_proxy_after_failure(
    primary: NativeAppError,
    proxy: RunningProxy,
) -> NativeAppError {
    match proxy.shutdown().await {
        Ok(()) => primary,
        Err(error) => combine_cleanup_error(primary, Some(NativeAppError::Proxy(error))),
    }
}

fn combine_cleanup_error(
    primary: NativeAppError,
    cleanup: Option<NativeAppError>,
) -> NativeAppError {
    match cleanup {
        Some(cleanup) => NativeAppError::CleanupAfterFailure {
            primary: Box::new(primary),
            cleanup: Box::new(cleanup),
        },
        None => primary,
    }
}

/// Secret-free native application startup, health, and cleanup failures.
#[derive(Debug, Error)]
pub enum NativeAppError {
    /// A resource bundle did not pass the current native contract.
    #[error(transparent)]
    Bundle(#[from] BundleError),
    /// Independent transport credentials could not be generated.
    #[error("transport credential generation failed")]
    SecretGeneration,
    /// Proxy startup, traffic ownership, or shutdown failed.
    #[error(transparent)]
    Proxy(#[from] ProxyError),
    /// Bundled R startup, health, or cleanup failed.
    #[error(transparent)]
    Runtime(#[from] LifecycleError),
    /// The generated browser hostname resolved to a non-loopback address.
    #[error("the generated browser hostname resolved outside loopback")]
    NonLoopbackBrowserHost,
    /// A bounded blocking runtime operation terminated unexpectedly.
    #[error("the native lifecycle worker terminated unexpectedly")]
    LifecycleWorkerTerminated,
    /// The combined owner no longer retains a proxy or runtime.
    #[error("the native application owner was not running")]
    OwnerNotRunning,
    /// Retryable runtime cleanup was requested before the proxy stopped.
    #[error("the native application owner still retained a live proxy")]
    OwnerStillRunning,
    /// Cleanup also failed after an earlier native application failure.
    #[error("native application lifecycle failed and cleanup also failed")]
    CleanupAfterFailure {
        /// Original operation failure.
        #[source]
        primary: Box<NativeAppError>,
        /// Later cleanup failure.
        cleanup: Box<NativeAppError>,
    },
}
