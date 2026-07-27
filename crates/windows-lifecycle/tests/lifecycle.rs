//! Integrated Windows runtime-owner acceptance tests.

#![cfg(windows)]

use std::fs;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use rpackit_transport::TransportSecrets;
use rpackit_windows_lifecycle::{
    LifecycleError, LifecycleLimits, RuntimeOwner, ShutdownKind, select_upstream_port,
};
use serde_json::json;
use tempfile::TempDir;
use zeroize::Zeroizing;

const FIXTURE: &str = env!("CARGO_BIN_EXE_rpackit-runtime-fixture");

const VALID_LAUNCHER: &str = r"
event_prefix <- 'RPACKIT_EVENT '
payload <- list(protocol_version = '2')
usage <- '--token-file <path>'
token_lines <- readLines(token_file, n = 2L, warn = FALSE)
unlink(token_file, force = TRUE)
options(shiny.sharedSecret = token)
class(app) <- 'rpackit_authenticated_app_path'
token_enforced = TRUE
host = '127.0.0.1'
launch.browser = announce_listening
";

struct FixtureBundle {
    _temporary: TempDir,
    bundle: PathBuf,
    sessions: PathBuf,
    interpreter: PathBuf,
}

impl FixtureBundle {
    fn new(mode: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let bundle = temporary.path().join("bundle with spaces");
        let resources = bundle.join("resources");
        let rscript = resources.join("R/bin/Rscript.exe");
        let interpreter = resources.join("R/bin/x64/Rscript.exe");
        let library = resources.join("R/library");
        let app = resources.join("app");
        let sessions = temporary.path().join("private sessions");
        fs::create_dir_all(rscript.parent().ok_or("Rscript parent missing")?)?;
        fs::create_dir_all(
            interpreter
                .parent()
                .ok_or("architecture Rscript parent missing")?,
        )?;
        fs::create_dir_all(&library)?;
        fs::create_dir_all(&app)?;
        fs::create_dir(&sessions)?;
        fs::copy(FIXTURE, &rscript)?;
        fs::copy(FIXTURE, &interpreter)?;
        fs::write(app.join("app.R"), b"synthetic app\n")?;
        fs::write(app.join("fixture-mode"), mode)?;
        fs::write(resources.join("launcher.R"), VALID_LAUNCHER)?;
        for package in ["jsonlite", "later", "shiny"] {
            let directory = library.join(package);
            fs::create_dir(&directory)?;
            fs::write(
                directory.join("DESCRIPTION"),
                format!("Package: {package}\nVersion: 1.0.0\n"),
            )?;
        }
        fs::write(
            resources.join("rpackit.json"),
            serde_json::to_vec_pretty(&valid_manifest())?,
        )?;
        Ok(Self {
            _temporary: temporary,
            bundle,
            sessions,
            interpreter,
        })
    }

    fn launch(
        &self,
        secrets: &TransportSecrets,
        limits: LifecycleLimits,
    ) -> Result<RuntimeOwner, LifecycleError> {
        RuntimeOwner::launch(
            &self.bundle,
            &self.sessions,
            select_upstream_port()?,
            secrets,
            limits,
        )
    }

    fn sessions_are_empty(&self) -> Result<bool, std::io::Error> {
        Ok(fs::read_dir(&self.sessions)?.next().is_none())
    }
}

#[test]
fn authenticated_runtime_starts_and_cleans_gracefully() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureBundle::new("normal")?;
    let secrets = TransportSecrets::generate()?;
    let exposed = Zeroizing::new(secrets.upstream().with_exposed(str::to_owned));
    let mut owner = fixture.launch(&secrets, test_limits())?;
    let session = owner
        .session_directory()
        .ok_or("session directory unavailable")?
        .to_path_buf();

    assert_ne!(
        owner.runtime_identity().ok_or("runtime unavailable")?.pid,
        0
    );
    assert_eq!(owner.launch_identity(), owner.runtime_identity());
    assert!(
        owner
            .bundle()
            .rscript()
            .ends_with(Path::new(r"R\bin\Rscript.exe"))
    );
    assert!(!format!("{owner:?}").contains(exposed.as_str()));
    owner.poll_health()?;
    let report = owner.shutdown()?;

    assert_eq!(report.kind, ShutdownKind::Graceful);
    assert_eq!(report.wrapper_exit_code, Some(0));
    assert_eq!(report.runtime_exit_code, Some(0));
    assert!(report.job_empty);
    assert!(report.session_removed);
    assert!(!session.exists());
    assert!(fixture.sessions_are_empty()?);
    Ok(())
}

#[test]
fn missing_architecture_interpreter_fails_before_launch() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = FixtureBundle::new("normal")?;
    fs::remove_file(&fixture.interpreter)?;
    let secrets = TransportSecrets::generate()?;

    let error = require_launch_error(
        fixture.launch(&secrets, test_limits()),
        "missing architecture interpreter unexpectedly launched",
    )?;
    assert!(contains_error(&error, |error| matches!(
        error,
        LifecycleError::ArchitectureRscriptUnavailable
    )));
    assert!(fixture.sessions_are_empty()?);
    Ok(())
}

#[test]
fn ignored_control_uses_forced_job_fallback() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureBundle::new("ignore-control")?;
    let secrets = TransportSecrets::generate()?;
    let mut limits = test_limits();
    limits.graceful_timeout = Duration::from_millis(250);
    let mut owner = fixture.launch(&secrets, limits)?;
    let report = owner.shutdown()?;

    assert_eq!(report.kind, ShutdownKind::Forced);
    assert!(report.wrapper_exit_code.is_some());
    assert!(report.runtime_exit_code.is_some());
    assert!(report.job_empty);
    assert!(fixture.sessions_are_empty()?);
    Ok(())
}

#[test]
fn owner_drop_forces_tree_and_removes_private_session() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureBundle::new("normal")?;
    let secrets = TransportSecrets::generate()?;
    let owner = fixture.launch(&secrets, test_limits())?;
    let session = owner
        .session_directory()
        .ok_or("session directory unavailable")?
        .to_path_buf();

    drop(owner);
    assert!(!session.exists());
    assert!(fixture.sessions_are_empty()?);
    Ok(())
}

#[test]
fn unexpected_audit_entry_preserves_session_for_explicit_retry()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureBundle::new("normal")?;
    let secrets = TransportSecrets::generate()?;
    let mut owner = fixture.launch(&secrets, test_limits())?;
    let session = owner
        .session_directory()
        .ok_or("session directory unavailable")?
        .to_path_buf();
    let audit = session.join("unexpected-audit-entry");
    fs::write(&audit, b"preserve")?;

    let Err(shutdown_error) = owner.shutdown() else {
        return Err("non-recursive cleanup unexpectedly removed audit entry".into());
    };
    assert!(contains_error(&shutdown_error, |error| matches!(
        error,
        LifecycleError::Launch(_)
    )));
    assert!(audit.is_file());
    assert!(session.is_dir());

    fs::remove_file(&audit)?;
    owner.retry_private_cleanup()?;
    assert!(!session.exists());
    assert!(fixture.sessions_are_empty()?);
    Ok(())
}

#[test]
fn readiness_timeout_kills_job_and_removes_session() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureBundle::new("never-ready")?;
    let secrets = TransportSecrets::generate()?;
    let mut limits = test_limits();
    limits.startup_timeout = Duration::from_millis(600);
    limits.listener_timeout = Duration::from_millis(300);
    limits.readiness_io_timeout = Duration::from_millis(100);

    let error = require_launch_error(
        fixture.launch(&secrets, limits),
        "readiness unexpectedly succeeded",
    )?;
    assert!(contains_error(&error, |error| matches!(
        error,
        LifecycleError::ReadinessTimeout
    )));
    assert!(fixture.sessions_are_empty()?);
    Ok(())
}

#[test]
fn malformed_protocol_kills_job_and_removes_session() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureBundle::new("malformed-protocol")?;
    let secrets = TransportSecrets::generate()?;

    let error = require_launch_error(
        fixture.launch(&secrets, test_limits()),
        "malformed protocol unexpectedly succeeded",
    )?;
    assert!(contains_error(&error, |error| matches!(
        error,
        LifecycleError::Protocol(_)
    )));
    assert!(fixture.sessions_are_empty()?);
    Ok(())
}

#[test]
fn startup_exit_reports_only_code_and_stderr_count() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureBundle::new("exit-before-protocol")?;
    let secrets = TransportSecrets::generate()?;

    let error = require_launch_error(
        fixture.launch(&secrets, test_limits()),
        "pre-protocol exit unexpectedly launched",
    )?;
    assert!(contains_error(&error, |error| matches!(
        error,
        LifecycleError::InterpreterExitedBeforeReadiness {
            exit_code: 2,
            discarded_stderr_bytes
        } if *discarded_stderr_bytes > 0
    )));
    assert!(fixture.sessions_are_empty()?);
    Ok(())
}

#[test]
fn occupied_port_fails_closed_without_touching_contender() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = FixtureBundle::new("normal")?;
    let secrets = TransportSecrets::generate()?;
    let contender = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = contender.local_addr()?.port();

    let error = require_launch_error(
        RuntimeOwner::launch(
            &fixture.bundle,
            &fixture.sessions,
            port,
            &secrets,
            test_limits(),
        ),
        "occupied upstream port unexpectedly succeeded",
    )?;
    assert!(contains_error(&error, |error| matches!(
        error,
        LifecycleError::LauncherReportedFailure(_)
    )));
    assert_eq!(contender.local_addr()?.port(), port);
    assert!(fixture.sessions_are_empty()?);
    Ok(())
}

#[test]
fn post_readiness_exit_is_detected_by_exact_handles() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureBundle::new("exit-after-ready")?;
    let secrets = TransportSecrets::generate()?;
    let mut owner = fixture.launch(&secrets, test_limits())?;
    thread::sleep(Duration::from_millis(100));

    let Err(error) = owner.poll_health() else {
        let _ = owner.force_shutdown();
        return Err("unexpected process exit was missed".into());
    };
    assert!(matches!(
        error,
        LifecycleError::ProtocolStreamEnded
            | LifecycleError::WrapperExitedUnexpectedly
            | LifecycleError::RuntimeExitedUnexpectedly
    ));
    let report = owner.force_shutdown()?;
    assert_eq!(report.kind, ShutdownKind::Forced);
    assert!(fixture.sessions_are_empty()?);
    Ok(())
}

fn test_limits() -> LifecycleLimits {
    LifecycleLimits {
        startup_timeout: Duration::from_secs(5),
        listener_timeout: Duration::from_secs(1),
        readiness_io_timeout: Duration::from_millis(250),
        graceful_timeout: Duration::from_secs(1),
        termination_timeout: Duration::from_secs(3),
        poll_interval: Duration::from_millis(10),
    }
}

fn contains_error(
    error: &LifecycleError,
    predicate: impl Fn(&LifecycleError) -> bool + Copy,
) -> bool {
    if predicate(error) {
        return true;
    }
    match error {
        LifecycleError::CleanupAfterFailure { primary, cleanup } => {
            contains_error(primary, predicate) || contains_error(cleanup, predicate)
        }
        _ => false,
    }
}

fn require_launch_error(
    result: Result<RuntimeOwner, LifecycleError>,
    message: &'static str,
) -> Result<LifecycleError, Box<dyn std::error::Error>> {
    match result {
        Err(error) => Ok(error),
        Ok(mut owner) => {
            let _ = owner.force_shutdown();
            Err(message.into())
        }
    }
}

fn valid_manifest() -> serde_json::Value {
    json!({
        "schema_version": "1",
        "bundle_type": "rpackit-desktop-resources",
        "app": {
            "name": "Synthetic",
            "type": "shiny-single-file",
            "path": "app"
        },
        "runtime": {
            "path": "R",
            "rscript": "R/bin/Rscript.exe",
            "library": "R/library",
            "platform": "windows",
            "r_version": "4.6.1",
            "source": "explicit",
            "provenance": null
        },
        "launcher": {
            "script": "launcher.R",
            "host": "127.0.0.1",
            "port": "required-argument",
            "token": "private-file",
            "control": "optional-argument",
            "protocol_version": "2",
            "event_stream": {
                "format": "ndjson",
                "destination": "stdout",
                "prefix": "RPACKIT_EVENT "
            },
            "network_token_enforced": true,
            "authentication": {
                "scheme": "shiny-shared-secret",
                "header": "Shiny-Shared-Secret",
                "scope": ["http", "websocket"],
                "token_transport": "private-file",
                "token_in_url": false,
                "minimum_shiny_version": "1.3.0"
            },
            "readiness": {
                "strategy": "authenticated-http-poll",
                "starting_event": "listening"
            }
        },
        "dependencies": {
            "installed": true,
            "strategy": "install-packages",
            "packages": ["jsonlite", "later", "shiny"],
            "locked_r_version": null,
            "r_constraint": null,
            "constraints": [],
            "constraints_verified": true
        },
        "created_by": {
            "package": "rpackit",
            "version": "0.1.0"
        }
    })
}
