//! Remote-only acceptance gate for released portable R and hello-shiny.

#![cfg(windows)]

use std::env;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rpackit_transport::TransportSecrets;
use rpackit_windows_launcher::{LaunchCommand, LaunchEnvironment, launch};
use rpackit_windows_lifecycle::{
    LifecycleError, LifecycleLimits, RuntimeOwner, ShutdownKind, ShutdownReport,
    select_upstream_port,
};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

const MAX_HTTP_RESPONSE_BYTES: u64 = 1024 * 1024;
const EXPECTED_PAGE_MARKER: &[u8] = b"Hello from rpackit";
const WRONG_CREDENTIAL: &str = "wrong-rpackit-credential-0123456789";
const AMBIENT_LEGACY_CREDENTIAL: &str = "ambient-legacy-token-must-not-survive";
const PROBE_TIMEOUT_EXIT_CODE: u32 = 0x5250_4B50;
const PROBE_AMBIENT_R_VARIABLES: [&str; 14] = [
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

type GateResult<T> = Result<T, Box<dyn Error>>;

struct GateConfig {
    bundle: PathBuf,
    sessions: PathBuf,
    evidence: PathBuf,
    profile_marker: PathBuf,
    runtime_version: String,
    runtime_sha256: String,
    rpackit_commit: String,
    examples_commit: String,
}

impl GateConfig {
    fn from_environment() -> GateResult<Self> {
        if env::var("GITHUB_ACTIONS").as_deref() != Ok("true") {
            return Err(gate_error(
                "the released-runtime gate is restricted to GitHub Actions",
            ));
        }

        let config = Self {
            bundle: PathBuf::from(required_environment("RPACKIT_RELEASE_BUNDLE")?),
            sessions: PathBuf::from(required_environment("RPACKIT_RELEASE_SESSIONS")?),
            evidence: PathBuf::from(required_environment("RPACKIT_RELEASE_EVIDENCE")?),
            profile_marker: PathBuf::from(required_environment("RPACKIT_PROFILE_MARKER")?),
            runtime_version: required_environment("RPACKIT_RUNTIME_VERSION")?,
            runtime_sha256: required_environment("RPACKIT_RUNTIME_SHA256")?,
            rpackit_commit: required_environment("RPACKIT_PACKAGE_SHA")?,
            examples_commit: required_environment("RPACKIT_EXAMPLES_SHA")?,
        };
        if !config.bundle.is_dir() {
            return Err(gate_error("the prepared release bundle was missing"));
        }
        if !config.sessions.is_dir() {
            return Err(gate_error("the private-session parent was missing"));
        }
        if config.evidence.exists() {
            return Err(gate_error("the lifecycle evidence path already existed"));
        }
        let Some(evidence_parent) = config.evidence.parent() else {
            return Err(gate_error("the lifecycle evidence parent was missing"));
        };
        if !evidence_parent.is_dir() {
            return Err(gate_error(
                "the lifecycle evidence parent was not a directory",
            ));
        }
        if config.profile_marker.exists() {
            return Err(gate_error(
                "the hostile-profile marker existed before the gate",
            ));
        }
        validate_hex(&config.runtime_sha256, 64, "runtime SHA-256")?;
        validate_hex(&config.rpackit_commit, 40, "rpackit commit")?;
        validate_hex(&config.examples_commit, 40, "examples commit")?;
        ensure_sessions_empty(&config.sessions)?;
        Ok(config)
    }
}

struct HttpResponse {
    status: u16,
    bytes: Vec<u8>,
}

struct NativeProbeReport {
    exit_code: u32,
    stdout_bytes: u64,
    stderr_bytes: u64,
    job_empty: bool,
}

#[test]
#[ignore = "downloads and prepares released portable R only in GitHub Actions"]
#[allow(clippy::too_many_lines)]
fn released_portable_r_and_hello_shiny_pass_lifecycle_matrix() -> GateResult<()> {
    let config = GateConfig::from_environment()?;
    let mut scenarios = Map::new();

    let native_probe = probe_native_interpreter(&config)?;
    eprintln!(
        "released-runtime native R probe: exit_code={}, stdout_bytes={}, \
         stderr_bytes={}, job_empty={}",
        native_probe.exit_code,
        native_probe.stdout_bytes,
        native_probe.stderr_bytes,
        native_probe.job_empty
    );
    scenarios.insert(
        "native_interpreter_package_probe".to_owned(),
        json!({
            "exit_code": native_probe.exit_code,
            "stdout_bytes": native_probe.stdout_bytes,
            "stderr_bytes": native_probe.stderr_bytes,
            "job_empty": native_probe.job_empty
        }),
    );

    let (mut graceful_owner, graceful_secrets) = launch_owner(&config, normal_limits())?;
    ensure(
        graceful_owner.launch_identity() == graceful_owner.runtime_identity(),
        "the architecture-specific interpreter was not the owned runtime",
    )?;
    let first_credential = Zeroizing::new(graceful_secrets.upstream().with_exposed(str::to_owned));
    let authenticated = http_get(
        graceful_owner.upstream_port(),
        Some(first_credential.as_str()),
        "authenticated",
    )?;
    ensure(
        authenticated.status == 200,
        "authenticated hello-shiny request did not return HTTP 200",
    )?;
    ensure(
        contains_bytes(&authenticated.bytes, EXPECTED_PAGE_MARKER),
        "authenticated response did not contain the hello-shiny page marker",
    )?;
    ensure(
        http_get(graceful_owner.upstream_port(), None, "missing-credential")?.status == 403,
        "missing Shiny credential was not denied",
    )?;
    ensure(
        http_get(
            graceful_owner.upstream_port(),
            Some(WRONG_CREDENTIAL),
            "wrong-credential",
        )?
        .status
            == 403,
        "wrong Shiny credential was not denied",
    )?;
    graceful_owner.poll_health()?;
    let graceful_report = graceful_owner.shutdown()?;
    verify_shutdown(&graceful_report, ShutdownKind::Graceful)?;
    scenarios.insert(
        "authenticated_graceful_lifecycle".to_owned(),
        json!({
            "direct_architecture_interpreter_owned": true,
            "authenticated_page_loaded": true,
            "missing_credential_denied": true,
            "wrong_credential_denied": true,
            "shutdown": report_evidence(&graceful_report)
        }),
    );
    ensure_sessions_empty(&config.sessions)?;

    let (mut forced_owner, _forced_secrets) = launch_owner(&config, normal_limits())?;
    let forced_report = forced_owner.force_shutdown()?;
    verify_shutdown(&forced_report, ShutdownKind::Forced)?;
    scenarios.insert(
        "forced_job_shutdown".to_owned(),
        json!({"shutdown": report_evidence(&forced_report)}),
    );
    ensure_sessions_empty(&config.sessions)?;

    let (dropped_owner, _dropped_secrets) = launch_owner(&config, normal_limits())?;
    let dropped_session = dropped_owner
        .session_directory()
        .ok_or_else(|| gate_error("drop scenario did not retain a private session"))?
        .to_path_buf();
    drop(dropped_owner);
    ensure(
        !dropped_session.exists(),
        "owner drop retained its private session",
    )?;
    ensure_sessions_empty(&config.sessions)?;
    scenarios.insert(
        "native_owner_crash_cleanup".to_owned(),
        json!({"job_and_private_session_removed": true}),
    );

    let (mut crashed_owner, _crashed_secrets) = launch_owner(&config, normal_limits())?;
    let runtime_pid = crashed_owner
        .runtime_identity()
        .ok_or_else(|| gate_error("runtime identity was unavailable"))?
        .pid;
    terminate_exact_process(runtime_pid)?;
    let crash_deadline = Instant::now()
        .checked_add(Duration::from_secs(10))
        .ok_or_else(|| gate_error("crash deadline overflowed"))?;
    loop {
        if crashed_owner.poll_health().is_err() {
            break;
        }
        if Instant::now() >= crash_deadline {
            let _ = crashed_owner.force_shutdown();
            return Err(gate_error("the exact runtime crash was not detected"));
        }
        thread::sleep(Duration::from_millis(25));
    }
    let crash_report = crashed_owner.force_shutdown()?;
    verify_shutdown(&crash_report, ShutdownKind::Forced)?;
    scenarios.insert(
        "launcher_runtime_crash".to_owned(),
        json!({
            "exact_process_exit_detected": true,
            "shutdown": report_evidence(&crash_report)
        }),
    );
    ensure_sessions_empty(&config.sessions)?;

    let timeout_secrets = TransportSecrets::generate()?;
    let timeout_error = RuntimeOwner::launch(
        &config.bundle,
        &config.sessions,
        select_upstream_port()?,
        &timeout_secrets,
        timeout_limits(),
    )
    .err()
    .ok_or_else(|| gate_error("one-millisecond startup unexpectedly succeeded"))?;
    ensure(
        contains_lifecycle_error(&timeout_error, |error| {
            matches!(error, LifecycleError::ReadinessTimeout)
        }),
        "the bounded startup did not fail with a readiness timeout",
    )?;
    ensure_sessions_empty(&config.sessions)?;
    scenarios.insert(
        "startup_timeout".to_owned(),
        json!({"failed_closed_and_cleaned": true}),
    );

    let contender = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let occupied_port = contender.local_addr()?.port();
    let occupied_secrets = TransportSecrets::generate()?;
    let occupied_result = RuntimeOwner::launch(
        &config.bundle,
        &config.sessions,
        occupied_port,
        &occupied_secrets,
        normal_limits(),
    );
    if let Ok(mut unexpected_owner) = occupied_result {
        let _ = unexpected_owner.force_shutdown();
        return Err(gate_error(
            "an occupied upstream port unexpectedly launched",
        ));
    }
    ensure(
        contender.local_addr()?.port() == occupied_port,
        "the lifecycle gate disturbed the competing listener",
    )?;
    ensure_sessions_empty(&config.sessions)?;
    scenarios.insert(
        "occupied_port".to_owned(),
        json!({"failed_closed_and_contender_survived": true}),
    );

    ensure(
        !config.profile_marker.exists(),
        "ambient R profile executed inside a sanitized bundled launch",
    )?;
    scenarios.insert(
        "ambient_profile_isolation".to_owned(),
        json!({"hostile_profile_not_executed": true}),
    );

    let evidence = json!({
        "schema_version": "1",
        "gate": "released-portable-r-hello-shiny",
        "runtime": {
            "version": config.runtime_version,
            "sha256": config.runtime_sha256
        },
        "sources": {
            "rpackit_commit": config.rpackit_commit,
            "examples_commit": config.examples_commit
        },
        "scenarios": Value::Object(scenarios),
        "private_sessions_empty": true,
        "local_runtime_retained": false
    });
    let mut encoded = serde_json::to_vec_pretty(&evidence)?;
    encoded.push(b'\n');
    ensure(
        !contains_bytes(&encoded, first_credential.as_bytes()),
        "lifecycle evidence contained the generated credential",
    )?;
    ensure(
        !contains_bytes(&encoded, AMBIENT_LEGACY_CREDENTIAL.as_bytes()),
        "lifecycle evidence contained the ambient legacy credential",
    )?;
    write_evidence_atomically(&config.evidence, &encoded)?;
    Ok(())
}

fn required_environment(name: &'static str) -> GateResult<String> {
    let value = env::var(name).map_err(|_| gate_error(format!("{name} was not configured")))?;
    if value.is_empty() {
        return Err(gate_error(format!("{name} was empty")));
    }
    Ok(value)
}

fn validate_hex(value: &str, length: usize, label: &'static str) -> GateResult<()> {
    ensure(
        value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        format!("{label} was malformed"),
    )
}

fn launch_owner(
    config: &GateConfig,
    limits: LifecycleLimits,
) -> GateResult<(RuntimeOwner, TransportSecrets)> {
    let secrets = TransportSecrets::generate()?;
    let owner = RuntimeOwner::launch(
        &config.bundle,
        &config.sessions,
        select_upstream_port()?,
        &secrets,
        limits,
    )?;
    Ok((owner, secrets))
}

#[allow(clippy::too_many_lines)]
fn probe_native_interpreter(config: &GateConfig) -> GateResult<NativeProbeReport> {
    let resources = config.bundle.join("resources");
    let runtime_home = resources.join("R");
    let runtime_bin = runtime_home.join("bin");
    let architecture_bin = runtime_bin.join("x64");
    let interpreter = architecture_bin.join("Rscript.exe");
    let library = runtime_home.join("library");
    ensure(
        interpreter.is_file() && library.is_dir(),
        "the native interpreter probe topology was incomplete",
    )?;

    let mut environment = LaunchEnvironment::from_current()?;
    for name in PROBE_AMBIENT_R_VARIABLES {
        let _ = environment.remove(name)?;
    }
    environment.set("R_HOME", runtime_home.as_os_str())?;
    environment.set("R_LIBS", library.as_os_str())?;
    environment.set("R_LIBS_SITE", library.as_os_str())?;
    environment.set("R_LIBS_USER", library.as_os_str())?;
    environment.set("RPACKIT_LAUNCH_PROTOCOL", "2")?;
    let mut path = OsString::from(architecture_bin.as_os_str());
    path.push(OsStr::new(";"));
    path.push(runtime_bin.as_os_str());
    if let Some(ambient_path) = env::var_os("PATH")
        && !ambient_path.is_empty()
    {
        path.push(OsStr::new(";"));
        path.push(ambient_path);
    }
    environment.set("PATH", path)?;

    let expression = concat!(
        "if (!requireNamespace('jsonlite', quietly=TRUE)) ",
        "quit(save='no', status=11L, runLast=FALSE);",
        "if (!requireNamespace('later', quietly=TRUE)) ",
        "quit(save='no', status=12L, runLast=FALSE);",
        "if (!requireNamespace('shiny', quietly=TRUE)) ",
        "quit(save='no', status=13L, runLast=FALSE);",
        "quit(save='no', status=0L, runLast=FALSE)"
    );
    let command = LaunchCommand::new(&interpreter, &resources)
        .args([
            OsString::from("--vanilla"),
            OsString::from("-e"),
            OsString::from(expression),
        ])
        .environment(environment);
    let mut process = launch(&command)?;
    let stdout = process
        .take_stdout()
        .ok_or_else(|| gate_error("the native probe stdout pipe was unavailable"))?;
    let stderr = process
        .take_stderr()
        .ok_or_else(|| gate_error("the native probe stderr pipe was unavailable"))?;
    let stdout_thread = thread::Builder::new()
        .name("released-runtime-probe-stdout".to_owned())
        .spawn(move || count_stream_bytes(stdout))?;
    let stderr_thread = thread::Builder::new()
        .name("released-runtime-probe-stderr".to_owned())
        .spawn(move || count_stream_bytes(stderr))?;

    let timed_out = process.wait(Duration::from_secs(15))?.is_none();
    if timed_out {
        process.terminate(PROBE_TIMEOUT_EXIT_CODE)?;
    }
    let job_empty = process.wait_for_empty(Duration::from_secs(10))?;
    let exit_code = process.wait(Duration::from_secs(10))?;
    drop(process);
    let stdout_bytes = stdout_thread
        .join()
        .map_err(|_| gate_error("the native probe stdout counter panicked"))??;
    let stderr_bytes = stderr_thread
        .join()
        .map_err(|_| gate_error("the native probe stderr counter panicked"))??;
    let exit_code =
        exit_code.ok_or_else(|| gate_error("the native probe exit code was unavailable"))?;

    ensure(!timed_out, "the native interpreter probe timed out")?;
    ensure(
        job_empty,
        "the native interpreter probe retained an active Job process",
    )?;
    ensure(
        exit_code == 0,
        format!(
            "the native interpreter/package probe failed: exit_code={exit_code}, \
             stdout_bytes={stdout_bytes}, stderr_bytes={stderr_bytes}"
        ),
    )?;
    Ok(NativeProbeReport {
        exit_code,
        stdout_bytes,
        stderr_bytes,
        job_empty,
    })
}

fn count_stream_bytes(mut stream: impl Read) -> io::Result<u64> {
    let mut total = 0_u64;
    let mut buffer = [0_u8; 4096];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(total),
            Ok(count) => {
                let count = u64::try_from(count).map_err(io::Error::other)?;
                total = total.saturating_add(count);
            }
            Err(error) => return Err(error),
        }
    }
}

fn normal_limits() -> LifecycleLimits {
    LifecycleLimits {
        startup_timeout: Duration::from_secs(90),
        listener_timeout: Duration::from_secs(15),
        readiness_io_timeout: Duration::from_secs(2),
        graceful_timeout: Duration::from_secs(10),
        termination_timeout: Duration::from_secs(10),
        poll_interval: Duration::from_millis(25),
    }
}

fn timeout_limits() -> LifecycleLimits {
    LifecycleLimits {
        startup_timeout: Duration::from_millis(1),
        listener_timeout: Duration::from_millis(1),
        readiness_io_timeout: Duration::from_millis(1),
        graceful_timeout: Duration::from_secs(1),
        termination_timeout: Duration::from_secs(10),
        poll_interval: Duration::from_millis(1),
    }
}

fn http_get(
    port: u16,
    credential: Option<&str>,
    observation: &'static str,
) -> GateResult<HttpResponse> {
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let timeout = Duration::from_secs(5);
    let mut stream = TcpStream::connect_timeout(&address.into(), timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut request = Zeroizing::new(Vec::with_capacity(256));
    write!(request, "GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n")?;
    if let Some(value) = credential {
        write!(request, "Shiny-Shared-Secret: {value}\r\n")?;
    }
    request.extend_from_slice(b"Connection: close\r\n\r\n");
    stream.write_all(&request)?;
    stream.flush()?;

    let mut bytes = Vec::new();
    stream
        .take(MAX_HTTP_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure(
        u64::try_from(bytes.len())? <= MAX_HTTP_RESPONSE_BYTES,
        format!("{observation} HTTP response exceeded the acceptance-test limit"),
    )?;
    let status_line_end = bytes
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| {
            gate_error(format!(
                "{observation} HTTP response omitted its status line"
            ))
        })?;
    let status_line = std::str::from_utf8(&bytes[..status_line_end])?;
    let status = status_line
        .split_ascii_whitespace()
        .nth(1)
        .ok_or_else(|| gate_error(format!("{observation} HTTP status code was missing")))?
        .parse::<u16>()?;
    Ok(HttpResponse { status, bytes })
}

fn terminate_exact_process(pid: u32) -> GateResult<()> {
    ensure(pid != 0, "runtime PID was zero")?;
    let status = Command::new("taskkill.exe")
        .args(["/PID", &pid.to_string(), "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    ensure(
        status.success(),
        "taskkill could not terminate the exact runtime",
    )
}

fn verify_shutdown(report: &ShutdownReport, expected: ShutdownKind) -> GateResult<()> {
    ensure(report.kind == expected, "shutdown kind did not match")?;
    ensure(
        report.job_empty,
        "the Windows Job retained an active process",
    )?;
    ensure(
        report.session_removed,
        "the private launch session was retained",
    )?;
    ensure(
        report.wrapper_exit_code.is_some(),
        "the wrapper exit code was unavailable",
    )?;
    ensure(
        report.runtime_exit_code.is_some(),
        "the runtime exit code was unavailable",
    )
}

fn report_evidence(report: &ShutdownReport) -> Value {
    json!({
        "kind": match report.kind {
            ShutdownKind::Graceful => "graceful",
            ShutdownKind::Forced => "forced"
        },
        "wrapper_exit_code_captured": report.wrapper_exit_code.is_some(),
        "runtime_exit_code_captured": report.runtime_exit_code.is_some(),
        "job_empty": report.job_empty,
        "session_removed": report.session_removed,
        "ignored_stdout_lines": report.ignored_stdout_lines,
        "discarded_stderr_bytes": report.discarded_stderr_bytes
    })
}

fn contains_lifecycle_error(
    error: &LifecycleError,
    predicate: impl Fn(&LifecycleError) -> bool + Copy,
) -> bool {
    if predicate(error) {
        return true;
    }
    match error {
        LifecycleError::CleanupAfterFailure { primary, cleanup } => {
            contains_lifecycle_error(primary, predicate)
                || contains_lifecycle_error(cleanup, predicate)
        }
        _ => false,
    }
}

fn ensure_sessions_empty(path: &Path) -> GateResult<()> {
    ensure(
        fs::read_dir(path)?.next().is_none(),
        "the private-session parent retained an entry",
    )
}

fn write_evidence_atomically(path: &Path, bytes: &[u8]) -> GateResult<()> {
    let staging = path.with_extension("json.tmp");
    if staging.exists() {
        return Err(gate_error("the lifecycle evidence staging path existed"));
    }
    fs::write(&staging, bytes)?;
    fs::rename(staging, path)?;
    Ok(())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn ensure(condition: bool, message: impl Into<String>) -> GateResult<()> {
    if condition {
        Ok(())
    } else {
        Err(gate_error(message))
    }
}

fn gate_error(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::other(message.into()).into()
}
