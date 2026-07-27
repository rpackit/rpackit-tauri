//! Synthetic Rscript replacement for Windows lifecycle acceptance tests.

#![cfg(windows)]
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

const MAX_REQUEST_BYTES: usize = 16 * 1024;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("synthetic runtime failed: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    let options = parse_arguments(&arguments)?;
    let app = required_path(&options, "--app")?;
    let token_path = required_path(&options, "--token-file")?;
    let control_path = required_path(&options, "--control")?;
    let port = required_text(&options, "--port")?
        .parse::<u16>()
        .map_err(|_| "invalid port".to_owned())?;
    let mode = fs::read_to_string(app.join("fixture-mode"))
        .map_err(|_| "fixture mode was unavailable".to_owned())?;
    let mode = mode.trim();

    verify_environment()?;
    let token = fs::read_to_string(&token_path)
        .map_err(|_| "token could not be read".to_owned())?
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    if token.len() < 16 || token.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err("token shape was invalid".to_owned());
    }
    fs::remove_file(&token_path).map_err(|_| "token could not be consumed".to_owned())?;

    if mode == "malformed-protocol" {
        println!("RPACKIT_EVENT {{not-json");
        std::io::stdout()
            .flush()
            .map_err(|_| "stdout flush failed".to_owned())?;
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }
    if mode == "launcher-error" {
        emit_error("runtime")?;
        return Err("requested launcher failure".to_owned());
    }

    let pid = std::process::id();
    emit_starting(pid, port)?;
    let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, port)) else {
        emit_error("runtime")?;
        return Err("listener bind failed".to_owned());
    };
    listener
        .set_nonblocking(true)
        .map_err(|_| "listener could not become nonblocking".to_owned())?;
    emit_listening(pid, port)?;

    if mode == "crash-after-listening" {
        return Err("requested post-listening crash".to_owned());
    }

    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let authenticated = handle_request(stream, &token, mode == "never-ready")?;
                if authenticated && mode == "exit-after-ready" {
                    return Err("requested post-readiness exit".to_owned());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return Err("listener accept failed".to_owned()),
        }

        if mode != "ignore-control" && control_path.exists() {
            emit_stopping()?;
            drop(listener);
            emit_stopped(pid)?;
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn parse_arguments(arguments: &[OsString]) -> Result<HashMap<String, OsString>, String> {
    if arguments.len() < 2 || arguments[0] != "--vanilla" {
        return Err("missing --vanilla".to_owned());
    }
    let remaining = &arguments[2..];
    if !remaining.len().is_multiple_of(2) {
        return Err("option pairs were malformed".to_owned());
    }
    let mut options = HashMap::new();
    for pair in remaining.chunks_exact(2) {
        let key = pair[0].to_string_lossy().into_owned();
        if options.insert(key, pair[1].clone()).is_some() {
            return Err("duplicate option".to_owned());
        }
    }
    Ok(options)
}

fn required_path(options: &HashMap<String, OsString>, name: &str) -> Result<PathBuf, String> {
    options
        .get(name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {name}"))
}

fn required_text<'a>(
    options: &'a HashMap<String, OsString>,
    name: &str,
) -> Result<&'a str, String> {
    options
        .get(name)
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("invalid {name}"))
}

fn verify_environment() -> Result<(), String> {
    let executable = env::current_exe().map_err(|_| "current exe unavailable".to_owned())?;
    let architecture_bin = executable
        .parent()
        .ok_or_else(|| "architecture runtime bin unavailable".to_owned())?;
    let bin = architecture_bin
        .parent()
        .ok_or_else(|| "runtime bin unavailable".to_owned())?;
    let home = bin
        .parent()
        .ok_or_else(|| "runtime home unavailable".to_owned())?;
    let library = home.join("library");
    for (name, expected) in [
        ("R_HOME", home.as_os_str()),
        ("R_LIBS", library.as_os_str()),
        ("R_LIBS_SITE", library.as_os_str()),
        ("R_LIBS_USER", library.as_os_str()),
    ] {
        if env::var_os(name).as_deref() != Some(expected) {
            return Err(format!("{name} was not isolated"));
        }
    }
    if env::var_os("RPACKIT_LAUNCH_PROTOCOL").as_deref() != Some(std::ffi::OsStr::new("2")) {
        return Err("launch protocol environment was wrong".to_owned());
    }
    if env::var_os("RPACKIT_SESSION_TOKEN").is_some() {
        return Err("legacy environment token was present".to_owned());
    }
    let path = env::var_os("PATH").ok_or_else(|| "PATH was absent".to_owned())?;
    let mut paths = env::split_paths(&path);
    let Some(first) = paths.next() else {
        return Err("PATH was empty".to_owned());
    };
    let Some(second) = paths.next() else {
        return Err("PATH omitted the bundled R bin".to_owned());
    };
    if first != architecture_bin || second != bin {
        return Err("bundled architecture and R bins were not first on PATH".to_owned());
    }
    Ok(())
}

fn handle_request(
    mut stream: TcpStream,
    expected_token: &str,
    reject_all: bool,
) -> Result<bool, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|_| "request read timeout failed".to_owned())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .map_err(|_| "request write timeout failed".to_owned())?;
    let mut request = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 512];
    while request.len() < MAX_REQUEST_BYTES && !request.ends_with(b"\r\n\r\n") {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(count) => request.extend_from_slice(&buffer[..count]),
        }
    }
    let authenticated = !reject_all && request_is_authenticated(&request, expected_token);
    let response = if authenticated {
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".as_slice()
    } else {
        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice()
    };
    stream
        .write_all(response)
        .map_err(|_| "response write failed".to_owned())?;
    Ok(authenticated)
}

fn request_is_authenticated(request: &[u8], expected_token: &str) -> bool {
    let Ok(request) = std::str::from_utf8(request) else {
        return false;
    };
    let mut lines = request.split("\r\n");
    if lines.next() != Some("GET / HTTP/1.1") {
        return false;
    }
    let mut token_count = 0_u8;
    let mut token_matches = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("Shiny-Shared-Secret") {
            token_count = token_count.saturating_add(1);
            token_matches = value.trim() == expected_token;
        }
    }
    token_count == 1 && token_matches
}

fn emit_starting(pid: u32, port: u16) -> Result<(), String> {
    emit(&format!(
        "{{\"protocol_version\":\"2\",\"event\":\"starting\",\"timestamp\":\"2026-07-27 00:00:00 UTC\",\"pid\":{pid},\"host\":\"127.0.0.1\",\"port\":{port},\"token_enforced\":true,\"graceful_stop\":true}}"
    ))
}

fn emit_listening(pid: u32, port: u16) -> Result<(), String> {
    emit(&format!(
        "{{\"protocol_version\":\"2\",\"event\":\"listening\",\"timestamp\":\"2026-07-27 00:00:01 UTC\",\"pid\":{pid},\"host\":\"127.0.0.1\",\"port\":{port},\"token_enforced\":true}}"
    ))
}

fn emit_stopping() -> Result<(), String> {
    emit(
        "{\"protocol_version\":\"2\",\"event\":\"stopping\",\"timestamp\":\"2026-07-27 00:00:02 UTC\",\"reason\":\"control-file\"}",
    )
}

fn emit_stopped(pid: u32) -> Result<(), String> {
    emit(&format!(
        "{{\"protocol_version\":\"2\",\"event\":\"stopped\",\"timestamp\":\"2026-07-27 00:00:03 UTC\",\"pid\":{pid}}}"
    ))
}

fn emit_error(phase: &str) -> Result<(), String> {
    emit(&format!(
        "{{\"protocol_version\":\"2\",\"event\":\"error\",\"timestamp\":\"2026-07-27 00:00:01 UTC\",\"phase\":\"{phase}\",\"message\":\"synthetic failure\",\"pid\":{}}}",
        std::process::id()
    ))
}

fn emit(json: &str) -> Result<(), String> {
    println!("RPACKIT_EVENT {json}");
    std::io::stdout()
        .flush()
        .map_err(|_| "stdout flush failed".to_owned())
}
