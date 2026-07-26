//! Windows process-tree lifecycle acceptance tests.

#![cfg(windows)]

use std::ffi::OsString;
use std::io::{self, Read};
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use rpackit_windows_launcher::{LaunchCommand, LaunchError, launch};
use tempfile::tempdir;
use windows::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Threading::{
    CreateEventW, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    WaitForSingleObject,
};
use windows::core::PCWSTR;

const FIXTURE: &str = env!("CARGO_BIN_EXE_rpackit-launcher-fixture");

#[test]
fn launch_preserves_arguments_and_captures_lifecycle_streams()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let value = OsString::from("space, quote \" and trailing slash \\");
    let command =
        LaunchCommand::new(FIXTURE, temporary.path()).args([OsString::from("echo"), value.clone()]);
    let mut process = launch(&command)?;

    assert_ne!(process.identity().pid, 0);
    assert_ne!(process.identity().creation_time_100ns, 0);
    assert!(process.is_in_job()?);
    assert!(!process.job_handle_is_inheritable()?);
    let policy = process.job_policy()?;
    assert!(policy.kill_on_close);
    assert!(!policy.breakaway_allowed);
    assert!(!policy.silent_breakaway_allowed);
    assert_eq!(process.wait(Duration::from_secs(10))?, Some(0));

    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut stdout_pipe = process
        .take_stdout()
        .ok_or_else(|| io::Error::other("stdout pipe was unavailable"))?;
    let mut stderr_pipe = process
        .take_stderr()
        .ok_or_else(|| io::Error::other("stderr pipe was unavailable"))?;
    stdout_pipe.read_to_string(&mut stdout)?;
    stderr_pipe.read_to_string(&mut stderr)?;
    assert_eq!(stdout, format!("stdout={}\n", value.to_string_lossy()));
    assert_eq!(stderr, format!("stderr={}\n", value.to_string_lossy()));
    Ok(())
}

#[test]
fn process_cannot_create_a_breakaway_child() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let outcome_path = temporary.path().join("breakaway outcome.txt");
    let command = LaunchCommand::new(FIXTURE, temporary.path()).args([
        OsString::from("breakaway"),
        outcome_path.as_os_str().to_owned(),
    ]);
    let process = launch(&command)?;

    assert_eq!(process.wait(Duration::from_secs(10))?, Some(0));
    assert_eq!(std::fs::read_to_string(outcome_path)?, "denied:5");
    Ok(())
}

#[test]
fn unrelated_inheritable_handle_is_not_inherited() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())?,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    // SAFETY: The security attributes are valid for the call and request one
    // unnamed event with an inheritable handle.
    let raw_sentinel =
        unsafe { CreateEventW(Some(&raw const attributes), true, false, PCWSTR::null()) }?;
    // SAFETY: CreateEventW returned a new owned handle, transferred once here.
    let sentinel = unsafe { OwnedHandle::from_raw_handle(raw_sentinel.0) };
    let handle_value = sentinel.as_raw_handle().addr().to_string();
    let outcome_path = temporary.path().join("handle outcome.txt");
    let command = LaunchCommand::new(FIXTURE, temporary.path()).args([
        OsString::from("handle"),
        OsString::from(handle_value),
        outcome_path.as_os_str().to_owned(),
    ]);
    let process = launch(&command)?;

    assert_eq!(process.wait(Duration::from_secs(10))?, Some(0));
    assert_eq!(std::fs::read_to_string(outcome_path)?, "not-inherited");
    drop(sentinel);
    Ok(())
}

#[test]
fn dropping_job_kills_wrapper_and_descendant() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let pid_path = temporary.path().join("process ids.txt");
    let command = LaunchCommand::new(FIXTURE, temporary.path())
        .args([OsString::from("tree"), pid_path.as_os_str().to_owned()]);
    let process = launch(&command)?;
    let pids = wait_for_pids(&pid_path, Duration::from_secs(10))?;

    assert_eq!(pids.len(), 2);
    assert!(pids.iter().all(|pid| process_is_running(*pid)));
    assert!(matches!(
        process.capture_job_member(0),
        Err(LaunchError::InvalidProcessId)
    ));
    assert!(matches!(
        process.capture_job_member(std::process::id()),
        Err(LaunchError::ProcessOutsideJob)
    ));
    let wrapper = process.capture_job_member(pids[0])?;
    let descendant = process.capture_job_member(pids[1])?;
    assert_eq!(wrapper.identity(), process.identity());
    assert_eq!(descendant.identity().pid, pids[1]);
    assert_ne!(descendant.identity().creation_time_100ns, 0);
    assert!(wrapper.is_alive()?);
    assert!(descendant.is_alive()?);
    drop(process);

    assert!(wrapper.wait(Duration::from_secs(10))?.is_some());
    assert!(descendant.wait(Duration::from_secs(10))?.is_some());
    for pid in pids {
        assert!(
            wait_until_not_running(pid, Duration::from_secs(10)),
            "process {pid} survived Job close"
        );
    }
    Ok(())
}

fn wait_for_pids(path: &Path, timeout: Duration) -> io::Result<Vec<u32>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(contents) = std::fs::read_to_string(path) {
            let pids: Vec<u32> = contents
                .lines()
                .filter_map(|line| line.parse::<u32>().ok())
                .collect();
            if pids.len() == 2 {
                return Ok(pids);
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "fixture did not publish both PIDs",
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn process_is_running(pid: u32) -> bool {
    // SAFETY: OpenProcess validates the PID and returns a new handle on success.
    let Ok(handle) = (unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
    }) else {
        return false;
    };
    // SAFETY: `handle` is valid until CloseHandle below.
    let wait = unsafe { WaitForSingleObject(handle, 0) };
    // SAFETY: `handle` was returned by OpenProcess and is closed exactly once.
    let _ = unsafe { CloseHandle(handle) };
    wait == WAIT_TIMEOUT
}

fn wait_until_not_running(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if !process_is_running(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(25));
    }
}
