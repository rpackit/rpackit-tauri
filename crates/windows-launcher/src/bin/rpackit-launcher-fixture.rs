//! Process-tree fixture used only by Windows lifecycle acceptance tests.

#![cfg(windows)]

use std::env;
use std::fs;
use std::net::TcpListener;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitCode};
use std::thread;
use std::time::Duration;

use windows::Win32::Foundation::{GetHandleInformation, HANDLE};

const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;

fn main() -> ExitCode {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let Some(mode) = arguments.next() else {
        eprintln!("missing fixture mode");
        return ExitCode::from(2);
    };

    match mode.to_string_lossy().as_ref() {
        "echo" => {
            let Some(value) = arguments.next() else {
                eprintln!("missing echo value");
                return ExitCode::from(2);
            };
            println!("stdout={}", value.to_string_lossy());
            eprintln!("stderr={}", value.to_string_lossy());
            ExitCode::SUCCESS
        }
        "tree" => {
            let Some(pid_path) = arguments.next() else {
                eprintln!("missing PID path");
                return ExitCode::from(2);
            };
            run_tree(Path::new(&pid_path))
        }
        "breakaway" => {
            let Some(outcome_path) = arguments.next() else {
                eprintln!("missing breakaway outcome path");
                return ExitCode::from(2);
            };
            run_breakaway_probe(Path::new(&outcome_path))
        }
        "handle" => {
            let Some(handle_value) = arguments.next() else {
                eprintln!("missing handle value");
                return ExitCode::from(2);
            };
            let Some(outcome_path) = arguments.next() else {
                eprintln!("missing handle outcome path");
                return ExitCode::from(2);
            };
            run_handle_probe(&handle_value.to_string_lossy(), Path::new(&outcome_path))
        }
        "listen" => {
            let Some(outcome_path) = arguments.next() else {
                eprintln!("missing listener outcome path");
                return ExitCode::from(2);
            };
            let Some(stop_path) = arguments.next() else {
                eprintln!("missing listener stop path");
                return ExitCode::from(2);
            };
            run_listener(Path::new(&outcome_path), Path::new(&stop_path))
        }
        "environment" => {
            let Some(present_name) = arguments.next() else {
                eprintln!("missing present environment name");
                return ExitCode::from(2);
            };
            let Some(removed_name) = arguments.next() else {
                eprintln!("missing removed environment name");
                return ExitCode::from(2);
            };
            run_environment(&present_name, &removed_name)
        }
        "sleep" => loop {
            thread::sleep(Duration::from_secs(1));
        },
        _ => {
            eprintln!("unknown fixture mode");
            ExitCode::from(2)
        }
    }
}

fn run_environment(present_name: &std::ffi::OsStr, removed_name: &std::ffi::OsStr) -> ExitCode {
    let Some(value) = env::var_os(present_name) else {
        eprintln!("expected environment value was absent");
        return ExitCode::from(15);
    };
    println!("value={}", value.to_string_lossy());
    println!(
        "removed={}",
        if env::var_os(removed_name).is_none() {
            "yes"
        } else {
            "no"
        }
    );
    ExitCode::SUCCESS
}

fn run_listener(outcome_path: &Path, stop_path: &Path) -> ExitCode {
    let listener = match TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("listener bind failed: {error}");
            return ExitCode::from(12);
        }
    };
    let port = match listener.local_addr() {
        Ok(address) => address.port(),
        Err(error) => {
            eprintln!("listener address failed: {error}");
            return ExitCode::from(13);
        }
    };
    let payload = format!("{}\n{port}\n", std::process::id());
    if let Err(error) = fs::write(outcome_path, payload) {
        eprintln!("listener outcome write failed: {error}");
        return ExitCode::from(14);
    }
    while !stop_path.exists() {
        thread::sleep(Duration::from_millis(25));
    }
    drop(listener);
    ExitCode::SUCCESS
}

fn run_handle_probe(handle_value: &str, outcome_path: &Path) -> ExitCode {
    let value = match handle_value.parse::<usize>() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("handle parse failed: {error}");
            return ExitCode::from(10);
        }
    };
    let handle = HANDLE(value as *mut std::ffi::c_void);
    let mut flags = 0_u32;
    // SAFETY: This is a deliberate probe of a numeric parent-handle value.
    // Windows validates whether the value names a handle in this process.
    let inherited = unsafe { GetHandleInformation(handle, &raw mut flags) }.is_ok();
    let outcome = if inherited {
        "inherited"
    } else {
        "not-inherited"
    };
    match fs::write(outcome_path, outcome) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("handle outcome write failed: {error}");
            ExitCode::from(11)
        }
    }
}

fn run_breakaway_probe(outcome_path: &Path) -> ExitCode {
    let executable = match env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("current_exe failed: {error}");
            return ExitCode::from(7);
        }
    };
    let spawn = Command::new(executable)
        .arg("sleep")
        .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
        .spawn();
    match spawn {
        Err(error) => {
            let outcome = format!("denied:{}", error.raw_os_error().unwrap_or_default());
            match fs::write(outcome_path, outcome) {
                Ok(()) => ExitCode::SUCCESS,
                Err(write_error) => {
                    eprintln!("breakaway outcome write failed: {write_error}");
                    ExitCode::from(8)
                }
            }
        }
        Ok(mut child) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::write(outcome_path, "allowed");
            ExitCode::from(9)
        }
    }
}

fn run_tree(pid_path: &Path) -> ExitCode {
    let executable = match env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("current_exe failed: {error}");
            return ExitCode::from(3);
        }
    };
    let mut child = match Command::new(executable).arg("sleep").spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!("child spawn failed: {error}");
            return ExitCode::from(4);
        }
    };
    let payload = format!("{}\n{}\n", std::process::id(), child.id());
    if let Err(error) = fs::write(pid_path, payload) {
        eprintln!("PID write failed: {error}");
        let _ = child.kill();
        let _ = child.wait();
        return ExitCode::from(5);
    }
    match child.wait() {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("child wait failed: {error}");
            ExitCode::from(6)
        }
    }
}
