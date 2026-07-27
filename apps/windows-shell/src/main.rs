//! Native Windows shell entry point for one prepared rpackit bundle.

#[cfg(windows)]
mod windows_app;

#[cfg(windows)]
fn main() {
    windows_app::main();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("rpackit-windows-shell is available only on Windows");
    std::process::exit(1);
}
