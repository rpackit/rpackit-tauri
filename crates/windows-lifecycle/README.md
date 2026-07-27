# rpackit Windows lifecycle owner

This internal Windows-only crate owns one authenticated proxy plus one
validated bundled-R process from pre-spawn checks through deterministic
cleanup. It composes the resource, launcher-protocol, transport and native
Windows process crates.

Startup succeeds only after:

1. schema-1/protocol-2 resources pass non-executing validation;
2. a protected private session and one-time `S` token file are created;
3. ambient R/rpackit environment variables are removed and the bundled
   runtime/library are selected explicitly, with canonical paths revalidated
   as ordinary R-compatible Windows aliases;
4. the direct `R/bin/x64/Rscript.exe` interpreter is created suspended,
   assigned to the no-breakaway kill-on-close Job, verified and resumed;
5. the token file is gone and a valid post-bind `listening` event arrives;
6. the reported create-time-aware process is the directly launched
   interpreter, belongs to the Job, and exclusively owns
   `127.0.0.1:<port>`; and
7. a direct request carrying `Shiny-Shared-Secret: S` returns HTTP 2xx/3xx.

Typical native-shell ownership is:

```rust,ignore
let mut native = rpackit_windows_lifecycle::NativeAppOwner::launch(
    bundle,
    session_parent,
    rpackit_windows_lifecycle::LifecycleLimits::default(),
    rpackit_transport::TransportLimits::default(),
).await?;

let browser = native.browser_launch()?;
// Trusted native WebView setup may use browser.address(), P and one-time B.
// BrowserLaunch never contains S and its Debug output redacts P and B.

native.poll_health().await?;
let report = native.shutdown().await?;
```

`NativeAppOwner::launch()` validates before process creation, generates one
independent `S`/`P`/`B` set, selects the upstream port, binds the proxy,
classifies the random `.localhost` hostname, and launches R with the same
`S`. It returns only after exact runtime/listener capture and authenticated
readiness. `BrowserLaunch` supplies native-only proxy address, `P`, and `B`
handles after that point; it never contains `S`. No credential appears in
arguments, environment variables, Debug output, protocol messages or errors.

Graceful `shutdown()` first requests protocol-2 control-file shutdown, then
terminates the complete Job on timeout and drains the proxy. Runtime health
failure, forced shutdown, and owner drop stop accepting proxy traffic before
Job cleanup. Cleanup requires zero active Job processes and removes only the
known files plus the exact empty session directory. Unexpected entries remain
owned for an explicit `retry_private_cleanup()`.

The lower-level `RuntimeOwner` API remains available for focused process
lifecycle tests and direct native integrations that already own a compatible
proxy and one shared `TransportSecrets` value.

The included synthetic runtime validates orchestration and negative paths.
The repository also defines a separate ignored, GitHub-Actions-only matrix
against the SHA-256-pinned portable-R Release, generated launcher, and pinned
`hello-shiny`. It retains only bounded secret-free JSON evidence and deletes
its archive, extracted/copied runtimes, package libraries, Cargo target, and
sessions. Its
[reviewed native-composition run](https://github.com/rpackit/rpackit-tauri/actions/runs/30234829826)
passed every direct real-R scenario plus one-time real bootstrap,
`P`-authenticated proxy loading, credential denials, and combined cleanup.
The later
[reviewed full-owner run](https://github.com/rpackit/rpackit-tauri/actions/runs/30237185375)
also composed this owner with the maintained Tauri WebView/window/profile
owner and proved complete real-runtime close and cleanup. Neither run claims a
generated application or installer.
