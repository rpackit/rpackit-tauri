# rpackit Windows lifecycle owner

This internal Windows-only crate owns one validated bundled-R process from
pre-spawn checks through deterministic cleanup. It is the composition layer
between the resource, launcher-protocol, transport-secret and native Windows
process crates.

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

Typical ownership is:

```rust,ignore
let secrets = rpackit_transport::TransportSecrets::generate()?;
let port = rpackit_windows_lifecycle::select_upstream_port()?;
let mut runtime = rpackit_windows_lifecycle::RuntimeOwner::launch(
    bundle,
    session_parent,
    port,
    &secrets,
    rpackit_windows_lifecycle::LifecycleLimits::default(),
)?;

runtime.poll_health()?;
let report = runtime.shutdown()?;
```

The complete Tauri owner binds and verifies its proxy/browser origin before
launching R with the same `TransportSecrets`. No secret is returned by this
API or included in arguments, environment variables, Debug output, protocol
messages or errors.

`shutdown()` first requests protocol-2 control-file shutdown, then terminates
the complete Job on timeout. Cleanup requires zero active Job processes and
removes only the known files plus the exact empty session directory.
Unexpected entries remain available through `session_directory()` and can be
cleaned later with `retry_private_cleanup()`.

The included synthetic runtime validates orchestration and negative paths.
The repository also defines a separate ignored, GitHub-Actions-only matrix
against the SHA-256-pinned portable-R Release, generated launcher, and pinned
`hello-shiny`. It retains only bounded secret-free JSON evidence and deletes
its archive, extracted/copied runtimes, package libraries, Cargo target, and
sessions. Its
[first reviewed run](https://github.com/rpackit/rpackit-tauri/actions/runs/30233439589)
passed every real-R process-owner scenario; that evidence does not extend to
the later combined proxy/WebView owner or a generated application.
