# rpackit Windows WebView owner

This internal Windows-only crate owns the browser side of one prepared rpackit
desktop launch. It starts only after `NativeAppOwner` has validated the bundle
and made the authenticated proxy plus bundled R runtime ready.

Preflight runs before R starts. It requires the exact application identifier,
rejects untrusted WebView2 environment and machine/user policy overrides, and
requires WebView2 `149.0.4022.98` or newer.

`SecureWebviewOwner::launch()` then:

1. creates a random profile below a canonical non-reparse parent;
2. creates one hidden, unfocused WebView with developer tools, popups,
   downloads, extensions, autofill, drag/drop, context menus, accelerators,
   status UI, and zoom shortcuts disabled;
3. installs native navigation, document-request, and external-scheme guards;
4. sends the one-time `B` only in the exact native bootstrap request;
5. reads back exactly one matching `P` session cookie with the required path,
   HttpOnly, and SameSite flags;
6. navigates to the authenticated application root; and
7. shows the window only after that document finishes.

Typical ownership from a Tauri event loop is:

```rust,ignore
let preflight = rpackit_windows_webview::WebviewPreflight::verify(
    app.config().identifier.clone(),
)?;

let mut native = rpackit_windows_lifecycle::NativeAppOwner::launch(
    bundle,
    session_parent,
    rpackit_windows_lifecycle::LifecycleLimits::default(),
    rpackit_transport::TransportLimits::default(),
).await?;

let browser = native.browser_launch()?;
let mut webview = rpackit_windows_webview::SecureWebviewOwner::launch(
    &app,
    &browser,
    profile_parent,
    &preflight,
    rpackit_windows_webview::SecureWindowConfig::default(),
    rpackit_windows_webview::WebviewLimits::default(),
).await?;
drop(browser);

webview.hide()?;
let native_report = native.shutdown().await?;
let webview_report = webview.shutdown().await?;
```

Shutdown deletes `P`, queues browsing-data clearing, destroys the window, and
removes only the exact per-launch profile with bounded retries. If profile
handles outlive the first bound, the owner retains the scope for an explicit
`retry_profile_cleanup()`. Errors and `Debug` output never contain `P`, `B`,
the private profile path, or browser content.

The crate does not download portable R, prepare bundles, generate application
resources, build installers, or persist browser state. The maintained
composition lives in `apps/windows-shell`.

The
[reviewed real-runtime gate](https://github.com/rpackit/rpackit-tauri/actions/runs/30237185375)
ran that shell against the published portable R 4.6.1 and pinned
`hello-shiny`, then proved authenticated readiness and complete
runtime/proxy/Job/session/cookie/window/profile cleanup.
