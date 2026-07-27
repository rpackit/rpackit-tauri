# rpackit maintained Windows shell

This is the thin Tauri event-loop composition for one already prepared rpackit
bundle. It combines `NativeAppOwner` with `SecureWebviewOwner`; it is not an
application generator or installer template.

Required arguments:

```text
rpackit-windows-shell.exe
  --bundle <validated-resource-bundle>
  --session-parent <existing-private-session-parent>
  --profile-parent <existing-webview-profile-parent>
```

The shell performs WebView2 policy/runtime preflight before starting R,
launches the authenticated proxy and bundled runtime, creates the hidden
hardened WebView, completes native bootstrap and cookie verification, then
shows the authenticated application. Window close and application exit are
intercepted once so the UI is hidden before deterministic runtime, proxy,
cookie, browsing-data clear request, window, session, and profile cleanup.

The paired `--evidence <new-file> --close-after-ready` options are reserved for
the remote acceptance gate. They close immediately after authenticated
readiness and write one bounded, path-free, secret-free JSON report. Supplying
only one of the pair fails before launch.

Heavy validation belongs in GitHub Actions. The
[reviewed released-runtime run](https://github.com/rpackit/rpackit-tauri/actions/runs/30237185375)
built this shell remotely, ran it against portable R 4.6.1 plus pinned
`hello-shiny`, verified every cleanup boolean, and removed the complete
runner-temporary work root.
