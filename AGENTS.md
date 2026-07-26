# Repository instructions

This repository owns the maintained native Tauri templates and transport
implementation for rpackit.

- Treat `../roadmap/TAURI_SECURE_TRANSPORT.md` as the versioned security
  contract. The implemented baseline is transport contract version 2. A failed
  hard gate must fail closed; do not add insecure fallbacks.
- Preserve the three-secret boundary: `S` is the upstream Shiny secret, `P` is
  the proxy-session cookie value, and `B` is the one-time native bootstrap
  credential. They are independently generated and must never be derived from
  one another.
- `B` may appear only in the exact native initial-bootstrap request header.
  It must be consumed once, stripped before any upstream dial, and rejected
  when missing, wrong, duplicated, malformed, or replayed.
- The bootstrap HTTP response, not JavaScript or the native cookie setter,
  creates `P` using a `Set-Cookie` field with no `Domain` attribute. Do not
  replace the host-only cookie with a domain cookie.
- Keep all secret values out of JavaScript, URLs, arguments, environment
  variables, manifests, logs, errors, reports, fixtures, and committed
  resources.
- Keep platform-specific code behind explicit target checks.
- Tests must be deterministic, use loopback-only mock services, and need no
  external network or credentials.
- Keep development-runtime evidence separate from release claims. Phase 1 is
  not release-ready until the full matrix passes on a reviewed fixed minimum
  WebView2 runtime, forced-crash profile persistence is proven, browser escape
  and resource-abuse cases pass, malformed upstream behavior is covered, and
  listener-overlap gates are resolved.
- Do not commit build products, runtime archives, crash dumps, transcripts, or
  scratch output. Native artifacts belong in GitHub Actions/Releases.
- Pin reviewed dependency versions, commit `Cargo.lock`, and run formatting,
  Clippy with warnings denied, tests, and the Windows no-bundle build before
  publishing.
