# Changelog

All notable changes to this pre-release repository are documented here.

## Unreleased

### Transport contract version 2

- Added three independent per-launch secrets: upstream authentication (`S`),
  proxy-session authentication (`P`), and one-time bootstrap authentication
  (`B`).
- Restricted `B` to one exact native initial-bootstrap request header and
  added fail-closed handling for missing, wrong, duplicated, malformed, and
  replayed credentials.
- Moved host-only `P` creation to the authenticated bootstrap HTTP response
  using `Set-Cookie` without `Domain`, `Expires`, or `Max-Age`.
- Replaced the unsuccessful high-level Tauri host-only cookie-set experiment
  with a narrow WebView2 `CreateWebResourceRequest` plus
  `NavigateWithWebResourceRequest` bootstrap boundary.
- Added strict loopback/Host admission, authentication-before-upstream-dial,
  protected-header normalization, bounded HTTP streaming, redirect and
  application-cookie handling, and validated WebSocket tunnelling.
- Added tracked shutdown/drain for downstream connections, upstream protocol
  drivers, and upgrade tunnels, plus an activity-based WebSocket idle
  watchdog.
- Added secret-free Windows overlap evidence for IPv4 wildcard, IPv6 v6-only
  wildcard, and IPv6 dual-stack wildcard contenders. The dual-stack contender
  remains alive across exact IPv4 and IPv6 probes. Each of the four traffic
  paths requires 8/8 proxy `401` responses and zero wildcard accepts. Bind
  success is recorded independently, while unexpected bind errors fail closed.
- Refreshed the compatible Futures and Hyper stack together and validated the
  combined lockfile through the real WebView2 gate. `webview2-com` remains on
  `0.38.2` until Tauri/wry migrate their Windows COM type graph from 0.61 to
  0.62.
- Updated pinned GitHub Actions to their Node 24 releases and bounded CI job
  durations.
- Added deterministic mock-upstream tests for bootstrap replay, malformed
  requests, Origin checks, redirects/cookies, WebSocket behavior,
  cross-instance isolation, hostname classification, and credential leakage.
- Added a real WebView2 acceptance harness for cookie flags, documents and
  subresources, fetches, delayed streaming, WebSocket cookie delivery, child
  hostname isolation, external redirects, process metadata, and clean
  shutdown, including same-data-directory profile recreation.
- Recorded a passing development-runtime run on WebView2 `150.0.4078.83`,
  including the clean profile-recreation gate and the three-contender,
  four-path listener-overlap gate. All three wildcard binds succeeded while
  all 32 exact-loopback requests reached the proxy and wildcard accepts
  remained zero. This is not a fixed-minimum or release-readiness claim.

### Known pre-release gaps

- The full matrix has not run against a reviewed fixed minimum WebView2
  runtime.
- Forced-crash profile recreation has not yet proven that `P` is unrecoverable
  from disk.
- Browser escape controls are configured but have not all been exercised by
  real negative navigation, popup, download, scheme, devtools, extension, and
  debugger attempts.
- HTTP idle/body-rate and WebSocket byte-rate abuse, plus the complete
  malformed-upstream matrix, are not finished. WebSocket activity-idle
  shutdown is already tested.
- Protocol-2 R launcher ownership and Windows Job Object lifecycle enforcement
  are Phase 2 work.
