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
- Added a raw upstream response guard that releases no bytes to Hyper until a
  bounded HTTP/1.1 response head passes strict CRLF, header-count, header-size,
  and unambiguous `Content-Length`/`Transfer-Encoding` checks. Ordinary HTTP
  rejects unsolicited protocol switches; WebSocket `101` still undergoes its
  existing exact handshake validation.
- Added secret-free evidence for separate valid raw HTTP and WebSocket
  baselines, 16 ordinary negative response heads, and 16 WebSocket `101`
  negatives. Every attack must become the exact static `502` with no
  unexpected header, downstream upgrade, attacker header canary, or tunneled
  frame. The raw upstream independently verifies one valid synthetic secret
  on all 34 requests and the exact normalized upgrade shape on all 17
  WebSocket requests.
- Disabled Hyper's automatic downstream `Date` field so locally generated
  rejection responses are byte-stable, while application-supplied response
  fields continue through normal response policy.
- Latched every pre-validation upstream read error permanently and added a
  scripted `AsyncRead` regression proving a retry cannot release retained
  prefix bytes.
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
- Recorded a passing development-runtime run on WebView2 `150.0.4078.99`,
  including the clean profile-recreation gate and the three-contender,
  four-path listener-overlap gate. All three wildcard binds succeeded while
  all 32 exact-loopback requests reached the proxy and wildcard accepts
  remained zero. The same run passed both raw response baselines, all 16 HTTP
  and 16 WebSocket negative heads, 34 valid synthetic upstream credentials,
  17 normalized WebSocket upgrade requests, zero unexpected downstream
  upgrades, and zero forwarded attacker markers. This is not a fixed-minimum
  or release-readiness claim.

### Known pre-release gaps

- The full matrix has not run against a reviewed fixed minimum WebView2
  runtime.
- Forced-crash profile recreation has not yet proven that `P` is unrecoverable
  from disk.
- Browser escape controls are configured but have not all been exercised by
  real negative navigation, popup, download, scheme, devtools, extension, and
  debugger attempts.
- HTTP idle/body-rate and WebSocket byte-rate abuse, plus truncated and
  malformed streamed-upstream-body handling, are not finished. WebSocket
  activity-idle shutdown and malformed response-head rejection are already
  tested.
- Protocol-2 R launcher ownership and Windows Job Object lifecycle enforcement
  are Phase 2 work.
