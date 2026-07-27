# Changelog

All notable changes to this pre-release repository are documented here.

## Unreleased

### Phase 2 lifecycle foundation

- Added a safe non-executing resource-bundle crate. It bounds strict
  schema-1 JSON, rejects unknown fields and protocol downgrades, requires the
  complete authenticated protocol-2 Windows contract, and verifies installed
  dependency evidence before any R process can start.
- Added canonical critical-path containment with link/reparse rejection,
  fixed bundled-R/app topology checks, per-package `DESCRIPTION` evidence, and
  bounded launcher marker validation that rejects legacy argument,
  environment, URL-token, and wildcard-bind transports.
- Added an isolated Windows native-launch crate that supplies an explicit
  executable path to `CreateProcessW`, quotes arguments without a shell,
  allowlists only stdin/stdout/stderr lifecycle pipes, and creates the wrapper
  with `CREATE_SUSPENDED`.
- Added optional explicit Unicode launch environments with Windows ordinal
  case-insensitive identity and ordering, replacement/removal APIs, strict
  name/value validation, exact double-NUL serialization, value-free Debug
  output, and zeroization after `CreateProcessW`.
- Added an unnamed, non-inheritable Job Object with
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, exact policy readback, no breakaway
  flags, suspended assignment, process creation-time identity, membership
  verification, and resume only after all gates pass.
- Added live Job-member capture for a protocol-reported runtime PID. The
  non-inheritable handle records creation time, rejects zero/exited/outside-Job
  processes, and remains tied to the exact identity across later PID reuse.
- Added bounded IPv4/IPv6 Windows owner-PID table inspection. Listener
  verification requires one exact `127.0.0.1:<port>` row owned by the captured
  live Job member and rejects every missing or competing same-port row.
- Added native per-launch private directories with 128-bit random names and
  protected DACLs applied atomically at creation. Exact canonical readback
  requires only current-account and `SYSTEM` full-control allow entries.
- Added protected `CREATE_NEW` token/control files. Tokens are restricted to a
  bounded URL-safe ASCII line, the temporary native write buffer is zeroized,
  control files must be absent before signaling, and cleanup removes only
  known files plus the exact empty directory without recursive deletion.
- Added fail-before-execution cleanup for failed Job assignment plus native
  lifecycle tests for quoting, policy and identity, attempted breakaway,
  unrelated inheritable-handle exclusion, and kill-on-close removal of a
  wrapper and descendant.
- Added a cross-platform, bounded protocol-2 NDJSON decoder and lifecycle
  tracker. It rejects duplicate/unknown fields, wrong versions, weakened
  loopback or token claims, line overflow/truncation, PID/port changes,
  impossible transitions, and events after a terminal state.
- Added a Windows runtime owner that composes validated resources, sanitized
  bundled-R environment, protected token/control handoff, suspended Job
  launch, bounded pipe monitoring, exact runtime/listener ownership,
  authenticated readiness, graceful control-file shutdown, forced Job
  fallback, zero-active-process accounting, and retryable non-recursive
  cleanup.
- Added an executable synthetic-R lifecycle matrix covering graceful and
  forced close, owner drop, malformed protocol, readiness timeout, occupied
  port, post-readiness exit, environment isolation, and preserved audit-entry
  cleanup retry without downloading a runtime locally.
- Added a remote-only released portable-R/`hello-shiny` workflow. It pins both
  source commits and the existing runtime Release SHA-256, prepares the real
  bundle only under `runner.temp`, exercises authenticated content plus
  graceful/forced/crash/timeout/occupied-port/profile-isolation paths, uploads
  only two small secret-free JSON evidence files, and deletes the archive,
  extracted and copied runtimes, package libraries, Cargo target, and private
  sessions.
- Changed manual WebView2 runners to use a uniquely named system-temp Cargo
  target by default and remove it after completion. CI explicitly reuses its
  runner-owned repository target; only a caller-supplied target is retained.
- Kept the Phase 2 boundary explicit: generated native-metadata validation,
  proxy/WebView orchestration and a reviewed passing released-runtime workflow
  run remain in progress.

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
- Added independent raw-byte token buckets for both WebSocket directions.
  Defaults allow 8 MiB/s with one second of burst capacity per direction;
  empty buckets pause reads so the existing bidirectional copy applies
  backpressure without parsing frames or buffering complete messages. Invalid
  enabled burst windows are rejected before listeners bind, while a zero
  ceiling disables only shaping.
- Added a secret-free real-loopback WebSocket rate matrix with a small valid
  baseline and separate 100-byte upload and download cases at 100 B/s with a
  100 ms burst. Both shaped cases must last at least 750 ms and finish within
  four seconds; all 3 upstream handshakes must carry a valid synthetic
  credential in normalized form with zero proxy-cookie or bootstrap-header
  leakage.
- Added a request-upload body guard with a 64 MiB default cap, 15-second
  non-empty-frame idle timeout, 1 KiB/s floor in complete 5-second windows,
  5-minute total timeout, and fail-closed trailer/parser handling. A real
  loopback matrix proves one immediate valid upload plus independent streamed
  byte-cap, idle, below-rate, over-duration, and parsed-trailer terminations.
  Invalid enabled rate windows are rejected before proxy listeners bind.
- Added secret-free Windows overlap evidence for IPv4 wildcard, IPv6 v6-only
  wildcard, and IPv6 dual-stack wildcard contenders. The dual-stack contender
  remains alive across exact IPv4 and IPv6 probes. Each of the four traffic
  paths requires 8/8 proxy `401` responses and zero wildcard accepts. Bind
  success is recorded independently, while unexpected bind errors fail closed.
- Made paired IPv6/IPv4 ephemeral-port allocation retry bounded
  `AddrInUse` races. Parallel proxy starts now select a fresh candidate up to
  32 times, while every other listener configuration or bind error still fails
  immediately.
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
- Added a streaming upstream response-body guard that enforces declared and
  configured lengths, maps parser/read failures to fixed secret-free internal
  errors, and rejects every trailer frame without forwarding its fields.
  Declared trailers and an over-limit `Content-Length` fail before downstream
  head release; errors discovered after streaming begins terminate with
  incomplete framing and a non-reusable downstream connection. The cap
  measures the proxied, encoded HTTP body.
- Added independent upstream response idle and sustained-rate gates plus a
  decoded-content boundary. Defaults cap both encoded and decoded bodies at
  256 MiB, require a non-empty encoded frame within 15 seconds, and require
  1 KiB/s in each complete 5-second window. At most two ordered
  `gzip`/`x-gzip`, HTTP `deflate` (zlib), `br`, or `zstd` layers are decoded
  with backpressure. Unsupported/malformed encodings, encoded partial
  responses, `no-transform`, and decoded overflow fail closed; invalidated
  encoding, length, range, validator, and digest metadata is removed.
- Added secret-free real-loopback response-resource evidence for identity and
  gzip baselines plus five idle, below-rate, decompression-expansion,
  malformed-gzip, and unsupported-coding negatives. The expansion fixture is
  67 encoded bytes and 4,128 decoded bytes against a 32-byte test cap. Passing
  requires five bounded terminations, 7/7 valid synthetic credentials, and
  zero proxy-cookie, bootstrap-header, or attacker-marker leakage.
- Captured the upstream request method in response normalization. `HEAD` and
  `304` now preserve a hypothetical nonzero `Content-Length` without false
  truncation while their guard remains body-forbidden; `204` rejects
  `Content-Length` and `Transfer-Encoding`; `205` accepts empty framing or
  `Content-Length: 0` but rejects nonzero lengths or any `Transfer-Encoding`.
  All four semantics have a zero-byte streaming allowance.
- Added seven fragmented valid-body/semantics baselines and 23 raw loopback
  negative body cases covering truncated fixed-length bodies, malformed or
  incomplete chunks, malformed/protected/oversized/excess-count trailers,
  chunked and close-delimited limit overflow, forbidden framing or malicious
  bytes on `204` and `205`, and response-splitting bytes after a terminal
  chunk or `Content-Length`. Passing requires 6 exact `502` responses, 12
  bounded stream fail-closed terminations, 1 empty close-delimited cutoff, 2
  bodyless malicious-status terminations, 2 isolated first responses, and
  30/30 valid synthetic upstream credentials. The keep-alive isolation oracle
  also requires 30/30 second authenticated request attempts, 30/30 physical
  downstream closes before proxy shutdown, zero second responses, zero
  reusable downstream connections, and zero forwarded attacker markers.
- Refreshed the compatible Futures and Hyper stack together and validated the
  combined lockfile through the real WebView2 gate. `webview2-com` remains on
  `0.38.2` until Tauri/wry migrate their Windows COM type graph from 0.61 to
  0.62.
- Updated pinned GitHub Actions to their Node 24 releases and bounded CI job
  durations.
- Added a versioned reviewed Fixed Version Runtime manifest that separates the
  historical WebView2 API floor (`120.0.2210.55`) from the supported x64
  minimum (`149.0.4022.98`). It pins the official Microsoft source, CAB size
  and SHA-256, expanded 259-file tree size and domain-separated SHA-256,
  executable digest/version, signer subject, and certificate thumbprint.
- Added fail-closed native fixed-runtime verification and runtime evidence.
  Startup rejects ambient WebView2 overrides, unsafe/reparse paths, wrong
  architecture or package shape, and every content mismatch before changing
  the in-memory Tauri context to `FixedRuntime`. The forced-crash child
  receives only the non-secret reviewed path after all inherited WebView2
  overrides are removed, repeats verification, and independently configures
  Tauri. The report closes `fixed_minimum_webview2` only when the actual loaded
  version exactly matches the supported minimum.
- Added a fixed-runtime PowerShell runner that downloads the CAB from the
  pinned Microsoft CDN URL, verifies the archive and Authenticode evidence,
  runs Debug and Release with the repository Cargo target, validates both
  secret-free reports, and deletes its temporary 294 MB archive and 667 MB
  extracted runtime. CI now runs and uploads both fixed reports in addition to
  the development-runtime report.
- Added deterministic mock-upstream tests for bootstrap replay, malformed
  requests, Origin checks, redirects/cookies, WebSocket behavior,
  cross-instance isolation, hostname classification, and credential leakage.
- Added a real WebView2 acceptance harness for cookie flags, documents and
  subresources, fetches, delayed streaming, WebSocket cookie delivery, child
  hostname isolation, external redirects, process metadata, and clean
  shutdown, including same-data-directory profile recreation.
- Added a cross-process forced-crash profile matrix. A restricted
  same-executable producer receives no secret input, verifies the exact
  session cookie in a populated private profile, waits two seconds, and writes
  only an atomic hostname marker. The parent forcibly terminates it, proves a
  held graceful-cleanup sentinel never ran, reopens the same profile for the
  old hostname, requires `P` absent, destroys the recreation WebView, and
  requires complete profile-directory removal.
- Added an active browser-escape matrix. It attempts external top-level
  navigation, popup creation, a download, and an external URI scheme; requires
  the document request to be replaced before network access, popup and
  download denial, cancellation of every observed external-scheme event, and
  an empty isolated download directory; and confirms zero escape requests at
  external collectors. The native probe creates a random volatile per-user URL
  protocol whose same-executable handler writes only a strictly scoped canary,
  self-tests that handler, and requires an event whose empty
  `InitiatingOrigin` proves it came from native `Navigate`. Cancellation must
  leave the canary absent; the registration is explicitly removed and verified
  absent. Native evidence reads back disabled devtools, browser accelerators,
  and default context menus, actively requires a valid unpacked extension
  install to fail with `ERROR_NOT_SUPPORTED`, rejects WebView2 environment and
  policy-registry overrides before bootstrap, repeats policy checks after
  creation, and requires no `DevToolsActivePort` in the profile.
- Recorded a passing development-runtime run on WebView2 `150.0.4078.99`,
  including the clean profile-recreation gate and the three-contender,
  four-path listener-overlap gate. All three wildcard binds succeeded while
  all 32 exact-loopback requests reached the proxy and wildcard accepts
  remained zero. The same run passed both raw response baselines, all 16 HTTP
  and 16 WebSocket negative heads, 34 valid synthetic upstream credentials,
  17 normalized WebSocket upgrade requests, zero unexpected downstream
  upgrades, and zero forwarded attacker markers. It also passed the immediate
  request-upload baseline, all five bounded byte/idle/rate/total/trailer
  negatives, 5/5 parsed synthetic upstream credentials, and zero request-probe
  credential leaks. It also passed the identity and gzip response-resource
  baselines, all five bounded idle/rate/expansion/malformed/unsupported
  negatives, 7/7 synthetic credentials, and zero credential or marker leaks;
  the 67-to-4,128-byte expansion case forwarded zero decoded bytes across its
  32-byte test cap. It also passed the WebSocket rate baseline plus both
  independent directional bounds with 3/3 valid normalized upstream
  handshakes and zero credential leakage; both debug and release runs measured
  997 ms client-to-upstream and 934 ms upstream-to-client. The same runtime
  passed the browser-escape matrix with one document network block, one popup
  denial, one download cancellation, one cancelled native external-scheme
  event with no canary launch, a removed volatile protocol registration, an
  empty download directory, and zero external collector requests. Its
  cross-process forced-crash producer also proved cookie presence before
  termination, absence after same-profile recreation, bypass of graceful
  cleanup, and complete profile removal with no secret-shaped report content.
  This is not a fixed-minimum or release-readiness claim.
- Recorded passing Debug and Release matrices on the exact reviewed Fixed
  Version Runtime `149.0.4022.98`. Both reports verified the committed
  manifest and expanded tree, loaded the exact runtime, passed every
  development and forced-crash/browser-escape gate, contained no secret
  shape, had zero unproven gates, and set `phase1_release_ready` to true.
  WebSocket shaping measured 1,007/934 ms in Debug and 1,006/921 ms in
  Release, with 3/3 valid normalized handshakes and no credential leakage.

### Known pre-release gaps

- The released portable-R/`hello-shiny` workflow needs a reviewed passing run,
  and the production Tauri owner still needs to compose this R lifecycle with
  the authenticated proxy/WebView shutdown sequence.
