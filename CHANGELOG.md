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
  upgrades, and zero forwarded attacker markers. It also passed the immediate
  request-upload baseline, all five bounded byte/idle/rate/total/trailer
  negatives, 5/5 parsed synthetic upstream credentials, and zero request-probe
  credential leaks. It also passed the identity and gzip response-resource
  baselines, all five bounded idle/rate/expansion/malformed/unsupported
  negatives, 7/7 synthetic credentials, and zero credential or marker leaks;
  the 67-to-4,128-byte expansion case forwarded zero decoded bytes across its
  32-byte test cap. This is not a fixed-minimum or release-readiness claim.

### Known pre-release gaps

- The full matrix has not run against a reviewed fixed minimum WebView2
  runtime.
- Forced-crash profile recreation has not yet proven that `P` is unrecoverable
  from disk.
- Browser escape controls are configured but have not all been exercised by
  real negative navigation, popup, download, scheme, devtools, extension, and
  debugger attempts.
- WebSocket byte-rate abuse remains unfinished. Authenticated request-upload
  byte/idle/rate/total/trailer limits, encoded and decoded response-body caps,
  response idle/rate/content-decoding limits, WebSocket activity-idle
  shutdown, and malformed response-head/body rejection are tested.
- Protocol-2 R launcher ownership and Windows Job Object lifecycle enforcement
  are Phase 2 work.
