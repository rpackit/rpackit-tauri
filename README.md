# rpackit-tauri

Maintained native Tauri templates and the security-critical loopback transport
for [rpackit](https://github.com/rpackit/rpackit).

The repository currently contains the completed Windows **Phase 1 transport
spike**. It is an executable acceptance harness, not a supported application
generator or installer. The authoritative contract is
[`TAURI_SECURE_TRANSPORT.md`](https://github.com/rpackit/roadmap/blob/main/TAURI_SECURE_TRANSPORT.md);
this implementation follows transport contract version 2.

## Contract at a glance

Each launch creates three independent 256-bit secrets:

| Value | Purpose | Allowed exposure |
| --- | --- | --- |
| `S` | Authenticates the proxy to the fixed Shiny upstream | Native proxy and exactly one upstream `Shiny-Shared-Secret` field |
| `P` | Authenticates browser HTTP and WebSocket traffic to the proxy | Native proxy and an HttpOnly, host-only WebView session cookie |
| `B` | Authorizes cookie bootstrap | Native shell and one exact, initial bootstrap request header; consumed once |

The random `rpackit-<nonce>.localhost` hostname is an origin-isolation nonce,
not a credential. No secret value belongs in JavaScript, a URL, process
arguments, environment variables, logs, reports, fixtures, or committed
resources.

The startup sequence is deliberately narrow:

1. The shell creates a hidden WebView2 with an isolated per-launch profile and
   binds the proxy only on IPv4 and IPv6 loopback.
2. Native code uses WebView2
   [`CreateWebResourceRequest`](https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/win32/icorewebview2environment2)
   and
   [`NavigateWithWebResourceRequest`](https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/win32/icorewebview2_2)
   to send `B` in the exact initial bootstrap request. This is not a general
   request interceptor.
3. The proxy authenticates and atomically consumes `B`, never dials the
   upstream for this route, and returns a fixed loading document with
   `Set-Cookie: rpackit_proxy_v1=...; Path=/; HttpOnly; SameSite=Strict`.
   Omitting `Domain` makes `P` genuinely host-only.
4. Native code verifies the cookie through readback, navigates to `/`, and
   shows the window only after the authenticated application root is ready.
5. Every application HTTP request and WebSocket upgrade must authenticate
   `P` before an upstream connection is opened. The proxy strips `P` and `B`,
   fixes the upstream authority, and injects exactly one `S`.

Missing, wrong, duplicated, malformed, or replayed bootstrap credentials fail
closed and create neither a cookie nor an upstream request.

## Why the bootstrap response sets the cookie

The initial implementation tried Tauri's high-level native cookie setter. In
the development machine's WebView2 runtime, that call produced no host-only
cookie on readback. This is consistent with WebView2's documented
[`AddOrUpdateCookie`](https://learn.microsoft.com/en-us/dotnet/api/microsoft.web.webview2.core.corewebview2cookiemanager.addorupdatecookie)
behavior: adding a cookie fails when its domain is unspecified. Supplying a
domain would create a domain cookie and would not satisfy the host-only
boundary.

Contract v2 therefore lets the browser process an ordinary HTTP `Set-Cookie`
field without `Domain`, while `B` prevents an unauthenticated local process
from obtaining `P`. The native WebView2 request API is used only to carry `B`
on that one navigation; JavaScript never handles either value.

## What the spike tests

The deterministic testkit covers admission and framing rejection, bootstrap
authentication and replay, Origin enforcement, document/assets, GET and
unsafe POST fetches, delayed streaming, redirects, application cookies,
WebSocket upgrade and echo, concurrent-instance isolation, and credential
leakage using loopback-only mock services.

Passing unit and headless integration tests does **not** establish browser
cookie behavior. `apps/windows-spike` drives a real WebView2 instance and
reports each empirical gate separately. The recorded development-runtime pass
on WebView2 `150.0.4078.99` established:

- the authenticated bootstrap, exact host-only/HttpOnly/Strict session cookie
  readback, application root, CSS, JavaScript, image, GET, unsafe POST,
  delayed stream, and WebSocket echo all completed;
- every observed upstream request carried exactly one valid `S`, while `P`,
  `B`, forwarding headers, and WebSocket extension offers did not reach the
  upstream;
- the request-upload baseline passed, all five byte/idle/rate/total/trailer
  negatives terminated boundedly, and all five parsed upstream requests
  carried one valid synthetic `S` with zero proxy-cookie or bootstrap-header
  leaks;
- the response-resource identity and gzip baselines passed, all five
  idle/rate/expansion/malformed/unsupported negatives terminated boundedly,
  the 67-byte compressed fixture expanded to 4,128 bytes but forwarded zero
  bytes across its 32-byte decoded cap, and all 7 requests carried one valid
  synthetic `S` with zero credential or marker leakage;
- the WebSocket byte-rate baseline passed, both independent 100-byte
  directional cases respected a 100 B/s ceiling with a 100 ms burst and
  bounded completion (997 ms client-to-upstream and 934 ms
  upstream-to-client), and all 3 upstream handshakes carried one valid
  synthetic `S` in normalized form with zero proxy-cookie or bootstrap-header
  leakage;
- JavaScript observed neither `P` nor a secret-shaped value, the child
  hostname received no proxy cookie, and an external redirect collector
  received no credential;
- active browser-escape probes attempted external top-level navigation, a
  popup, a download, and a `mailto:` launch. The external document was
  replaced locally before network access, the popup and download were denied,
  and the page-origin scheme launch was denied. A random per-run volatile
  per-user URL protocol was self-tested with a scoped same-executable canary;
  its one native-origin WebView2 event was cancelled, the handler marker
  remained absent, and the registration was removed and verified absent. The
  isolated download directory stayed empty, and both external collectors
  received zero escape requests;
- native readback confirmed devtools, browser accelerator keys, and default
  context menus disabled. A valid unpacked-extension install was explicitly
  rejected as unsupported, WebView2 environment and policy-registry overrides
  were absent before and after creation, and the profile contained no
  `DevToolsActivePort`;
- process arguments and environment were secret-free, and clean shutdown
  removed the session cookie, queued browsing-data cleanup, and destroyed the
  WebView; recreating a WebView with the same data directory after clean
  shutdown found no reusable `P`;
- a separate same-executable producer verified `P` in a populated private
  profile, settled for two seconds, and was forcibly terminated by its parent.
  The graceful-cleanup sentinel remained absent; recreating a WebView with the
  same profile and old hostname found no `P`, destroyed cleanly, and allowed
  the entire profile directory to be removed. The child received no secret
  input and its hostname-only control marker contained no secret shape.

The harness exited `0` with `development_gates_passed: true`. This evidence is
specific to the recorded runtime and machine; a different runtime must produce
its own passing report.

The same complete matrix subsequently passed in both Debug and Release against
the reviewed x64 Fixed Version Runtime `149.0.4022.98`. Both reports loaded
that exact version, verified the committed manifest and expanded runtime tree,
contained no secret shape, had no unproven release gates, and recorded
`phase1_release_ready: true`. The Debug WebSocket rate cases measured 1,007 ms
client-to-upstream and 934 ms upstream-to-client; Release measured 1,006 ms
and 921 ms. This closes the Phase 1 fixed-minimum gate; it does not implement
the Phase 2 R launcher lifecycle.

On this Windows installation, the system/Tokio DNS probe returned
`unavailable` for the random `.localhost` subdomain. That is not treated as
proof that arbitrary system resolvers support the name. The WebView boundary
instead relies on [RFC 6761 section 6.3](https://www.rfc-editor.org/rfc/rfc6761.html#section-6.3),
which reserves every name under `.localhost` for loopback, and Chromium's
source-level rule to
[`Always treat .localhost as loopback`](https://chromium.googlesource.com/chromium/src/+/5d131a1fd9b808c5fd08c45f8299e669b13ec393%5E%21/).
[WebView2 uses the Microsoft Edge/Chromium runtime](https://learn.microsoft.com/en-us/microsoft-edge/webview2/).
The shell rejects untrusted WebView2 environment overrides that can replace
the runtime, profile, channel, or browser arguments. Fixed-runtime mode first
verifies the exact reviewed package and then asks Tauri to set the one expected
browser-folder override before runtime creation. It also checks the machine
and user WebView2 policy-registry views for the application, executable, and
wildcard identities before and after WebView creation. A system probe that
ever observes a non-loopback answer stops before a WebView or `B` request is
created.

The real WebView also loaded the authenticated bootstrap and application
through a proxy that listens only on loopback and rejects any non-loopback
peer and incorrect `Host`. This is runtime evidence that the recorded WebView2
reached the loopback-only endpoint; it is not a claim that the separate
system/Tokio resolver supports arbitrary `.localhost` subdomains. There is no
stable-host fallback.

## Development

Required Windows baseline:

- Rust `1.97.1-x86_64-pc-windows-msvc`
- Visual Studio 2022 C++ desktop workload and Windows SDK
- Tauri CLI `2.11.4`
- Tauri crate `2.11.5`
- WebView2 Runtime `149.0.4022.98` or newer; the reviewed Phase 1 minimum is
  tested separately as an exact Fixed Version package

Install the pinned CLI:

```powershell
cargo install tauri-cli --version 2.11.4 --locked
```

Run the deterministic core checks:

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Build the Windows shell without producing an installer:

```powershell
Set-Location apps/windows-spike
cargo tauri build --no-bundle
```

Run the real WebView2 acceptance harness:

```powershell
.\tests\run-webview2.ps1
```

Run the reviewed fixed-minimum Debug and Release matrices:

```powershell
.\tests\run-webview2-fixed.ps1
```

The fixed runner downloads the x64 package from the pinned Microsoft CDN URL,
checks the archive length and SHA-256, extracts it with `expand.exe`, verifies
the exact 259-file/667,247,853-byte tree digest, executable digest, file
version, Microsoft signer and certificate thumbprint, and then deletes the
temporary archive and runtime. Both runners reuse the repository Cargo
`target` directory by default instead of creating another multi-gigabyte
temporary build cache.

The harness exits nonzero when a required gate fails and writes only
secret-free JSON reports to caller-selected temporary paths. No report,
runtime archive, extracted runtime, profile, or build product belongs in Git.

Listener ownership is a measured Windows development gate. After the proxy
owns exact IPv4 and IPv6 loopback addresses, the harness tries three same-port
`SO_REUSEADDR` contenders: IPv4 wildcard, IPv6 v6-only wildcard, and IPv6
dual-stack wildcard. The dual-stack contender stays alive while both exact
IPv4 and exact IPv6 are tested. Every one of the four traffic paths receives
eight real requests. A wildcard bind may succeed; the gate passes only when
all 32 requests receive the proxy's expected `401` and all wildcard listeners
accept zero connections. Bind outcomes and counts are recorded without
credentials. On the recorded development run all three wildcard binds
succeeded, all 32 exact-loopback requests returned `401`, and wildcard accepts
remained zero.

Authenticated request uploads have their own fail-closed streaming guard after
proxy authentication and before the fixed upstream. Defaults allow at most
64 MiB, require each non-empty data frame to arrive within 15 seconds, require
at least 1 KiB/s in every complete 5-second window, and stop one body after
5 minutes. Bodies that finish before a rate window ends are not padded to a
minimum size. Request trailers, parser failures, byte-limit overflow, idle
uploads, below-rate uploads, and over-duration uploads terminate the upstream
request with a fixed secret-free internal error. A zero rate explicitly
disables only the rate floor; invalid enabled rate windows are rejected at
proxy startup. The loopback suite proves an immediate bounded upload and
separate streamed byte-cap, idle, below-rate, total-time, and trailer
negatives. The real WebView2 harness serializes the same secret-free evidence
and includes it in
`development_gates_passed`.

Malformed upstream response heads are a separate fail-closed development
gate. Before Hyper receives any upstream response byte, the proxy requires
strict CRLF framing, HTTP/1.1, and bounded header bytes and count. If framing
fields are present, the response may have one decimal `Content-Length` or
exactly `Transfer-Encoding: chunked`, never both. Ordinary HTTP rejects
unsolicited protocol switches; the WebSocket path admits a raw `101` only for
its exact structured handshake validation.

The raw loopback attacker harness proves separate valid HTTP and WebSocket
baselines, including one tunneled WebSocket frame. It then runs 16 ordinary
HTTP variants and 16 WebSocket `101` variants. The ordinary matrix covers
conflicting framing, unsupported transfer codings, lenient syntax, header
limits, unsafe connection/redirect/cookie fields, and an unsolicited switch.
The WebSocket matrix adds forbidden `101` framing, ambiguous or incorrect
handshake fields, unoffered subprotocols, extensions, and a protected
connection nomination. Every parser-valid unsafe head contains an attacker
canary and every WebSocket negative includes a valid attacker frame.

Passing requires all 32 negatives to become the exact static `502` header set
and `Upstream rejected` body, with no downstream upgrade and no canary or frame
bytes. Hyper's automatic `Date` field is disabled so locally generated
rejections are byte-stable; unexpected headers fail the oracle. All 34
upstream requests must carry one valid synthetic `S`, and all 17 WebSocket
requests must also have the exact normalized upstream upgrade shape. The
recorded WebView2 `150.0.4078.99` run passed both baselines, all 32 negatives,
34/34 synthetic credentials, 17/17 normalized WebSocket requests, zero
downstream upgrades, and zero forwarded markers.

Malformed and truncated ordinary HTTP bodies have a separate streaming gate.
The proxy rejects a declared trailer or an over-limit `Content-Length` before
releasing the downstream response head. Once streaming begins, it enforces the
declared and configured byte limits, converts upstream parser/read failures to
fixed secret-free internal errors, and rejects trailer frames without
forwarding their fields. Because a response head cannot be replaced after it
has been released, those streaming failures are required to close before head
serialization or end with detectably incomplete framing and
`Connection: close`, not a synthetic 502. Which of those two safe outcomes
occurs can depend on whether the downstream server polls the failed body
before writing its head. The one close-delimited overflow case is cut off with
an empty body and a non-reusable connection because closing is itself that
response's delimiter. This first byte cap measures the proxied, encoded HTTP
body. A separate decoded-content boundary prevents a small compressed body
from expanding past the configured final-representation limit.

Upstream responses also have independent resource clocks and controlled
content decoding. Defaults cap both the encoded body and final decoded
representation at 256 MiB, require a non-empty encoded frame within 15
seconds, and require at least 1 KiB/s in every complete 5-second window.
Bodies that finish within their current window pass without a minimum-size
rule, and a zero rate disables only that floor. The proxy supports at most two
ordered `gzip`/`x-gzip`, HTTP `deflate` (zlib), `br`, or `zstd` layers,
decodes them in reverse application order with backpressure, and never
forwards a decoded frame that crosses the final cap. Codec failures are
replaced by fixed secret-free errors. After transformation it removes
`Content-Encoding`, `Content-Length`, range metadata, representation
validators, and digest fields that no longer describe the downstream bytes.
Encoded partial responses and encoded responses carrying
`Cache-Control: no-transform` fail before downstream head release.

The real-loopback resource matrix proves an immediate identity baseline and
an exact gzip-decoding baseline, then independently cuts off idle,
below-rate, decompression-expansion, malformed-gzip, and unsupported-coding
cases. Its expansion fixture is 67 encoded bytes and 4,128 decoded bytes
against a 32-byte test limit. All five negatives terminate boundedly, all
seven upstream requests carry one valid synthetic `S`, and no proxy cookie,
bootstrap header, or attacker marker crosses either boundary. The WebView2
report serializes this evidence as `response_resource_limits` and includes it
in `development_gates_passed`.

Upgraded WebSocket tunnels keep the five-minute activity-idle watchdog and add
independent raw-byte token buckets for client-to-upstream and
upstream-to-client traffic. The default ceiling is 8 MiB/s in each direction
with one second of burst capacity. WebSocket frame bytes and payload bytes
consume the same budget. When a bucket is empty, reads pause and
`copy_bidirectional` applies backpressure; the proxy does not parse frames,
accumulate an unbounded message, or forward bytes beyond the current
allowance. A zero ceiling disables only rate shaping. An enabled burst window
must be nonzero and no longer than the idle timeout or proxy startup fails
before listeners bind.

The loopback rate matrix proves a small authenticated baseline followed by
independent upload and download cases. Each case transfers a 100-byte
application payload under a 100 B/s ceiling and 100 ms burst window, must take
at least 750 ms, and must finish within four seconds. Passing also requires all
3 upstream handshakes to carry one valid synthetic `S`, all 3 requests to have
the normalized WebSocket shape, and zero `P` or `B` leakage. The WebView2
report serializes this evidence as `websocket_rate_limits`; the
`websocket_byte_rates_bounded` development gate requires the complete matrix.
The recorded WebView2 `150.0.4078.99` debug and release runs both passed with
997 ms client-to-upstream and 934 ms upstream-to-client delivery, 3/3 valid
normalized upstream handshakes, and zero credential leaks.
The reviewed Fixed Version Runtime `149.0.4022.98` also passed in Debug at
1,007/934 ms and Release at 1,006/921 ms, again with all 3 handshakes valid and
normalized and no credential leakage.

The ordinary forwarder captures the request method before sending it upstream.
Responses to `HEAD` and `304 Not Modified` retain a nonzero hypothetical
`Content-Length` without treating the absent body as truncation, while their
body guard still permits zero streamed bytes. A `204 No Content` likewise
permits no body, and any `Content-Length` or `Transfer-Encoding` on that status
is rejected before downstream head release. `205 Reset Content` is also
body-forbidden: an empty response or `Content-Length: 0` is accepted, a
nonzero length or any `Transfer-Encoding` is rejected before release, and
unframed malicious body bytes are dropped. Rejecting every transfer coding on
`205`, including a nominally empty chunked message, avoids ambiguous
stream/trailer framing on a status that must not carry content.

The raw loopback body matrix first proves fragmented valid
`Content-Length`, chunked, and close-delimited baselines plus bodyless `HEAD`
and `304` baselines with nonzero hypothetical lengths, a bodyless `204`
without framing, and a bodyless `205` with `Content-Length: 0`. Twenty-three
negatives then cover truncated fixed-length bodies, invalid/overflowing chunk
sizes, truncated chunks, missing delimiters or terminal chunks,
malformed/protected/oversized/excess-count trailers, chunked and
close-delimited streamed-limit overflow, forbidden framing or malicious bytes
on `204` and `205`, and bytes after a terminal chunk or complete fixed-length
response. Passing requires 6 exact pre-stream 502 responses, 12 bounded
stream fail-closed terminations, 1 bounded empty close-delimited cutoff, 2
bodyless malicious-status terminations, and 2 isolated safe first responses.
All 30 first upstream requests must carry one valid synthetic `S`. The client
also attempts a second authenticated request on every keep-alive downstream
socket: all 30 sockets must physically close before proxy shutdown, no second
response may arrive, and no attacker marker or reusable connection may
result. The response-splitting and no-body fixtures deliberately omit an
upstream `Connection: close` where applicable, so this proves proxy-enforced
downstream closure rather than inherited upstream advice.

## Status

This repository remains pre-release because it is an acceptance spike, but
Phase 1 is complete: the development runtime and the exact reviewed Fixed
Version Runtime `149.0.4022.98` both passed the complete matrix in Debug and
Release. The fixed reports have `development_gates_passed: true`,
`phase1_release_ready: true`, and an empty `unproven_release_gates` object.

Protocol-2 R launcher ownership and Windows Job Objects belong to Phase 2;
resource generation and installers are later milestones. See
[ARCHITECTURE.md](ARCHITECTURE.md) for component boundaries and evidence
interpretation.
