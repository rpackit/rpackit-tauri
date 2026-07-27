# rpackit-tauri

Maintained native Tauri templates and the security-critical loopback transport
for [rpackit](https://github.com/rpackit/rpackit).

The repository contains the completed Windows **Phase 1 transport spike** and
a fail-closed **Phase 2 native application-owner milestone**. A maintained
development shell now composes the authenticated proxy, released
portable-R/`hello-shiny` process lifecycle, hidden hardened WebView, native
bootstrap, host-only session, window-close handling, and bounded profile
cleanup. Its real-runtime remote gate passes. It remains an executable
acceptance harness, not a generated end-user application or supported
installer. The authoritative contract is
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
and 921 ms. This closes the Phase 1 fixed-minimum gate; it does not close the
full Phase 2 R launcher lifecycle.

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

## Phase 2 process-owner foundation

`crates/resource-bundle` now performs the required non-executing startup
validation before any R process is created. It bounds and strictly deserializes
`resources/rpackit.json`, rejects unknown fields and every schema/protocol
downgrade, accepts only the authenticated protocol-2 Windows topology, and
requires installed dependency evidence. Every critical manifest path is
resolved below the canonical resource root with links and Windows reparse
points rejected. The validator also matches the declared Shiny layout, checks
every package directory and `DESCRIPTION`, and bounds the generated launcher
before requiring its current token-consumption, loopback, authentication,
listening-event, and secret-transport markers. It never executes R,
`launcher.R`, or application code.

`crates/windows-launcher` now owns the small audited unsafe boundary needed to
start a bundled Windows process tree. It:

- requires explicit absolute executable and working-directory paths and calls
  `CreateProcessW` with the executable in `lpApplicationName`, without a
  command shell;
- can replace ambient inheritance with a validated explicit Unicode
  environment block whose names are unique and sorted by Windows'
  locale-independent case-insensitive ordering; malformed names/values are
  rejected, values are omitted from Debug output, and the serialized block is
  zeroized after process creation;
- creates the wrapper suspended and supplies an explicit inherited-handle
  allowlist containing only closed stdin plus stdout/stderr lifecycle pipes;
- creates an unnamed, non-inheritable Job Object, enables
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, reads the policy back, and rejects
  either breakaway flag;
- assigns the still-suspended wrapper to the Job, records PID plus process
  creation time, verifies membership through the exact process handle, and
  resumes only after every gate succeeds;
- can open a separately reported positive runtime PID with a non-inheritable,
  create-time-aware process handle, rejecting an exited process or any process
  outside this launch's Job;
- reads Windows' IPv4 and IPv6 owner-PID listener tables and accepts only one
  exact `127.0.0.1:<port>` row owned by that captured live Job member, with no
  competing listener on the selected port;
- creates a cryptographically random per-launch directory with
  [`CreateDirectoryW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw)
  and an atomic protected DACL containing exactly full-control allow entries
  for the current account and `SYSTEM`;
- creates the token and control files with `CreateFileW(CREATE_NEW)` and the
  same protected two-principal file DACL, writes `S` only as one URL-safe line
  in the token file, zeroizes the temporary write buffer, and reads every DACL
  back through `GetNamedSecurityInfoW`; and
- terminates the suspended child before execution if Job assignment fails,
  while closing the owned Job kills the complete remaining process tree. Its
  cleanup API removes only the two fixed files and then the exact empty
  session directory; it never recursively deletes an unexpected entry.

Windows tests prove argument preservation through paths and values containing
spaces, quotes, and trailing backslashes; exact Job-policy readback; failed
assignment before execution; rejection of an attempted breakaway child;
exclusion of an unrelated inheritable handle; and removal of both a wrapper
and its descendant when the Job closes. The same tree test captures exact
handles for both processes, rejects the test runner as an outside-Job PID, and
observes both captured identities terminate after Job close. A real
IPv4-loopback listener test independently matches its Windows owner-PID table
row to the captured identity. Explicit-environment tests prove Unicode value
preservation, case-insensitive replacement, ambient `PATH` removal, Windows
sorting, exact double-NUL termination, malformed-field rejection, and
value-free Debug output. Private-session tests cover paths with spaces,
exact token contents, DACL readback, absent-then-atomic control creation,
duplicate rejection, invalid input without residue, launcher-style token
deletion, and preservation of an unexpected audit entry during cleanup.
Cross-platform resource-bundle tests separately cover strict valid loading,
unknown fields and contract downgrades, unsafe paths, local and HTTPS
provenance, incomplete dependencies, missing installed-package evidence,
launcher tampering, application-layout disagreement, size limits, and
symlinked critical resources on platforms that support deterministic symlink
creation.

`crates/launcher-protocol` provides the safe protocol-2 boundary shared by
later lifecycle owners. Its streaming decoder bounds every stdout line,
discards non-prefixed output without retaining its content, rejects malformed
JSON, duplicate or unknown fields, wrong protocol versions, weak host/token
claims, and partial final lines, then permanently poisons itself after a hard
failure. Its state tracker requires one matching
`starting -> listening -> stopping? -> stopped` sequence with a stable
positive runtime PID, selected port, and exact graceful-stop policy; `error`
is terminal. Error display text is length-bounded and control characters are
collapsed.

`crates/windows-lifecycle` now composes those foundations into one Windows
runtime owner. It validates the bundle before creating a session, removes
ambient R/rpackit variables, pins `R_HOME`, every R library variable, protocol
2, and the bundled `R/bin/x64` plus `R/bin` paths, writes `S` only to the
protected token file, bypasses the top-level Windows `Rscript.exe` command-shell
wrapper, and launches the actual x64 interpreter exactly:

```text
R/bin/x64/Rscript.exe --vanilla launcher.R --app <path> --port <port>
  --token-file <private-path> --control <private-path>
```

Canonical paths remain the validation identity. Before any path reaches R,
the lifecycle owner removes only supported Windows verbatim prefixes and
canonicalizes the resulting ordinary path again to prove that it names the
same validated object. This avoids passing `\\?\` paths to R while preserving
the fail-closed containment decision.

The owner drains stderr without retaining text and feeds stdout only to the
bounded protocol decoder. It returns from startup only after token deletion,
the matching post-bind `listening` event, create-time-aware Job-member capture,
exact owner-PID listener verification, and a direct HTTP 2xx/3xx response
authenticated with `S`. `poll_health()` checks both exact process handles.
`shutdown()` creates the protected control file, waits a bounded graceful
period, terminates the whole Job as fallback, requires zero active Job
members, joins both pipe monitors, and removes only the known session files
and now-empty directory. An unexpected entry is preserved and
`retry_private_cleanup()` keeps cleanup explicit and retryable.

`NativeAppOwner` is the higher-level native-shell boundary. It validates the
bundle, generates one independent `S`/`P`/`B` set, selects the R port, binds
the authenticated proxy, classifies the random `.localhost` hostname, and
then launches the already validated R bundle with the same `S`. It returns
only after authenticated R readiness. Its `BrowserLaunch` value exposes the
random proxy address plus native-only `P` and `B` handles, never `S`; Debug
output redacts both credentials. Runtime-health failure stops the proxy before
forced Job cleanup, forced shutdown and owner drop also stop browser traffic
first, and graceful close cleans the runtime before draining the proxy.
Retryable private-session cleanup remains owned rather than silently discarded.

`crates/windows-webview` adds the browser-side owner. Preflight rejects
application-identity mismatches, untrusted WebView2 environment or registry
policy overrides, and runtimes below the reviewed minimum before R starts.
After native readiness it creates one hidden WebView with a random per-launch
profile, installs native navigation and escape guards, sends `B` only through
the exact initial native request, verifies the resulting `P` cookie and flags,
navigates to the authenticated application root, and then shows the window.
Shutdown hides the window, deletes `P`, queues the browsing-data clear request,
destroys the WebView, and removes only the exact scoped profile with bounded
retries.

`apps/windows-shell` is the thin event-loop composition layer. It intercepts
window and application close requests, hides the UI, shuts down
`NativeAppOwner`, then finishes WebView/profile cleanup. It emits only bounded,
path-free, secret-free boolean evidence. It is maintained infrastructure for
the future generator, not the generated application itself.

A synthetic `Rscript.exe` acceptance fixture passes authenticated startup,
graceful close, forced fallback when control is ignored, owner-drop
termination, malformed protocol, readiness timeout, occupied-port rejection,
post-readiness process exit detection, and non-recursive cleanup retry. The
fixture also verifies the actual isolated child environment. Separate
composition tests prove one-time bootstrap, authenticated proxy forwarding,
missing-session rejection, proxy-first crash cleanup, zero tracked sessions,
and listener closure. These fixtures contain no portable R and are not a
substitute for the released-runtime gate.

The separate `Released portable R lifecycle gate` workflow is the real-runtime
boundary. It runs only on GitHub-hosted Windows, checks out pinned rpackit and
`hello-shiny` commits, downloads the existing portable-R `v4.6.1` prerelease,
verifies its published SHA-256, and prepares a dependency-complete bundle in a
unique `runner.temp` directory. An explicitly ignored Rust acceptance target
then proves the real page loads only with `S`, missing and wrong credentials
receive `403`, graceful and forced Job shutdown leave zero members, owner drop
removes the process tree and private session, an exact runtime crash is
detected, a one-millisecond startup deadline fails closed, an occupied port
does not disturb its contender, the directly launched interpreter is the
protocol-reported runtime, and an ambient hostile R profile does not run. It
also drives the real page through `NativeAppOwner` and the maintained Tauri
shell: native `B` bootstrap establishes the exact `P` session, the real
application document finishes, and automated close verifies graceful runtime
shutdown, proxy closure, an empty Job, private-session removal, cookie
deletion, acceptance of the browsing-data clear request, window destruction,
and exact profile removal.

Only three bounded, path-free, secret-free JSON files are retained for seven
days. The downloaded archive, extracted runtime, copied bundle, package
libraries, Cargo target, profiles, and sessions are deleted together before
the runner finishes. The
[reviewed full-owner run 30237185375](https://github.com/rpackit/rpackit-tauri/actions/runs/30237185375)
closes the real-R native application-owner milestone. It does not claim a
generated application, installer, clean-machine installation, or signing.

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

Build either maintained Windows acceptance shell without producing an
installer:

```powershell
Set-Location apps/windows-spike
cargo tauri build --no-bundle

Set-Location ..\windows-shell
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
temporary archive and runtime. When run manually, both runners now use one
uniquely named system-temp Cargo directory and remove it after the process
exits. CI explicitly passes its existing runner-scoped Cargo target so the
Debug and Release matrices can reuse remote build output. A maintainer can
still pass `-TargetDirectory` deliberately, in which case that caller-owned
directory is retained.

Do not run the released portable-R gate locally. Its ignored test and
preparation script both require `GITHUB_ACTIONS=true`; the workflow owns all
large inputs in `runner.temp` and removes that complete verified subtree.
Portable runtime archives intended for users belong in
[GitHub Releases](https://github.com/rpackit/runtime-win/releases), not this
working tree.

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

## Versioned generated-project source

`templates/windows-v1/template.json` is the machine-readable boundary used by
the rpackit project generator. It pins transport contract 2, resource schema
1, launcher protocol 2, the reviewed Rust/Tauri/wry/WebView2 minima, the
application shell, and the six runtime crates needed by a generated project.
`templates/windows-v1/Cargo.toml` is the reduced generated-project workspace;
the acceptance spike and testkit are deliberately absent.

A `windows-template-v*` tag publishes one SHA-256-addressed source ZIP from
the exact Git tree. The asset is generator input only. It contains no
executable, installer, portable R runtime, or end-user release.

## Status

This repository remains pre-release because it is an acceptance spike, but
Phase 1 is complete: the development runtime and the exact reviewed Fixed
Version Runtime `149.0.4022.98` both passed the complete matrix in Debug and
Release. The fixed reports have `development_gates_passed: true`,
`phase1_release_ready: true`, and an empty `unproven_release_gates` object.

Phase 2 now has strict schema-1 resource validation, verified Windows
Job/process creation, exact runtime PID/listener capture, strict protocol-2
decoding, atomically restricted token/control files, an authenticated
proxy/runtime owner, and a maintained Tauri WebView/window/profile owner with
deterministic close handling. The remote-only released
portable-R/`hello-shiny` workflow owns the real-runtime matrix and all of its
temporary storage. Its
[reviewed run 30237185375](https://github.com/rpackit/rpackit-tauri/actions/runs/30237185375)
passed the direct, proxied, and real WebView-owner paths plus complete cleanup.
Resource-driven application generation, installers, clean-machine
verification, and signing are later milestones. See
[ARCHITECTURE.md](ARCHITECTURE.md) for component boundaries and evidence
interpretation.
