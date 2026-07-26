# rpackit-tauri

Maintained native Tauri templates and the security-critical loopback transport
for [rpackit](https://github.com/rpackit/rpackit).

The repository currently contains the Windows **Phase 1 transport spike**. It
is an executable acceptance harness, not a supported application generator or
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
- JavaScript observed neither `P` nor a secret-shaped value, the child
  hostname received no proxy cookie, and an external redirect collector
  received no credential;
- process arguments and environment were secret-free, and clean shutdown
  removed the session cookie, queued browsing-data cleanup, and destroyed the
  WebView; recreating a WebView with the same data directory after clean
  shutdown found no reusable `P`.

The harness exited `0` with `development_gates_passed: true`. This evidence is
specific to the recorded runtime and machine; a different runtime must produce
its own passing report.

On this Windows installation, the system/Tokio DNS probe returned
`unavailable` for the random `.localhost` subdomain. That is not treated as
proof that arbitrary system resolvers support the name. The WebView boundary
instead relies on [RFC 6761 section 6.3](https://www.rfc-editor.org/rfc/rfc6761.html#section-6.3),
which reserves every name under `.localhost` for loopback, and Chromium's
source-level rule to
[`Always treat .localhost as loopback`](https://chromium.googlesource.com/chromium/src/+/5d131a1fd9b808c5fd08c45f8299e669b13ec393%5E%21/).
[WebView2 uses the Microsoft Edge/Chromium runtime](https://learn.microsoft.com/en-us/microsoft-edge/webview2/).
The shell rejects any WebView2 environment override that can replace the
runtime or resolver arguments. A system probe that ever observes a
non-loopback answer stops before a WebView or `B` request is created.

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
- WebView2 Runtime

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

The harness exits nonzero when a required gate fails and writes only a
secret-free JSON report to a caller-selected temporary path. No report,
runtime profile, or build product belongs in Git.

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

## Status

This code is pre-release and `phase1_release_ready` remains false. Known
Phase 1 release gaps include:

- the complete matrix has not run against a reviewed fixed minimum WebView2
  runtime;
- forced-crash profile recreation has not proven that `P` is unrecoverable
  from disk after a native-process crash;
- configured navigation, popup, download, custom-scheme, devtools, extension,
  and remote-debugging controls have not all been exercised end to end;
- HTTP idle/body-rate and WebSocket byte-rate abuse gates, plus malformed and
  truncated streamed-upstream-body handling, are not finished; WebSocket
  activity-idle shutdown and strict malformed response-head rejection are
  already tested.

A development-runtime pass cannot substitute for the complete matrix.
Protocol-2 R
launcher ownership and Windows Job Objects belong to Phase 2; resource
generation and installers are later milestones. See
[ARCHITECTURE.md](ARCHITECTURE.md) for component boundaries and evidence
interpretation.
