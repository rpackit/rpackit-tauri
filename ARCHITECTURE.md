# Architecture

## Scope and authority

This repository implements the Windows Phase 1 spike for rpackit's
authenticated native loopback transport. The authoritative security contract
is
[`TAURI_SECURE_TRANSPORT.md`](https://github.com/rpackit/roadmap/blob/main/TAURI_SECURE_TRANSPORT.md).
This document describes the implementation of transport contract version 2;
it does not expand or weaken that contract.

The spike is an acceptance harness. It is not yet an application generator,
supported installer, or implementation of protocol-2 R process ownership.

## Components

| Component | Responsibility | Must not own |
| --- | --- | --- |
| `crates/transport` | Secrets, strict HTTP admission, bootstrap, authenticated reverse proxy, response normalization, WebSocket validation and tunnelling | WebView UI, application-selected upstreams, persistent credentials |
| `crates/transport-testkit` | Loopback-only mock upstream and collectors, deterministic browser assets, listener-overlap probes, secret-free counters and reports | External network, real credentials, release claims |
| `apps/windows-spike` | Hidden hardened Tauri/WebView2 shell, one native bootstrap navigation, cookie readback, browser exercise, cleanup and acceptance report | JavaScript bridge for credentials, general request injection, R launcher lifecycle |
| `tests/run-webview2.ps1` | Starts the real WebView2 harness and rejects a failed development gate | Fixed-runtime certification or installer validation |

## Secret and origin model

Each launch generates independent 256-bit values:

- `S` authenticates the native proxy to one fixed Shiny upstream.
- `P` authenticates browser traffic to the proxy.
- `B` authorizes exactly one cookie-bootstrap request.

An independent random nonce forms
`rpackit-<nonce>.localhost:<proxy-port>`. The nonce isolates the browser origin
between launches but is not a credential. Cookies are not port-scoped, so a
fresh hostname is required even when every proxy uses an ephemeral port.

The proxy owns compatible IPv4 and IPv6 loopback listeners and rejects a
non-loopback peer, an incorrect `Host`, an absolute or authority-form target,
ambiguous framing, protected `Connection` tokens, unsupported upgrades, and
other malformed admission before application forwarding. Windows listeners
request `SO_EXCLUSIVEADDRUSE` before bind.

## Bootstrap sequence

```text
hidden WebView2
    |
    | exact native GET + one-time B header
    v
/__rpackit_bootstrap on loopback proxy
    |
    | authenticate and consume B; no upstream dial
    | fixed HTML + host-only HttpOnly Strict Set-Cookie(P)
    v
WebView2 cookie store
    |
    | native readback, then navigate to /
    v
authenticated proxy request with P
    |
    | strip P and B; inject exactly one S
    v
fixed 127.0.0.1 Shiny upstream
```

The shell constructs only that first request with WebView2
[`CreateWebResourceRequest`](https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/win32/icorewebview2environment2)
and
[`NavigateWithWebResourceRequest`](https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/win32/icorewebview2_2).
No general WebView request interceptor and no credential-bearing JavaScript
bridge is installed.

The proxy accepts only the exact bootstrap path and an exact single `B`.
Authentication uses a constant-time comparison and atomic one-time
consumption. Missing, wrong, duplicated, malformed, or replayed `B` returns a
fixed secret-free failure, creates no `P`, and does not dial the upstream.

The successful response contains a fixed non-navigating document and:

```text
Set-Cookie: rpackit_proxy_v1=<P>; Path=/; HttpOnly; SameSite=Strict
```

There is deliberately no `Domain`, `Expires`, or `Max-Age`. Processing the
response at the random proxy host creates a true host-only session cookie.

## Why HTTP creates the host-only cookie

The spike first attempted Tauri's high-level native cookie setter. On WebView2
`150.0.4078.83`, the setter did not produce a host-only cookie on readback.
WebView2 documents that
[`AddOrUpdateCookie`](https://learn.microsoft.com/en-us/dotnet/api/microsoft.web.webview2.core.corewebview2cookiemanager.addorupdatecookie)
fails when a cookie's domain is unspecified. Giving the native cookie object a
domain would change the required host-only semantics.

The HTTP bootstrap response is therefore the cookie-creation boundary. `B`
authenticates access to that response, and the narrow native WebView2 request
API transports `B` only on the initial navigation. This is both narrower than
general interception and compatible with ordinary browser host-only cookie
semantics.

## Authenticated application traffic

Every non-bootstrap HTTP request and WebSocket upgrade authenticates one
unambiguous `P` before opening an upstream connection. Unsafe HTTP methods and
WebSocket upgrades also require the exact proxy `Origin`.

Before forwarding, the proxy:

1. removes the reserved proxy cookie, the bootstrap field, any inbound
   protected secret, forwarding/spoofing fields, and validated hop-by-hop
   fields;
2. fixes the upstream authority and, when present, rewrites `Origin` to that
   fixed upstream;
3. injects exactly one `Shiny-Shared-Secret: S` as the last protected mutation;
4. streams bounded bodies with backpressure.

The response path rejects attempts to set the reserved proxy cookie, rewrites
only redirects that exactly target the fixed upstream, preserves external
redirects without following them, and normalizes acceptable application
cookies for the proxy origin.

WebSocket handshakes receive the same authentication and admission controls.
The proxy validates the client request and upstream `101`, strips extension
offers, verifies the accept value and selected subprotocol, then tunnels bytes
bidirectionally with an activity-based idle watchdog. Successful reads and
writes reset the watchdog; shutdown drains or aborts every tracked connection,
upstream protocol driver, and upgrade tunnel before returning.

## WebView boundary

The test shell uses a unique data directory and incognito mode, starts hidden,
and denies non-proxy top-level navigation, new windows, downloads, devtools,
browser extensions, autofill, drag-and-drop, and zoom shortcuts. It reads the
cookie only to verify flags and value equality in native code; the value is
never put in the report.

Normal cleanup deletes `P`, clears browsing data, destroys the WebView, and
recreates the same profile to test that no cookie is reusable. Forced-crash
profile recreation is a separate hard gate. The clean same-data-directory
recreation gate passed on the recorded development runtime; the forced-crash
gate remains unproven.

## Resolver evidence

Two observations are intentionally recorded separately:

1. the system/Tokio lookup classifies all returned addresses and fails if any
   address is non-loopback;
2. the actual WebView must finish the authenticated bootstrap and application
   navigation through the running proxy.

On the recorded Windows development run, the first observation was
`unavailable` for the random `.localhost` subdomain. The second succeeded.
The WebView-specific invariant comes from
[RFC 6761 section 6.3](https://www.rfc-editor.org/rfc/rfc6761.html#section-6.3)
and Chromium's source-level rule to
[`Always treat .localhost as loopback`](https://chromium.googlesource.com/chromium/src/+/5d131a1fd9b808c5fd08c45f8299e669b13ec393%5E%21/);
[WebView2 uses Microsoft Edge with Chromium bits](https://learn.microsoft.com/en-us/microsoft-edge/webview2/).
The shell rejects environment overrides for the runtime and browser arguments,
and a system probe that actually observes a non-loopback result aborts before
creating a WebView or sending `B`.

Because the proxy listens only on loopback, rejects non-loopback peers, and
requires the exact random `Host`, successful authenticated loading is
additional runtime evidence that WebView2 reached the loopback endpoint. It is
not a claim that all Windows resolver APIs support arbitrary `.localhost`
subdomains. The architecture provides no stable-host fallback.

## Listener ownership evidence

Windows exact-address exclusivity and wildcard overlap are separate
observations. After the proxy binds exact IPv4 and IPv6 loopback addresses, the
testkit creates three same-port `SO_REUSEADDR` contenders: IPv4 wildcard, IPv6
v6-only wildcard, and IPv6 dual-stack wildcard. Windows may reject a wildcard
bind or permit it while still excluding the exact interface, as described in
Microsoft's
[`SO_REUSEADDR` and `SO_EXCLUSIVEADDRUSE` binding matrix](https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse).
Wildcard bind success alone is therefore not a failed gate.

The IPv4 wildcard is tested against exact IPv4, and the IPv6 v6-only wildcard
against exact IPv6. The same dual-stack contender remains alive while the
probe tests exact IPv4 and then exact IPv6. Each of those four traffic paths
receives eight real, credential-free requests with the proxy's exact `Host`.
The request omits `P`, so only the proxy can return the expected fixed `401`;
the mock upstream must remain untouched. A variant passes only when every raw
per-target counter is 8/8 and its wildcard listener accepts zero connections.
The acceptance report records every bind outcome and raw counter without
recording any credential.

On the recorded development run all three wildcard binds succeeded. Exact
IPv4 under the IPv4 contender, exact IPv6 under the v6-only contender, and both
exact targets under the single dual-stack contender each returned 8/8 proxy
`401` responses. All three wildcard accept counts remained zero, for 32 total
exact-loopback requests.

`windows_listener_overlap_all_variants_pass` requires all three contenders and
all four traffic paths to pass from their raw counters. The report removes
`listener_overlap_matrix` from `unproven_release_gates` only for that measured
result. Unexpected bind errors fail the harness; only Windows `AddrInUse` or
`PermissionDenied` is recorded as an ordinary rejected contender. This
resolves that development-runtime gate; it does not imply Phase 1 readiness or
certify the remaining fixed-runtime and browser matrices.

## Evidence and release boundary

The headless suite proves deterministic negative cases and transport
normalization. The real WebView2 harness separately proves browser cookie,
subresource, fetch, streaming, WebSocket, child-host, external-redirect,
cleanup, and secret-leakage behavior. Its JSON output contains only versions,
hostnames, booleans, counts, and route names.

A passing development report is not Phase 1 release readiness. The complete
matrix must still pass on a reviewed fixed minimum WebView2 runtime, and a
forced native-process crash must prove that the profile cannot recover `P`.
The remaining matrix also includes actual browser escape-path attempts, HTTP
idle/body-rate and WebSocket byte-rate abuse, malformed upstream framing, and
the fixed-minimum runtime. Exact-address takeover, IPv4/IPv6 wildcard overlap,
and WebSocket activity-idle shutdown are already tested on the development
environment. Protocol-2 R launcher ownership and Windows Job Objects are Phase
2 work.

## Maintainer rules

- Change the authoritative roadmap contract before changing a security
  invariant here.
- Increment the transport contract for an incompatible boundary change.
- Keep all failure responses and empirical reports secret-free.
- Never replace a failed gate with a warning, stable-host fallback, domain
  cookie, URL credential, JavaScript handoff, or unauthenticated bootstrap.
