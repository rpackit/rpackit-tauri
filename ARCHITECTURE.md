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
4. streams request bodies with backpressure through independent byte, idle,
   minimum-rate, total-time, and trailer gates.

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

## Malformed upstream response-head evidence

The upstream socket is wrapped by a response guard before it is passed to
Hyper. The guard buffers at most the configured response-header limit and
releases no bytes until one complete response head passes strict raw checks:

- every line uses CRLF and the response is HTTP/1.1 with an allowed final
  status;
- the configured header byte and field-count bounds hold;
- when present, `Content-Length` is unique and decimal and
  `Transfer-Encoding` is unique and exactly `chunked`; the two never coexist,
  while responses that require neither remain valid;
- ordinary HTTP forwarding rejects informational or switching responses,
  while the WebSocket path permits `101` only for its later exact handshake
  validation.

Any read error before validation clears the retained prefix and permanently
latches the guard closed; retrying the wrapper cannot resume or release those
bytes.

The existing structured normalization then rejects ambiguous `Connection` and
`Location`, protected connection nominations, unsafe cookies, protected
response fields, and any WebSocket response whose upgrade, accept,
subprotocol, or extension fields do not exactly match the downstream offer.
The testkit drives both layers through real loopback sockets and both
forwarding paths:

- a valid ordinary HTTP baseline and 16 HTTP negative heads;
- a valid `101` baseline that tunnels one raw WebSocket frame and 16
  WebSocket negative heads.

The WebSocket server independently verifies that the proxy sent the normalized
upgrade request and exactly one synthetic upstream credential. Parser-valid
unsafe heads contain an attacker canary; every WebSocket negative also carries
a valid attacker frame after its head. Passing requires every one of the 32
negatives to become the exact locally generated `502`, no WebSocket negative
to switch the downstream connection, all 34 upstream requests to have one
valid synthetic credential, all 17 WebSocket requests to have the exact
normalized upgrade shape, and zero canary/frame bytes downstream.

The downstream server disables Hyper's automatic `Date` field. The fixed
oracle therefore requires exactly `Cache-Control: no-store`,
`Connection: close`, `Content-Length: 17`, and
`Content-Type: text/plain; charset=utf-8`, followed by the exact
`Upstream rejected` body; any upstream-derived or other unexpected header
fails the gate. This evidence is part of `development_gates_passed` in the
real WebView2 report. The recorded WebView2 `150.0.4078.99` report contains
both passing baselines, 32/32 exact fixed `502` results, 34/34 valid synthetic
upstream credentials, 17/17 normalized WebSocket requests, no downstream
upgrade, and zero forwarded markers.

The body guard deliberately does not claim that errors discovered after a
response head has been released can be rewritten into a `502`. A declared
trailer or over-limit `Content-Length` is rejected before downstream head
release. After release, declared/configured byte limits, upstream parser/read
errors, and trailer frames fail with a fixed secret-free internal error. The
downstream response already carries `Connection: close`, so the corresponding
gate accepts either closure before downstream head serialization or
detectably incomplete framing, and requires bounded termination with no
trailer, attacker marker, second response, or reusable connection. The split
between those two safe outcomes is scheduling-dependent. The close-delimited
over-limit case is necessarily delimited by that close; its oracle therefore
requires an empty bounded response body and no marker. The configured byte
limit applies to the proxied, encoded HTTP body. Expansion after
`Content-Encoding` decompression is not bounded by this guard and remains part
of the open resource-abuse gate.

The forwarder records the request method before the upstream request is moved.
Its body policy treats `HEAD`, `204`, `205`, and `304` as body-forbidden.
`HEAD` and `304` may preserve a nonzero hypothetical `Content-Length` in the
downstream head without enforcing it as streamed bytes. `204` rejects either
`Content-Length` or `Transfer-Encoding` before releasing a downstream head.
`205` accepts no framing or `Content-Length: 0`, rejects a nonzero declared
length or any `Transfer-Encoding` before release, and drops any streamed
content. Rejecting even nominally empty chunked framing avoids stream/trailer
ambiguity on a status that must not carry content. The body-forbidden guard
has a zero-byte streaming allowance, so a data frame cannot leak when no-body
semantics are in effect.

The raw body matrix proves fragmented valid fixed-length, chunked, and
close-delimited baselines plus bodyless `HEAD` and `304` responses carrying
nonzero hypothetical lengths, a bodyless `204` without framing, and a bodyless
`205` with `Content-Length: 0`. Its 23 negatives require 6 exact pre-stream
`502` responses, 12 stream fail-closed terminations, 1 empty
close-delimited-limit cutoff, 2 bodyless malicious-status terminations, and 2
response-splitting attempts isolated to the first safe response. The split
between withheld-head and incomplete-framing outcomes among the 12 streaming
failures is scheduling-dependent. The trailer set includes malformed,
protected, oversized, and 97-field cases against the configured 96-field
maximum.

All 30 first upstream requests must carry exactly one synthetic upstream
credential. After each first response head or physical close, the raw client
attempts a second authenticated request on the same keep-alive downstream
socket. Passing requires 30/30 attempts, 30/30 physical closes before proxy
shutdown, zero second responses, zero reusable connections, bounded
termination, and zero forwarded attacker markers. The response-splitting and
no-body fixtures omit upstream `Connection: close` where applicable so the
observed downstream close is enforced by the proxy.

The authenticated request-upload guard starts its clocks only when the
upstream client begins polling the body. It caps streamed data at 64 MiB by
default, resets a 15-second idle deadline only after a non-empty data frame,
requires 1 KiB/s in each completed 5-second tumbling window, and enforces a
5-minute total duration. A body that ends within its current window passes
without a minimum-size rule. Any inner-body error or trailer frame is replaced
with a fixed secret-free error, and a frame that would cross the cap is never
forwarded. The loopback matrix proves one immediate valid body, one chunked
body cut off before crossing its byte cap, three otherwise-completing bodies
cut off independently by idle, rate, and total time, and one parsed chunked
trailer converted to a fixed `502`.
Configuration validation rejects a zero enabled rate window or a rate window
longer than the total body lifetime. The real harness serializes these results
as `request_body_limits`; the
`request_body_resource_limits_fail_closed` development gate requires the valid
baseline, all five bounded negatives, every parsed probe request to carry a
valid synthetic credential, and zero proxy-cookie or bootstrap-header leaks.
The byte-cap and trailer errors can be discovered before or after the upstream
request head is serialized, so between 4 and 6 parsed probe requests are
valid; the recorded run observed 5/5 correctly authenticated heads.

## Evidence and release boundary

The headless suite proves deterministic negative cases and transport
normalization. The real WebView2 harness separately proves browser cookie,
subresource, fetch, streaming, WebSocket, child-host, external-redirect,
cleanup, and secret-leakage behavior. Its JSON output contains only versions,
hostnames, booleans, counts, and route names.

A passing development report is not Phase 1 release readiness. The complete
matrix must still pass on a reviewed fixed minimum WebView2 runtime, and a
forced native-process crash must prove that the profile cannot recover `P`.
The remaining matrix includes actual browser escape-path attempts,
response-body idle/rate and decompression-expansion abuse, WebSocket byte-rate
abuse, crash profile persistence, and the fixed-minimum runtime.
Authenticated request-upload byte/idle/rate/total/trailer limits,
exact-address takeover, IPv4/IPv6 wildcard overlap, strict malformed upstream
response-head rejection, streamed response-body/trailer fail-closed behavior,
and WebSocket activity-idle shutdown are tested on the development
environment. Protocol-2 R launcher ownership and Windows Job Objects are
Phase 2 work.

## Maintainer rules

- Change the authoritative roadmap contract before changing a security
  invariant here.
- Increment the transport contract for an incompatible boundary change.
- Keep all failure responses and empirical reports secret-free.
- Never replace a failed gate with a warning, stable-host fallback, domain
  cookie, URL credential, JavaScript handoff, or unauthenticated bootstrap.
